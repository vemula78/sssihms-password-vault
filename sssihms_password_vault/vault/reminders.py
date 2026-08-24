"""Daily rotation-reminder sweep — DESIGN.md §8.

Registered as the scheduler entrypoint in ``hooks.py`` (Package A's file; this module only
provides the function it points at — ``sssihms_password_vault.vault.reminders.
daily_rotation_sweep``, no args, the pinned signature in DESIGN.md §10).

Not required to be importable without Frappe (only generator/health/csv-parsing are, per
DESIGN.md §9) — this module is Frappe-dependent throughout and is exercised via
``bench --site <site> execute ...`` or the scheduler itself, never plain pytest.
"""

from __future__ import annotations

import frappe
from frappe.utils import cint, getdate
from frappe.utils import today as frappe_today


def daily_rotation_sweep() -> dict:
    """Scheduled entrypoint. Runs as Administrator under the scheduler, so
    ``frappe.get_all`` (which does not apply permissions) is the right call here and needs
    no ``ignore_permissions`` flag.

    Steps (DESIGN.md §8):

    1. Exit if the master switch is off.
    2. Find credentials past their ``rotation_due`` date, excluding disabled spaces.
    3. Skip a credential last reminded within ``reminder_repeat_days`` — the re-remind
       cadence, so an overdue item nags on a schedule, not daily.
    4. Group by space; recipients are that space's Manager-level members (enabled Users
       only), falling back to all Vault Admin role holders if a space has no enabled
       manager.
    5. One digest per space: a Notification Log entry per recipient, plus one email to all
       of them. Titles and due dates only — never usernames, URLs, or any secret.
    6. Stamp ``last_reminded_on`` on every notified credential with a direct
       ``frappe.db.set_value`` (bookkeeping, not an edit: must not touch ``modified``,
       fire ``validate()``, or clear anything else on the document).
    """
    settings = frappe.get_single("Vault Settings")
    if not cint(settings.rotation_reminders_enabled):
        return {"skipped": "reminders_disabled"}

    as_of = getdate(frappe_today())
    repeat_days = cint(settings.reminder_repeat_days) or 7

    disabled_spaces = {
        row.name for row in frappe.get_all("Vault Space", filters={"disabled": 1}, fields=["name"])
    }

    due = frappe.get_all(
        "Vault Credential",
        filters={"rotation_due": ["<=", as_of]},
        fields=["name", "title", "vault_space", "rotation_due", "last_reminded_on"],
    )

    by_space: dict[str, list] = {}
    for cred in due:
        if cred.vault_space in disabled_spaces:
            continue
        if cred.last_reminded_on and (as_of - getdate(cred.last_reminded_on)).days < repeat_days:
            continue
        by_space.setdefault(cred.vault_space, []).append(cred)

    notified = 0
    spaces_notified = 0
    logger = frappe.logger("sssihms_password_vault")

    for space, credentials in by_space.items():
        recipients = _space_manager_emails(space)
        fallback_used = False
        if not recipients:
            recipients = _vault_admin_emails()
            fallback_used = True
        if not recipients:
            logger.warning(
                f"Rotation reminder: no recipient for space {space} "
                f"({len(credentials)} credential(s) overdue) — no enabled Manager-level "
                "member and no enabled Vault Admin."
            )
            continue

        subject = (
            f"[Password Vault] {len(credentials)} credential(s) overdue for rotation in {space}"
        )
        message = _digest_message(space, credentials, fallback_used)

        for recipient in recipients:
            frappe.get_doc(
                {
                    "doctype": "Notification Log",
                    "for_user": recipient,
                    "type": "Alert",
                    "subject": subject,
                    "email_content": message,
                }
            ).insert(ignore_permissions=True)
        frappe.sendmail(recipients=recipients, subject=subject, message=message)

        for cred in credentials:
            # Direct write, not doc.save(): this is scheduler bookkeeping, not an edit — it
            # must not touch `modified`, run validate(), or otherwise look like a user
            # changed the credential. Same pattern sssihms_hr uses for its own reminder
            # ledger writes.
            frappe.db.set_value(
                "Vault Credential", cred.name, "last_reminded_on", as_of, update_modified=False
            )
        notified += len(credentials)
        spaces_notified += 1

    frappe.db.commit()
    return {"spaces_notified": spaces_notified, "credentials_notified": notified}


def _space_manager_emails(space: str) -> list[str]:
    """Enabled-User names of ``space``'s Manager-level members."""
    managers = frappe.get_all(
        "Vault Space Member",
        filters={"parenttype": "Vault Space", "parent": space, "access_level": "Manager"},
        fields=["user"],
    )
    users = {row.user for row in managers}
    return _enabled(users)


def _vault_admin_emails() -> list[str]:
    """Enabled-User names of every Vault Admin role holder — the fallback when a space has
    due credentials but no enabled Manager-level member."""
    admins = frappe.get_all(
        "Has Role", filters={"role": "Vault Admin", "parenttype": "User"}, fields=["parent"]
    )
    users = {row.parent for row in admins}
    return _enabled(users)


def _enabled(users: set[str]) -> list[str]:
    if not users:
        return []
    rows = frappe.get_all("User", filters={"name": ["in", list(users)], "enabled": 1}, fields=["name"])
    return [row.name for row in rows]


def _digest_message(space: str, credentials: list, fallback_used: bool) -> str:
    lines = [f"{len(credentials)} credential(s) in Vault Space '{space}' are overdue for rotation:", ""]
    for cred in sorted(credentials, key=lambda c: c.rotation_due):
        lines.append(f"- {cred.title} (due {getdate(cred.rotation_due).isoformat()})")
    if fallback_used:
        lines.append("")
        lines.append(
            "No enabled space Manager was found for this space — this notice went to "
            "Vault Admin instead."
        )
    return "\n".join(lines)
