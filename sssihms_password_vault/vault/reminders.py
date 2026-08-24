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

from sssihms_password_vault.vault.audit import write_access_log
from sssihms_password_vault.vault.permissions import is_vault_auditor_only


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
       only, auditors excluded), falling back to all Vault Admin role holders if a space
       has no enabled manager.
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

    # Two conditions, not one: Frappe's query layer wraps date comparisons in
    # ifnull(), so a bare `<=` filter also matches rows where rotation_due is NULL —
    # every credential with no rotation policy would be "overdue" forever. Found live
    # on the evaluation bench, not in code review.
    due = frappe.get_all(
        "Vault Credential",
        filters=[
            ["rotation_due", "is", "set"],
            ["rotation_due", "<=", as_of],
        ],
        fields=["name", "title", "vault_space", "rotation_due", "last_reminded_on"],
    )

    by_space: dict[str, list] = {}
    for cred in due:
        if not cred.rotation_due:
            continue  # belt-and-braces for the ifnull hazard above
        if cred.vault_space in disabled_spaces:
            continue
        if cred.last_reminded_on and (as_of - getdate(cred.last_reminded_on)).days < repeat_days:
            continue
        by_space.setdefault(cred.vault_space, []).append(cred)

    notified = 0
    spaces_notified = 0
    logger = frappe.logger("sssihms_password_vault")

    for space, credentials in by_space.items():
        recipients = _space_manager_recipients(space)
        fallback_used = False
        if not recipients:
            recipients = _vault_admin_recipients()
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
                    # A User *name*, which is what this field links to. The email address
                    # is a separate column and only coincides with the name on sites where
                    # usernames are email addresses (audit finding L17).
                    "for_user": recipient["name"],
                    "type": "Alert",
                    "subject": subject,
                    "email_content": message,
                }
            ).insert(ignore_permissions=True)

        # A digest carries credential titles and due dates out of the space, so who
        # received one is an access event. Titles never go into the log row itself —
        # counts and recipients only.
        write_access_log(
            None,
            action="reminder",
            vault_space=space,
            detail=(
                f"rotation digest: {len(credentials)} credential(s) to "
                f"{len(recipients)} recipient(s)"
                + (" via Vault Admin fallback" if fallback_used else "")
            ),
        )

        try:
            frappe.sendmail(
                recipients=[r["email"] for r in recipients if r.get("email")],
                subject=subject,
                message=message,
            )
        except Exception:
            # No outgoing email account (or SMTP down) must not kill the scheduled job:
            # the in-app Notification Log rows above are already written, which is the
            # guaranteed channel. Email is best-effort on top. Found live on the
            # evaluation bench (OutgoingEmailError with no SMTP configured).
            frappe.log_error(
                title="Password Vault rotation digest email failed",
                message=f"space={space} recipients={len(recipients)}",
            )

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


def _space_manager_recipients(space: str) -> list[dict]:
    """Enabled, non-auditor Manager-level members of ``space``."""
    managers = frappe.get_all(
        "Vault Space Member",
        filters={"parenttype": "Vault Space", "parent": space, "access_level": "Manager"},
        fields=["user"],
    )
    users = {row.user for row in managers}
    return _enabled(users)


def _vault_admin_recipients() -> list[dict]:
    """Enabled Vault Admin role holders — the fallback when a space has due credentials but
    no enabled Manager-level member."""
    admins = frappe.get_all(
        "Has Role", filters={"role": "Vault Admin", "parenttype": "User"}, fields=["parent"]
    )
    users = {row.parent for row in admins}
    return _enabled(users)


def _enabled(users: set[str]) -> list[dict]:
    """Enabled Users from ``users``, as ``{"name", "email"}``, with auditors dropped.

    The sweep runs as Administrator and therefore never consults the permission hooks —
    which made it the fourth auditor path the three mirrored guards do not cover (audit
    finding M2). A digest lists exactly what an auditor must not see: the titles of the
    credentials in a space. An auditor who is also a space Manager was receiving them, in a
    Notification Log row inserted with ignore_permissions and in an email body that then
    sits in tabEmail Queue.

    ``is_vault_auditor_only`` returns False for a Vault Admin, so an admin who also audits
    keeps receiving digests — the same precedence the rest of the app uses.
    """
    if not users:
        return []
    rows = frappe.get_all(
        "User",
        filters={"name": ["in", list(users)], "enabled": 1},
        fields=["name", "email"],
    )
    return [
        {"name": row.name, "email": row.email or row.name}
        for row in rows
        if not is_vault_auditor_only(row.name)
    ]


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
