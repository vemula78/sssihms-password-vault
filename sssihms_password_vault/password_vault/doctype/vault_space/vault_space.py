from __future__ import annotations

import frappe
from frappe import _
from frappe.model.document import Document
from frappe.utils import cint, now

from sssihms_password_vault.vault.audit import write_access_log
from sssihms_password_vault.vault.permissions import LEVEL_RANK, is_vault_admin

VAULT_USER_ROLE = "Vault User"


class VaultSpace(Document):
    """A department-scoped container. Membership in its `members` table, not a global
    role, is what decides who can read, edit or delete the credentials inside it —
    see vault/permissions.py.
    """

    def validate(self) -> None:
        self._guard_disabled_flag()
        self._reject_duplicate_members()
        self._require_a_manager()
        self._stamp_new_members()

    def _guard_disabled_flag(self) -> None:
        """Only a Vault Admin may change the `disabled` archival lock.

        A space Manager holds `write` on their own space so they can maintain its member
        table — and nothing previously scoped *which* fields that write covered, so a
        Manager could clear `disabled`, do the reveals and edits the flag exists to
        prevent, and set it back (audit finding M7). The flag is enforced against exactly
        the people who could turn it off, which made it advisory rather than a lock.

        The change is logged either way: an archival state change is a security event, and
        the denial is the more interesting of the two rows.
        """
        before = self.get_doc_before_save()
        if before is None:
            return
        if cint(before.disabled) == cint(self.disabled):
            return

        new_state = "disabled" if cint(self.disabled) else "enabled"
        if not is_vault_admin(frappe.session.user):
            write_access_log(
                None,
                action="space",
                outcome="denied",
                vault_space=self.name,
                detail=f"attempt to set space {new_state} (Vault Admin only)",
            )
            frappe.db.commit()
            frappe.throw(
                _("Only a Vault Admin can enable or disable a Vault Space."),
                frappe.PermissionError,
            )

        write_access_log(
            None,
            action="space",
            vault_space=self.name,
            detail=f"space {new_state}",
        )

    def _reject_duplicate_members(self) -> None:
        """Two rows for one user would make `get_membership_level` a max() over
        contradictory levels — legal, but it means the form shows "Reader" while the
        effective level is Manager. Reject it instead of silently resolving it."""
        seen: set[str] = set()
        for row in self.members:
            if row.user in seen:
                frappe.throw(
                    _("{0} appears more than once in the member list.").format(row.user),
                    title=_("Duplicate Member"),
                )
            seen.add(row.user)

    def _require_a_manager(self) -> None:
        """A space with members but no Manager is a configuration error, not a fallback.

        Vault Admin can always administer any space, so nothing is *unreachable* — but a
        space whose members cannot maintain their own membership or delete a stale
        credential will quietly accumulate both, and the person who set it up will not
        find out until they need one of those things. An empty member list is fine: that
        is a space that has not been handed over yet.
        """
        if not self.members:
            return
        if not any(row.access_level == "Manager" for row in self.members):
            frappe.throw(
                _("A space with members needs at least one Manager."),
                title=_("Vault Space"),
            )

    def _stamp_new_members(self) -> None:
        before = self.get_doc_before_save()
        existing = {row.name for row in (before.members if before else [])}
        for row in self.members:
            if row.name in existing:
                continue
            row.added_by = frappe.session.user
            row.added_on = now()

    def after_insert(self) -> None:
        """Space creation is a security event: it is the unit of access scoping, and
        nothing else in the log would otherwise record that it came into existence or who
        made it (audit finding L11)."""
        write_access_log(
            None,
            action="space",
            vault_space=self.name,
            detail=f"space created with {len(self.members)} member row(s)",
        )

    def on_update(self) -> None:
        self._grant_vault_user_role()
        self._log_membership_changes()

    def _grant_vault_user_role(self) -> None:
        """Every member needs the `Vault User` role, which is the doctype-level grant that
        membership then narrows (DESIGN.md deviation 1). Without it a member has no ORM
        access at all and the permission query conditions have nothing to narrow.

        `ignore_permissions` is deliberate and is the narrow kind: membership is granted by
        a space Manager who is very unlikely to hold write access on the User doctype, and
        the role confers nothing on any row the holder is not a member of — so this grants
        no access that the member row itself did not already grant.
        """
        if not frappe.db.exists("Role", VAULT_USER_ROLE):
            # Only possible on a site where after_install did not complete. Say so rather
            # than failing every space save.
            frappe.log_error(
                title="sssihms_password_vault",
                message=(
                    f"Role '{VAULT_USER_ROLE}' is missing; space members will have no ORM "
                    "access until it exists. Re-run install/after_install."
                ),
            )
            return

        for row in self.members:
            if not row.user or not frappe.db.exists("User", row.user):
                continue
            if VAULT_USER_ROLE in frappe.get_roles(row.user):
                continue
            user_doc = frappe.get_doc("User", row.user)
            user_doc.flags.ignore_permissions = True
            user_doc.add_roles(VAULT_USER_ROLE)

    def _log_membership_changes(self) -> None:
        """Membership changes are security events: they are what grants and revokes access
        to every secret in the space, so each one gets its own access-log row."""
        before = self.get_doc_before_save()
        old = {
            row.user: row.access_level
            for row in (before.members if before else [])
            if row.user
        }
        new = {row.user: row.access_level for row in self.members if row.user}

        for user, level in new.items():
            if user not in old:
                self._log_membership(f"added {user} as {level}")
            elif old[user] != level:
                self._log_membership(f"changed {user} from {old[user]} to {level}")
        for user in old:
            if user not in new:
                self._log_membership(f"removed {user} (was {old[user]})")

    def _log_membership(self, detail: str) -> None:
        write_access_log(
            None,
            action="membership",
            vault_space=self.name,
            detail=detail,
        )

    def on_trash(self) -> None:
        """No cascade. Deleting a space that still holds credentials would either orphan
        them (unreachable, undeletable) or destroy them wholesale — neither is something a
        single click should be able to do to a department's credential store."""
        if frappe.db.exists("Vault Credential", {"vault_space": self.name}):
            count = frappe.db.count("Vault Credential", {"vault_space": self.name})
            frappe.throw(
                _("This space still holds {0} credential(s). Delete or move them first.").format(
                    count
                ),
                title=_("Vault Space"),
            )

        # Deleting a space destroys its whole member table — every grant and revocation
        # this log recorded — so the deletion itself has to be on record (audit finding
        # L11). The row's `vault_space` Link dangles afterwards, which is the same
        # deliberate arrangement `ignore_links_on_delete` makes for credentials: the log
        # outlives what it logs.
        write_access_log(
            None,
            action="space",
            vault_space=self.name,
            detail=f"space deleted ({len(self.members)} member row(s))",
        )


def member_levels(space: str) -> dict[str, str]:
    """Every member of `space` mapped to their highest access level.

    A convenience over the member table for callers that need the whole space at once (the
    reminder sweep needs its Managers). Single-membership lookups go through
    `vault.permissions.get_membership_level`, which is the cached, authoritative path.

    Queried through `frappe.qb` for the same reason as `get_membership_level`: reading a
    child doctype through `get_all` needs a `parent` argument and pulls the permission
    machinery in, and the query builder parameterises its literals.
    """
    member = frappe.qb.DocType("Vault Space Member")
    rows = (
        frappe.qb.from_(member)
        .select(member.user, member.access_level)
        .where((member.parenttype == "Vault Space") & (member.parent == space))
    ).run(as_dict=True)

    levels: dict[str, str] = {}
    for row in rows:
        user, level = row.get("user"), row.get("access_level")
        if not user or level not in LEVEL_RANK:
            continue
        current = levels.get(user)
        if current is None or LEVEL_RANK[level] > LEVEL_RANK[current]:
            levels[user] = level
    return levels
