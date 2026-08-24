from __future__ import annotations

import frappe
from frappe import _
from frappe.model.document import Document


class CredentialAccessLog(Document):
    """Append-only. Four independent layers hold that property, so that no single mistake
    reopens it:

    1. DocPerms (credential_access_log.json): no role has write, create or delete —
       System Manager and Vault Admin included. `in_create: 1` also removes the New button.
       Creation happens only through `vault.audit.write_access_log`.
    2. This controller: `validate` blocks every edit, `on_trash` blocks every delete
       without a console-only override.
    3. Not submittable, so no amend path exists. `allow_rename: 0`. `track_changes: 0` —
       a Version row of a log row is itself a mutation vector and adds nothing.
    4. Convention, enforced by review: no code in this app may call `frappe.db.delete` or
       `frappe.db.sql` against this table. The framework cannot guard that.
    """

    def validate(self) -> None:
        if not self.is_new():
            # Append-only means append-only. Even a System Manager edit is blocked here:
            # there is no legitimate reason to rewrite audit history, and an editable log
            # is not evidence of anything.
            frappe.throw(_("Access log rows cannot be modified."), frappe.PermissionError)

    def on_trash(self) -> None:
        # The System Manager override is deliberate and console-only:
        #
        #     bench --site <site> console
        #     >>> frappe.flags.vault_audit_delete_override = True
        #     >>> frappe.delete_doc("Credential Access Log", name)
        #
        # The flag cannot be set over HTTP — no whitelisted method in this app sets it —
        # so the override requires shell access to the VM, which is the correct bar for
        # destroying audit evidence. Bulk delete from the list view routes through
        # on_trash per row and so hits the same block.
        if not (
            "System Manager" in frappe.get_roles(frappe.session.user)
            and frappe.flags.get("vault_audit_delete_override")
        ):
            frappe.throw(_("Access log rows cannot be deleted."), frappe.PermissionError)

        frappe.logger("sssihms_password_vault").warning(
            f"AUDIT OVERRIDE: {frappe.session.user} deleted access log row {self.name}"
        )
