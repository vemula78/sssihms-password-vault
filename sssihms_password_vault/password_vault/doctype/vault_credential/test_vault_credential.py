"""Permission, reveal and audit-trail proofs for Vault Credential (DESIGN.md §1.4, §2, §3).

Run with a site: ``bench --site <site> run-tests --app sssihms_password_vault \\
    --module sssihms_password_vault.password_vault.doctype.vault_credential.test_vault_credential``

Exercises the parts of PACKAGE A that PACKAGE B's pinned interfaces (get_membership_level,
write_access_log, reveal_secret) depend on end to end. Not runnable without a bench/site —
see vault/tests/ for the pure-logic suites (generator, health scoring, CSV parsing).
"""

from __future__ import annotations

import frappe
from frappe.tests.utils import FrappeTestCase

from sssihms_password_vault.vault.api import reveal_secret
from sssihms_password_vault.vault.permissions import get_membership_level

SPACE = "Test Space — Vault Credential"
DISABLED_SPACE = "Test Space — Disabled"

READER = "vault-reader@example.test"
EDITOR = "vault-editor@example.test"
MANAGER = "vault-manager@example.test"
OUTSIDER = "vault-outsider@example.test"
AUDITOR = "vault-auditor@example.test"


def _ensure_user(email: str, roles: tuple[str, ...] = ()) -> None:
    if not frappe.db.exists("User", email):
        user = frappe.get_doc(
            {
                "doctype": "User",
                "email": email,
                "first_name": email.split("@")[0],
                "send_welcome_email": 0,
            }
        )
        user.insert(ignore_permissions=True)
    if roles:
        frappe.get_doc("User", email).add_roles(*roles)


class TestVaultCredential(FrappeTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        frappe.set_user("Administrator")

        for role in ("Vault Admin", "Vault Auditor", "Vault User"):
            if not frappe.db.exists("Role", role):
                frappe.get_doc({"doctype": "Role", "role_name": role, "desk_access": 1}).insert(
                    ignore_permissions=True
                )

        _ensure_user(READER)
        _ensure_user(EDITOR)
        _ensure_user(MANAGER)
        # The outsider carries Vault User deliberately: an account with no vault role is
        # already stopped by the DocPerm ceiling, which proves nothing about the membership
        # hooks. The case that matters is a user the role system WOULD admit, narrowed to
        # nothing by has_permission + query conditions because no membership row exists.
        _ensure_user(OUTSIDER, roles=("Vault User",))
        _ensure_user(AUDITOR, roles=("Vault Auditor",))

        if not frappe.db.exists("Vault Space", SPACE):
            frappe.get_doc(
                {
                    "doctype": "Vault Space",
                    "space_name": SPACE,
                    "members": [
                        {"user": READER, "access_level": "Reader"},
                        {"user": EDITOR, "access_level": "Editor"},
                        {"user": MANAGER, "access_level": "Manager"},
                        {"user": AUDITOR, "access_level": "Reader"},
                    ],
                }
            ).insert(ignore_permissions=True)

        if not frappe.db.exists("Vault Space", DISABLED_SPACE):
            frappe.get_doc(
                {
                    "doctype": "Vault Space",
                    "space_name": DISABLED_SPACE,
                    "disabled": 1,
                    "members": [{"user": MANAGER, "access_level": "Manager"}],
                }
            ).insert(ignore_permissions=True)

    def setUp(self):
        frappe.set_user("Administrator")

    def tearDown(self):
        frappe.set_user("Administrator")

    def _make_credential(self, **overrides) -> "frappe.model.document.Document":
        payload = {
            "doctype": "Vault Credential",
            "vault_space": SPACE,
            "credential_type": "login",
            "title": "Test Login",
            "username": "svc-account",
            "password": "Tr0ub4dor&3xtra!Long",
        }
        payload.update(overrides)
        frappe.set_user("Administrator")
        doc = frappe.get_doc(payload)
        doc.insert(ignore_permissions=True)
        return doc

    # ------------------------------------------------------------------ membership

    def test_get_membership_level_reflects_the_member_table(self):
        self.assertEqual(get_membership_level(READER, SPACE), "Reader")
        self.assertEqual(get_membership_level(EDITOR, SPACE), "Editor")
        self.assertEqual(get_membership_level(MANAGER, SPACE), "Manager")
        self.assertIsNone(get_membership_level(OUTSIDER, SPACE))

    def test_outsider_cannot_read_the_credential(self):
        cred = self._make_credential(title="Outsider Read Test")
        frappe.set_user(OUTSIDER)
        # frappe.get_doc is permission-free ORM access by design; enforcement happens in
        # check_permission, which is what every real entry point (frappe.client.get, the
        # form view, our own API module) routes through. Assert on that layer.
        doc = frappe.get_doc("Vault Credential", cred.name)
        with self.assertRaises(frappe.PermissionError):
            doc.check_permission("read")
        self.assertFalse(
            frappe.has_permission("Vault Credential", ptype="read", doc=cred.name, user=OUTSIDER)
        )

    def test_outsider_list_view_sees_nothing(self):
        self._make_credential(title="Outsider List Test")
        frappe.set_user(OUTSIDER)
        names = frappe.get_list("Vault Credential", filters={"vault_space": SPACE}, pluck="name")
        self.assertEqual(names, [])

    def test_reader_can_read_but_not_write(self):
        cred = self._make_credential(title="Reader Perm Test")
        frappe.set_user(READER)
        doc = frappe.get_doc("Vault Credential", cred.name)
        doc.notes = "reader tried to edit"
        with self.assertRaises(frappe.PermissionError):
            doc.save()

    def test_editor_can_edit_but_not_delete(self):
        cred = self._make_credential(title="Editor Perm Test")
        frappe.set_user(EDITOR)
        doc = frappe.get_doc("Vault Credential", cred.name)
        doc.notes = "editor edit"
        doc.save()
        with self.assertRaises(frappe.PermissionError):
            frappe.delete_doc("Vault Credential", cred.name)

    def test_manager_can_delete(self):
        cred = self._make_credential(title="Manager Delete Test")
        frappe.set_user(MANAGER)
        frappe.delete_doc("Vault Credential", cred.name)
        self.assertFalse(frappe.db.exists("Vault Credential", cred.name))

    def test_disabled_space_blocks_write_even_for_manager(self):
        cred = self._make_credential(title="Disabled Space Test", vault_space=DISABLED_SPACE)
        frappe.set_user(MANAGER)
        doc = frappe.get_doc("Vault Credential", cred.name)
        doc.notes = "should not save"
        with self.assertRaises(frappe.PermissionError):
            doc.save()

    # ------------------------------------------------------------------- immutability

    def test_vault_space_cannot_change_after_insert(self):
        other_space = SPACE
        cred = self._make_credential(title="Immutable Space Test")
        frappe.set_user("Administrator")
        doc = frappe.get_doc("Vault Credential", cred.name)
        doc.vault_space = DISABLED_SPACE
        with self.assertRaises(frappe.exceptions.ValidationError):
            doc.save()

    def test_credential_type_cannot_change_after_insert(self):
        cred = self._make_credential(title="Immutable Type Test")
        doc = frappe.get_doc("Vault Credential", cred.name)
        doc.credential_type = "wifi"
        with self.assertRaises(frappe.exceptions.ValidationError):
            doc.save()

    # ------------------------------------------------------------------------ reveal

    def test_reveal_secret_by_member_succeeds_and_logs(self):
        cred = self._make_credential(title="Reveal Success Test")
        frappe.set_user(READER)
        result = reveal_secret(credential=cred.name, field_key="password", action="reveal")
        self.assertEqual(result["value"], "Tr0ub4dor&3xtra!Long")

        log = frappe.get_last_doc(
            "Credential Access Log", filters={"credential": cred.name, "action": "reveal"}
        )
        self.assertEqual(log.outcome, "success")
        self.assertEqual(log.user, READER)

    def test_reveal_secret_by_outsider_is_denied_and_logged(self):
        cred = self._make_credential(title="Reveal Denied Test")
        frappe.set_user(OUTSIDER)
        with self.assertRaises(frappe.PermissionError):
            reveal_secret(credential=cred.name, field_key="password", action="reveal")

        frappe.set_user("Administrator")
        log = frappe.get_last_doc(
            "Credential Access Log", filters={"credential": cred.name, "action": "reveal"}
        )
        self.assertEqual(log.outcome, "denied")

    def test_reveal_secret_by_auditor_is_denied_even_though_a_member(self):
        """Separation of duties (BRIEF §3): auditor-ness disqualifies reveal even for a
        user who also holds space membership."""
        cred = self._make_credential(title="Auditor Reveal Test")
        frappe.set_user(AUDITOR)
        with self.assertRaises(frappe.PermissionError):
            reveal_secret(credential=cred.name, field_key="password", action="reveal")

    def test_vault_admin_can_reveal_without_membership(self):
        cred = self._make_credential(title="Admin Reveal Test")
        _ensure_user("vault-admin@example.test", roles=("Vault Admin",))
        frappe.set_user("vault-admin@example.test")
        result = reveal_secret(credential=cred.name, field_key="password", action="reveal")
        self.assertEqual(result["value"], "Tr0ub4dor&3xtra!Long")

    def test_reveal_denied_when_space_disabled(self):
        cred = self._make_credential(title="Disabled Reveal Test", vault_space=DISABLED_SPACE)
        frappe.set_user(MANAGER)
        with self.assertRaises(frappe.PermissionError):
            reveal_secret(credential=cred.name, field_key="password", action="reveal")

    # -------------------------------------------------------------------- no leakage

    def test_get_doc_never_returns_the_plaintext_secret(self):
        cred = self._make_credential(title="No Leak Test")
        frappe.set_user(MANAGER)
        doc = frappe.get_doc("Vault Credential", cred.name)
        self.assertNotEqual(doc.password, "Tr0ub4dor&3xtra!Long")

    # ---------------------------------------------------------------------- audit trail

    def test_create_update_delete_each_write_one_log_row(self):
        frappe.set_user("Administrator")
        cred = self._make_credential(title="Audit Trail Test")
        self.assertTrue(
            frappe.db.exists(
                "Credential Access Log", {"credential": cred.name, "action": "create"}
            )
        )

        doc = frappe.get_doc("Vault Credential", cred.name)
        doc.notes = "changed"
        doc.save()
        self.assertTrue(
            frappe.db.exists(
                "Credential Access Log", {"credential": cred.name, "action": "update"}
            )
        )

        frappe.delete_doc("Vault Credential", cred.name)
        self.assertTrue(
            frappe.db.exists(
                "Credential Access Log", {"credential": cred.name, "action": "delete"}
            )
        )

    def test_log_row_survives_credential_deletion(self):
        """`ignore_links_on_delete` (hooks.py) must let the credential's own log rows
        outlive it — the dangling Link is the point, not a bug."""
        cred = self._make_credential(title="Survives Deletion Test")
        frappe.delete_doc("Vault Credential", cred.name)
        rows = frappe.get_all("Credential Access Log", filters={"credential": cred.name})
        self.assertGreater(len(rows), 0)
