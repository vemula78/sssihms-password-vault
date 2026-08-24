"""Append-only proofs for Credential Access Log (DESIGN.md §4).

Run with a site: ``bench --site <site> run-tests --app sssihms_password_vault \\
    --module sssihms_password_vault.password_vault.doctype.credential_access_log.test_credential_access_log``

Not runnable without a bench/site — the doctype and its DocPerm rows have to exist in the
database. See vault/tests/ for the pure-logic suites that run without one.
"""

from __future__ import annotations

import frappe
from frappe.tests.utils import FrappeTestCase

from sssihms_password_vault.vault.audit import write_access_log

TEST_SPACE = "Test Space — Access Log"


class TestCredentialAccessLog(FrappeTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        frappe.set_user("Administrator")
        if not frappe.db.exists("Vault Space", TEST_SPACE):
            frappe.get_doc(
                {
                    "doctype": "Vault Space",
                    "space_name": TEST_SPACE,
                    "members": [{"user": "Administrator", "access_level": "Manager"}],
                }
            ).insert(ignore_permissions=True)

    def setUp(self):
        frappe.set_user("Administrator")

    def tearDown(self):
        frappe.flags.vault_audit_delete_override = False
        frappe.set_user("Administrator")

    # -------------------------------------------------------------- creation path

    def test_write_access_log_creates_a_row(self):
        row = write_access_log(
            None, vault_space=TEST_SPACE, action="membership", detail="test setup"
        )
        self.assertTrue(frappe.db.exists("Credential Access Log", row.name))
        self.assertEqual(row.action, "membership")
        self.assertEqual(row.outcome, "success")
        self.assertEqual(row.user, "Administrator")

    def test_no_role_can_create_directly(self):
        """DocPerms grant `create` to nobody (§1.6): a permission-checked insert must fail
        for every role-based account, Vault Admin included — rows exist only via
        write_access_log's ignore_permissions insert. Administrator is deliberately NOT the
        actor here: Frappe hardcodes Administrator past all permission checks, so an
        Administrator insert succeeding proves nothing about the DocPerm ceiling."""
        admin_user = "vault-admin-logtest@example.test"
        if not frappe.db.exists("User", admin_user):
            frappe.get_doc(
                {
                    "doctype": "User",
                    "email": admin_user,
                    "first_name": "vault-admin-logtest",
                    "send_welcome_email": 0,
                }
            ).insert(ignore_permissions=True)
        frappe.get_doc("User", admin_user).add_roles("Vault Admin")

        frappe.set_user(admin_user)
        doc = frappe.get_doc(
            {
                "doctype": "Credential Access Log",
                "credential_title": "(direct insert attempt)",
                "vault_space": TEST_SPACE,
                "action": "reveal",
                "outcome": "success",
                "user": admin_user,
                "timestamp": frappe.utils.now(),
            }
        )
        with self.assertRaises(frappe.PermissionError):
            doc.insert()

    # -------------------------------------------------------------- immutability

    def test_existing_row_cannot_be_saved(self):
        row = write_access_log(None, vault_space=TEST_SPACE, action="membership", detail="a")
        row = frappe.get_doc("Credential Access Log", row.name)
        row.detail = "tampered"
        with self.assertRaises(frappe.PermissionError):
            row.save(ignore_permissions=True)

    # -------------------------------------------------------------- deletion path

    def test_delete_denied_without_override(self):
        row = write_access_log(None, vault_space=TEST_SPACE, action="membership", detail="b")
        with self.assertRaises(frappe.PermissionError):
            frappe.delete_doc("Credential Access Log", row.name, ignore_permissions=True)
        self.assertTrue(frappe.db.exists("Credential Access Log", row.name))

    def test_delete_denied_for_system_manager_without_flag(self):
        """Holding System Manager is necessary but not sufficient — the console-only flag
        must also be set."""
        row = write_access_log(None, vault_space=TEST_SPACE, action="membership", detail="c")
        frappe.flags.vault_audit_delete_override = False
        with self.assertRaises(frappe.PermissionError):
            frappe.delete_doc("Credential Access Log", row.name, ignore_permissions=True)

    def test_delete_allowed_with_system_manager_and_console_flag(self):
        row = write_access_log(None, vault_space=TEST_SPACE, action="membership", detail="d")
        self.assertIn("System Manager", frappe.get_roles("Administrator"))
        frappe.flags.vault_audit_delete_override = True
        frappe.delete_doc("Credential Access Log", row.name, ignore_permissions=True)
        self.assertFalse(frappe.db.exists("Credential Access Log", row.name))

    def test_bulk_delete_from_list_view_hits_the_same_guard(self):
        """Frappe's bulk delete calls on_trash per document — same block, no shortcut."""
        row = write_access_log(None, vault_space=TEST_SPACE, action="membership", detail="e")
        with self.assertRaises(frappe.PermissionError):
            for name in [row.name]:
                frappe.delete_doc("Credential Access Log", name, ignore_permissions=True)
