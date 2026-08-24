"""Vault Space tests for the two auditor paths the permission hooks never see.

Run with a site: ``bench --site <site> run-tests --module \\
    sssihms_password_vault.password_vault.doctype.vault_space.test_vault_space``

Both cases come from the independent audit of 2026-08-24. Neither is reachable through
``credential_has_permission`` or ``credential_query_conditions``, which is exactly why the
three mirrored guards did not cover them: the rotation sweep runs as Administrator and
never consults the hooks, and the health report reached its own conclusion two layers
downstream of the role check.
"""

from __future__ import annotations

import frappe
from frappe.tests.utils import FrappeTestCase
from frappe.utils import add_days, today

SPACE = "Test Space — Reminder Digest"
MANAGER = "vault-digest-manager@example.test"
AUDITOR = "vault-digest-auditor@example.test"


def _ensure_user(email: str, roles: tuple[str, ...] = ()) -> None:
    if not frappe.db.exists("User", email):
        frappe.get_doc(
            {
                "doctype": "User",
                "email": email,
                "first_name": email.split("@")[0],
                "send_welcome_email": 0,
            }
        ).insert(ignore_permissions=True)
    if roles:
        frappe.get_doc("User", email).add_roles(*roles)


class TestVaultSpaceAuditorPaths(FrappeTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        frappe.set_user("Administrator")

        for role in ("Vault Admin", "Vault Auditor", "Vault User"):
            if not frappe.db.exists("Role", role):
                frappe.get_doc(
                    {"doctype": "Role", "role_name": role, "desk_access": 1}
                ).insert(ignore_permissions=True)

        _ensure_user(MANAGER)
        # A Manager of the space who is ALSO an auditor: the case DESIGN §2.4(b) names and
        # the one a narrower "auditor and nothing else" test would miss, since Vault User
        # is auto-granted the moment anyone joins a space.
        _ensure_user(AUDITOR, roles=("Vault Auditor",))

        if not frappe.db.exists("Vault Space", SPACE):
            frappe.get_doc(
                {
                    "doctype": "Vault Space",
                    "space_name": SPACE,
                    "members": [
                        {"user": MANAGER, "access_level": "Manager"},
                        {"user": AUDITOR, "access_level": "Manager"},
                    ],
                }
            ).insert(ignore_permissions=True)

    def setUp(self):
        frappe.set_user("Administrator")

    def tearDown(self):
        frappe.set_user("Administrator")

    def test_auditor_manager_is_excluded_from_the_rotation_digest(self):
        """M2/T4: the digest lists the titles and due dates of every overdue credential in
        the space — precisely what an auditor must not see. The sweep runs as Administrator
        and selected recipients on `access_level == "Manager"` alone, so an auditor who was
        also a Manager received them, in a Notification Log row inserted with
        ignore_permissions and in an email body that then sits in tabEmail Queue."""
        from sssihms_password_vault.vault.reminders import daily_rotation_sweep

        settings = frappe.get_single("Vault Settings")
        settings.rotation_reminders_enabled = 1
        settings.save(ignore_permissions=True)

        cred = frappe.get_doc(
            {
                "doctype": "Vault Credential",
                "vault_space": SPACE,
                "credential_type": "login",
                "title": "Digest Exclusion Test",
                "username": "svc-digest",
                "password": "Tr0ub4dor&3xtra!Long",
                "rotation_due": add_days(today(), -30),
            }
        )
        cred.insert(ignore_permissions=True)
        frappe.db.commit()

        subject_like = ("like", f"%{SPACE}%")
        before_auditor = frappe.db.count(
            "Notification Log", {"for_user": AUDITOR, "subject": subject_like}
        )

        daily_rotation_sweep()

        self.assertGreater(
            frappe.db.count("Notification Log", {"for_user": MANAGER, "subject": subject_like}),
            0,
            "the non-auditor Manager should still receive the digest",
        )
        self.assertEqual(
            frappe.db.count("Notification Log", {"for_user": AUDITOR, "subject": subject_like}),
            before_auditor,
            "an auditor must never receive credential titles",
        )

    def test_auditor_cannot_run_the_health_report(self):
        """L2/T4: the health report's roles list (Vault Admin / Vault User) does NOT
        exclude an auditor, because Vault User is auto-granted to every space member. What
        stopped them was credential_has_permission returning False in the per-document
        loop, leaving an empty result — a guard two layers downstream. Deny explicitly."""
        from sssihms_password_vault.password_vault.report.vault_health import vault_health

        frappe.set_user(AUDITOR)
        with self.assertRaises(frappe.PermissionError):
            vault_health.execute({"vault_space": SPACE})
        frappe.set_user("Administrator")
