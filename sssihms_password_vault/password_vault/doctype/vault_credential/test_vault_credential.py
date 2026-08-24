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
from sssihms_password_vault.vault.audit import write_access_log
from sssihms_password_vault.vault.permissions import get_membership_level

SPACE = "Test Space — Vault Credential"
DISABLED_SPACE = "Test Space — Disabled"

READER = "vault-reader@example.test"
EDITOR = "vault-editor@example.test"
MANAGER = "vault-manager@example.test"
OUTSIDER = "vault-outsider@example.test"
AUDITOR = "vault-auditor@example.test"
#: No roles at all — the case the pre-existing OUTSIDER fixture deliberately does not
#: cover, and the one the reveal door was open to.
NOROLE = "vault-norole@example.test"


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

    # ------------------------------------------------ Codex audit regressions

    def test_auditor_member_cannot_read_credentials(self):
        """Codex finding #2: an auditor who is also a space member (AUDITOR is a Reader in
        SPACE) must still be denied every credential read — at the ORM layer, not just in
        reveal_secret. Separation of duties holds regardless of membership."""
        cred = self._make_credential(title="Auditor Member Read Test")
        self.assertFalse(
            frappe.has_permission("Vault Credential", ptype="read", doc=cred.name, user=AUDITOR)
        )
        frappe.set_user(AUDITOR)
        names = frappe.get_list("Vault Credential", filters={"vault_space": SPACE}, pluck="name")
        self.assertEqual(names, [])

    def test_framework_get_password_is_blocked(self):
        """Codex finding #1: frappe.client.get_password must not hand back a vault secret
        with no audit row. The override refuses and logs the attempt."""
        cred = self._make_credential(title="GetPassword Bypass Test")
        before = frappe.db.count("Credential Access Log", {"credential": cred.name})
        from sssihms_password_vault.vault.api import get_password_override

        with self.assertRaises(frappe.PermissionError):
            get_password_override("Vault Credential", cred.name, "password")
        after = frappe.db.count("Credential Access Log", {"credential": cred.name})
        self.assertGreater(after, before)  # the blocked attempt is on record

    def test_invalid_reveal_action_is_logged(self):
        """Codex finding #4: a malformed action is an attempted-abuse signal and must be
        logged as a denial, not thrown unrecorded."""
        from sssihms_password_vault.vault.api import reveal_secret

        cred = self._make_credential(title="Invalid Action Test")
        frappe.set_user(MANAGER)
        with self.assertRaises(Exception):
            reveal_secret(cred.name, "password", action="exfiltrate")
        frappe.set_user("Administrator")
        self.assertTrue(
            frappe.db.exists(
                "Credential Access Log", {"credential": cred.name, "outcome": "denied"}
            )
        )

    def test_credential_has_no_version_tracking(self):
        """Codex finding #3: version tracking is off on Vault Credential, so no Version row
        can ever carry a secret field regardless of Frappe's masking internals."""
        meta = frappe.get_meta("Vault Credential")
        self.assertFalse(meta.track_changes)

    # -------------------------------------- independent audit (2026-08-24) regressions

    def test_reveal_requires_a_vault_role(self):
        """H3/T9: an authenticated account with no vault role at all must be refused
        before anything is resolved, and must not be able to write a log row.

        NOROLE is created without roles on purpose — the opposite of OUTSIDER, who carries
        Vault User deliberately. The old code let any account probe sequential VC-#####
        names, learn which existed, and commit one attacker-authored row per probe."""
        _ensure_user(NOROLE)
        cred = self._make_credential(title="No Role Test")
        before = frappe.db.count("Credential Access Log", {"credential": cred.name})
        frappe.set_user(NOROLE)
        with self.assertRaises(frappe.PermissionError):
            reveal_secret(cred.name, "password")
        frappe.set_user("Administrator")
        self.assertEqual(
            frappe.db.count("Credential Access Log", {"credential": cred.name}), before
        )

    def test_nonexistent_credential_answers_like_an_inaccessible_one(self):
        """H3: existence must not be observable. A bogus name and a real-but-forbidden one
        both raise PermissionError, and neither writes a row."""
        frappe.set_user(MANAGER)
        with self.assertRaises(frappe.PermissionError):
            reveal_secret("VC-99999999", "password")
        frappe.set_user("Administrator")

    def test_malformed_field_key_is_rejected_and_never_stored_verbatim(self):
        """H1: a field key is a template identifier. Markup in it used to reach the log
        verbatim and then render, unescaped, in the report an admin or auditor opens."""
        cred = self._make_credential(title="Field Key Injection Test")
        payload = "<img src=x onerror=alert(1)>"
        frappe.set_user(MANAGER)
        with self.assertRaises(frappe.PermissionError):
            reveal_secret(cred.name, payload)
        frappe.set_user("Administrator")
        rows = frappe.get_all(
            "Credential Access Log",
            filters={"credential": cred.name, "outcome": "denied"},
            fields=["field_key", "field_label", "detail"],
        )
        self.assertTrue(rows)
        for row in rows:
            for value in (row.field_key, row.field_label, row.detail):
                self.assertNotIn("<", value or "")

    def test_unknown_field_key_is_logged_as_denied_not_success(self):
        """M5: a well-formed but nonexistent field key used to commit an
        `outcome="success"` row — permanently, in an append-only table — for a reveal that
        returned nothing and never could."""
        cred = self._make_credential(title="Unknown Field Test")
        frappe.set_user(MANAGER)
        with self.assertRaises(frappe.PermissionError):
            reveal_secret(cred.name, "no_such_field")
        frappe.set_user("Administrator")
        rows = frappe.get_all(
            "Credential Access Log",
            filters={"credential": cred.name, "field_key": "no_such_field"},
            fields=["outcome", "detail"],
        )
        self.assertTrue(rows)
        for row in rows:
            self.assertEqual(row.outcome, "denied")

    def test_access_report_escapes_log_content(self):
        """H1/T2: whatever is in the log, the report must not hand markup to the browser.
        Covers rows written before the door-level check existed."""
        cred = self._make_credential(title="Report Escaping Test")
        write_access_log(
            cred,
            action="reveal",
            outcome="denied",
            field_key="password",
            field_label="<img src=x onerror=alert(1)>",
            detail="<script>alert(2)</script>",
        )
        frappe.db.commit()
        from sssihms_password_vault.password_vault.report.credential_access_report import (
            credential_access_report,
        )

        result = credential_access_report.execute({"credential": cred.name})
        rows = result[1]
        self.assertTrue(rows)
        for row in rows:
            for field in ("field_label", "detail", "credential_title"):
                self.assertNotIn("<", row.get(field) or "")

    def test_docshare_cannot_grant_credential_access(self):
        """M1/T3: Frappe evaluates document sharing after a has_permission denial and ORs
        the shared set over permission_query_conditions — so a DocShare row would overturn
        both membership hooks, including the auditor's 1=0 lock. It must be refused."""
        cred = self._make_credential(title="DocShare Test")
        # OUTSIDER, not NOROLE: this has to prove that a share cannot *widen* the
        # membership hooks, so the sharee must be someone the role ceiling already admits.
        # A role-less account is stopped earlier and more bluntly — frappe.get_list raises
        # PermissionError at check_select_permission rather than returning an empty list,
        # which proves nothing about DocShare.
        with self.assertRaises(frappe.PermissionError):
            frappe.share.add("Vault Credential", cred.name, OUTSIDER, read=1)
        self.assertFalse(
            frappe.db.exists(
                "DocShare", {"share_doctype": "Vault Credential", "share_name": cred.name}
            )
        )
        frappe.set_user(OUTSIDER)
        self.assertEqual(frappe.get_list("Vault Credential", pluck="name"), [])
        frappe.set_user("Administrator")

    def test_share_docperm_is_off(self):
        """M1: the guard above is what makes this stick, but the DocPerm should not offer
        `share` in the first place."""
        for doctype in ("Vault Credential", "Vault Space"):
            for perm in frappe.get_meta(doctype).permissions:
                self.assertFalse(perm.share, f"{doctype} still grants share to {perm.role}")

    def test_only_vault_admin_can_change_the_disabled_flag(self):
        """M7/T8: `disabled` is enforced against exactly the people who could turn it off.
        A space Manager holds write on their space for the member table; that write must not
        extend to the archival lock."""
        space = frappe.get_doc("Vault Space", SPACE)
        frappe.set_user(MANAGER)
        space.disabled = 1
        with self.assertRaises(frappe.PermissionError):
            space.save()
        frappe.set_user("Administrator")
        self.assertFalse(frappe.db.get_value("Vault Space", SPACE, "disabled"))

    def test_get_password_override_is_actually_wired(self):
        """T1: the existing bypass test calls get_password_override directly, so it passes
        even with the hooks.py entry deleted — which is the regression it was written to
        catch. Assert the wiring itself."""
        self.assertEqual(
            frappe.override_whitelisted_method("frappe.client.get_password"),
            "sssihms_password_vault.vault.api.get_password_override",
        )

    def test_child_row_get_password_bypass_is_logged(self):
        """M8: the child-row path is the more targeted bypass — every non-login template
        keeps its secrets in Credential Secret Field rows — and it was refused with nothing
        on record, despite the comment claiming a parent lookup."""
        cred = self._make_credential(
            title="Child Row Bypass Test",
            credential_type="netbanking",
            secret_fields=[
                {
                    "field_key": "customerId",
                    "label": "Customer ID",
                    "is_secret": 1,
                    "secret_value": "CID-987654",
                }
            ],
        )
        row_name = cred.secret_fields[0].name
        before = frappe.db.count("Credential Access Log", {"credential": cred.name})
        from sssihms_password_vault.vault.api import get_password_override

        with self.assertRaises(frappe.PermissionError):
            get_password_override("Credential Secret Field", row_name, "secret_value")
        self.assertGreater(
            frappe.db.count("Credential Access Log", {"credential": cred.name}), before
        )
