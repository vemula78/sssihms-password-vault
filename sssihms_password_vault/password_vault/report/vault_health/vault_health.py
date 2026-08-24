"""Vault Health — Script Report wrapper (DESIGN.md §6).

Thin Frappe glue only: all scoring/grouping logic lives in ``vault/health.py``, which is
what stays testable without a site. Chosen as a Script Report rather than a Page precisely
so ``execute()`` runs server-side — decryption never touches the client — and filters,
column rendering and export come for free.
"""

from __future__ import annotations

import frappe
from frappe import _

from sssihms_password_vault.vault.audit import write_access_log
from sssihms_password_vault.vault.health import analyze, collect_uses
from sssihms_password_vault.vault.permissions import get_membership_level, is_vault_admin


def execute(filters: dict | None = None):
    filters = filters or {}
    user = frappe.session.user
    vault_space = filters.get("vault_space") or None

    # Re-check even though the report is role-gated (Vault Admin / Vault User only, per
    # vault_health.json) — a Vault User's report access is a ceiling, not a grant; a
    # non-admin must still be a Manager of the one space they are asking about. Vault
    # Auditor is excluded by the roles list itself, so there is nothing to re-check for
    # that role here: it never reaches this function.
    if not is_vault_admin(user):
        if not vault_space:
            frappe.throw(_("Select a Vault Space to run this report."))
        if get_membership_level(user, vault_space) != "Manager":
            frappe.throw(
                _("Only a space Manager or Vault Admin can run this report."),
                frappe.PermissionError,
            )

    # get_all for names, then get_doc per credential — deliberately not a single get_all
    # with all fields, so credential_has_permission (and the query-conditions hook) stay in
    # force document-by-document. A caller who somehow reached this function with a
    # broader filters dict than their own membership permits still only sees what
    # get_doc lets through; never ignore_permissions.
    cred_filters = {"vault_space": vault_space} if vault_space else {}
    names = [row.name for row in frappe.get_all("Vault Credential", filters=cred_filters, fields=["name"])]

    accessible: list[str] = []
    spaces_scanned: set[str] = set()
    for name in names:
        try:
            doc = frappe.get_doc("Vault Credential", name)
            accessible.append(name)
            if doc.vault_space:
                spaces_scanned.add(doc.vault_space)
        except frappe.PermissionError:
            continue

    result = analyze(collect_uses(accessible), as_of=frappe.utils.today())

    # Audit: the log's ``vault_space`` is a mandatory Link (DESIGN.md §1.6), so an org-wide
    # run cannot be logged as one synthetic "(all spaces)" row — that name fails link
    # validation (cross-package finding, Package A review). Log one row per space actually
    # scanned instead: that IS what the admin saw, and every row links to a real space. A
    # single-space run degenerates to exactly one row. Zero accessible credentials → zero
    # rows, which is honest — nothing was decrypted.
    scope = vault_space or "org-wide"
    for space in sorted(spaces_scanned):
        write_access_log(
            None,
            vault_space=space,
            action="health_report",
            detail=f"scope={scope} score={result['summary']['score']}",
        )

    return _columns(), result["rows"], None, None, _report_summary(result["summary"])


def _columns() -> list[dict]:
    return [
        {"fieldname": "credential", "label": _("Credential"), "fieldtype": "Link", "options": "Vault Credential", "width": 110},
        {"fieldname": "title", "label": _("Title"), "fieldtype": "Data", "width": 180},
        {"fieldname": "vault_space", "label": _("Space"), "fieldtype": "Link", "options": "Vault Space", "width": 120},
        {"fieldname": "field_label", "label": _("Field"), "fieldtype": "Data", "width": 150},
        {"fieldname": "verdict", "label": _("Verdict"), "fieldtype": "Data", "width": 90},
        {"fieldname": "bits", "label": _("Bits"), "fieldtype": "Int", "width": 70},
        {"fieldname": "reused_group", "label": _("Reused group"), "fieldtype": "Data", "width": 100},
        {"fieldname": "reused_group_size", "label": _("Reused count"), "fieldtype": "Int", "width": 100},
        {"fieldname": "rotation_status", "label": _("Rotation"), "fieldtype": "Data", "width": 100},
        {"fieldname": "expiry_status", "label": _("Expiry"), "fieldtype": "Data", "width": 100},
    ]


def _report_summary(summary: dict) -> list[dict]:
    return [
        {"value": summary["total_passwords"], "label": _("Total passwords"), "datatype": "Int"},
        {
            "value": summary["weak_count"],
            "label": _("Weak"),
            "datatype": "Int",
            "indicator": "Red" if summary["weak_count"] else "Green",
        },
        {
            "value": summary["reused_count"],
            "label": _("Reused"),
            "datatype": "Int",
            "indicator": "Red" if summary["reused_count"] else "Green",
        },
        {"value": summary["score"], "label": _("Score"), "datatype": "Percent"},
    ]
