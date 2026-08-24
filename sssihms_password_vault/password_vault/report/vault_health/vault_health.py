"""Vault Health — Script Report wrapper (DESIGN.md §6).

Thin Frappe glue only: all scoring/grouping logic lives in ``vault/health.py``, which is
what stays testable without a site. Chosen as a Script Report rather than a Page precisely
so ``execute()`` runs server-side — decryption never touches the client — and filters,
column rendering and export come for free.
"""

from __future__ import annotations

import frappe
from frappe import _
from frappe.utils import escape_html

from sssihms_password_vault.vault.audit import write_access_log
from sssihms_password_vault.vault.health import analyze, collect_uses
from sssihms_password_vault.vault.permissions import (
    get_membership_level,
    is_vault_admin,
    is_vault_auditor_only,
    space_is_disabled,
)

#: Rendered as `Data` columns, which Frappe does not escape — see the same constant in
#: credential_access_report.py. `title` comes from a credential an Editor controls and
#: `field_label` from a child row they name, so both are user-authored (audit finding H1).
_ESCAPED_FIELDS = ("title", "field_label")


def execute(filters: dict | None = None):
    filters = filters or {}
    user = frappe.session.user
    vault_space = filters.get("vault_space") or None

    # Re-check even though the report is role-gated (Vault Admin / Vault User only, per
    # vault_health.json) — a Vault User's report access is a ceiling, not a grant; a
    # non-admin must still be a Manager of the one space they are asking about.
    #
    # An auditor is NOT excluded by that roles list, contrary to what this comment used to
    # claim (audit finding L2): `Vault User` is auto-granted to every space member, so an
    # auditor who is also a space Manager passes both the roles list and the Manager check
    # below. What actually stopped them was credential_has_permission returning False in
    # the per-document loop, leaving `accessible` empty — the third mirror, two layers
    # down. Deny explicitly here instead of depending on that: separation of duties should
    # not be an emergent property of a loop.
    if is_vault_auditor_only(user):
        frappe.throw(
            _("The Vault Auditor role cannot run the health report."),
            frappe.PermissionError,
        )

    if not is_vault_admin(user):
        if not vault_space:
            frappe.throw(_("Select a Vault Space to run this report."))
        if get_membership_level(user, vault_space) != "Manager":
            frappe.throw(
                _("Only a space Manager or Vault Admin can run this report."),
                frappe.PermissionError,
            )
        if space_is_disabled(vault_space):
            # A disabled space is documented as read-only and reveal-free. The health
            # report decrypts every secret in scope server-side to score it, so running it
            # over an archived space is a reveal in all but name (audit finding L4). Vault
            # Admin is exempt: archival is an admin policy, not a limit on the admin.
            frappe.throw(
                _("This space is disabled. Re-enable it to run the health report."),
                frappe.PermissionError,
            )

    # frappe.get_all does NOT apply credential_query_conditions — it sets
    # ignore_permissions=True unconditionally, so this list is every credential in scope of
    # the filter regardless of who is asking. This comment used to claim the opposite
    # (audit finding L1); the sibling access report states it correctly.
    #
    # The scoping is done entirely by the per-document frappe.has_permission below, which
    # does route through credential_has_permission. Note that frappe.get_doc checks
    # nothing, so the has_permission call is load-bearing and must stay ahead of it.
    # Never ignore_permissions anywhere in this path.
    cred_filters = {"vault_space": vault_space} if vault_space else {}
    rows = frappe.get_all(
        "Vault Credential", filters=cred_filters, fields=["name", "vault_space"]
    )

    accessible: list[str] = []
    spaces_scanned: set[str] = set()
    for row in rows:
        if not frappe.has_permission("Vault Credential", ptype="read", doc=row.name, user=user):
            continue
        accessible.append(row.name)
        if row.vault_space:
            spaces_scanned.add(row.vault_space)

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

    for row in result["rows"]:
        for field in _ESCAPED_FIELDS:
            if row.get(field):
                row[field] = escape_html(row[field])

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
