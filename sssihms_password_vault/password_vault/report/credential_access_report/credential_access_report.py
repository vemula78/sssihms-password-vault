"""Credential Access Report — the access log, scoped to what the caller may audit.

Who sees what:

* **Vault Admin** / **System Manager** — every space.
* **Vault Auditor** — every space. That is the point of the role: the auditor reads the
  log across the whole organization and never reads a credential (no DocPerm row on Vault
  Credential at all, and `reveal_secret` refuses the auditor role outright).
* **Vault User** — only the spaces in which they hold `Manager`. A space Manager needs to
  see who has been revealing their department's credentials; a Reader or Editor does not.

This report is why `Vault User` has no read DocPerm on Credential Access Log: giving a
space Manager direct doctype read would expose every space's log, and a
`permission_query_conditions` hook on the log would then have to duplicate this scoping.
One scoped report is the smaller surface.

The rows are read with `frappe.get_all`, which ignores permissions — deliberate, and the
reason the space scope below is computed *first* and applied as a hard `in` filter that is
never derived from user input. A caller who passes a `vault_space` filter they cannot audit
gets an empty result, not someone else's log.
"""

from __future__ import annotations

import frappe
from frappe import _

from sssihms_password_vault.vault.audit import ACTIONS, OUTCOMES
from sssihms_password_vault.vault.permissions import (
    get_managed_spaces,
    is_vault_admin,
    is_vault_auditor,
)

#: A log query with no bound is a full table scan of the most sensitive table in the app.
_PAGE_LENGTH = 2000


def execute(filters: dict | None = None):
    filters = frappe._dict(filters or {})
    user = frappe.session.user

    sees_everything = is_vault_admin(user) or is_vault_auditor(user)
    allowed_spaces = None if sees_everything else get_managed_spaces(user)

    if allowed_spaces is not None and not allowed_spaces:
        frappe.throw(
            _(
                "You can only audit spaces you manage, and you do not manage any. "
                "Ask a Vault Admin for Manager access, or use the Vault Health report."
            ),
            frappe.PermissionError,
        )

    query_filters: dict = {}
    if allowed_spaces is not None:
        query_filters["vault_space"] = ("in", allowed_spaces)

    requested_space = filters.get("vault_space")
    if requested_space:
        if allowed_spaces is not None and requested_space not in allowed_spaces:
            # Deliberately an empty result rather than an error: telling the caller that a
            # space exists but is out of scope is itself a disclosure.
            return _columns(), []
        query_filters["vault_space"] = requested_space

    # Every remaining filter is validated against a fixed set or a Frappe type before it
    # reaches the query — nothing here is interpolated into SQL.
    if filters.get("action") in ACTIONS:
        query_filters["action"] = filters.get("action")
    if filters.get("outcome") in OUTCOMES:
        query_filters["outcome"] = filters.get("outcome")
    if filters.get("user"):
        query_filters["user"] = filters.get("user")
    if filters.get("credential"):
        query_filters["credential"] = filters.get("credential")

    from_date, to_date = filters.get("from_date"), filters.get("to_date")
    if from_date and to_date:
        query_filters["timestamp"] = ("between", [from_date, f"{to_date} 23:59:59"])
    elif from_date:
        query_filters["timestamp"] = (">=", from_date)
    elif to_date:
        query_filters["timestamp"] = ("<=", f"{to_date} 23:59:59")

    rows = frappe.get_all(
        "Credential Access Log",
        filters=query_filters,
        fields=[
            "timestamp",
            "user",
            "action",
            "outcome",
            "credential",
            "credential_title",
            "vault_space",
            "field_label",
            "ip_address",
            "detail",
        ],
        order_by="timestamp desc",
        limit_page_length=_PAGE_LENGTH,
    )

    return _columns(), rows


def _columns() -> list[dict]:
    return [
        {
            "fieldname": "timestamp",
            "label": _("When"),
            "fieldtype": "Datetime",
            "width": 165,
        },
        {
            "fieldname": "user",
            "label": _("User"),
            "fieldtype": "Link",
            "options": "User",
            "width": 180,
        },
        {"fieldname": "action", "label": _("Action"), "fieldtype": "Data", "width": 110},
        {"fieldname": "outcome", "label": _("Outcome"), "fieldtype": "Data", "width": 90},
        {
            "fieldname": "vault_space",
            "label": _("Space"),
            "fieldtype": "Link",
            "options": "Vault Space",
            "width": 140,
        },
        {
            "fieldname": "credential_title",
            "label": _("Credential"),
            "fieldtype": "Data",
            "width": 200,
        },
        {
            "fieldname": "credential",
            "label": _("ID"),
            "fieldtype": "Link",
            "options": "Vault Credential",
            "width": 110,
        },
        {"fieldname": "field_label", "label": _("Field"), "fieldtype": "Data", "width": 160},
        {"fieldname": "ip_address", "label": _("IP"), "fieldtype": "Data", "width": 120},
        {"fieldname": "detail", "label": _("Detail"), "fieldtype": "Data", "width": 240},
    ]
