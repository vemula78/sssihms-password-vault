"""Install hooks."""

from __future__ import annotations

import frappe

#: The three roles this app owns. All are created here rather than shipped as fixtures so
#: that a re-install never duplicates them and so the comment explaining *why* there are
#: three lives next to the code that makes them.
#:
#: `Vault User` is not in BRIEF.md and is a deliberate addition (DESIGN.md deviation 1):
#: Frappe DocPerm rows grant by role, and a controller/`has_permission` hook can only ever
#: deny, never grant. Without a base role a space member would have zero ORM access and
#: `permission_query_conditions` would have nothing to narrow. `Vault User` is that base
#: grant; on its own it confers nothing on any row the holder is not a member of, because
#: every read/write path is filtered by Vault Space Member level.
_CUSTOM_ROLES = ("Vault Admin", "Vault Auditor", "Vault User")

MODULE_NAME = "Password Vault"


def after_install() -> None:
    _create_custom_roles()
    _create_module_def()
    frappe.db.commit()


def _create_custom_roles() -> None:
    for role_name in _CUSTOM_ROLES:
        if frappe.db.exists("Role", role_name):
            continue
        role = frappe.get_doc(
            {
                "doctype": "Role",
                "role_name": role_name,
                # Every one of these roles is a Desk role — there is no portal/website
                # surface in this app, and a role without desk access could not open the
                # credential form or any report.
                "desk_access": 1,
            }
        )
        role.insert(ignore_permissions=True)


def _create_module_def() -> None:
    """Frappe normally creates the Module Def from modules.txt during install; create it
    defensively so a partially-installed site (or a `migrate` before `install-app`
    finished) still resolves the doctypes' `module` field."""
    if frappe.db.exists("Module Def", MODULE_NAME):
        return
    frappe.get_doc(
        {
            "doctype": "Module Def",
            "module_name": MODULE_NAME,
            "app_name": "sssihms_password_vault",
        }
    ).insert(ignore_permissions=True)
