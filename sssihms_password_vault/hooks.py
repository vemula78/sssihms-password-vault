app_name = "sssihms_password_vault"
app_title = "SSSIHMS Password Vault"
app_publisher = "Praveen Vemula"
app_description = (
    "Organizational password manager for SSSIHMS: department-scoped shared credentials "
    "with role-based access, reveal auditing and rotation reminders."
)
app_email = "vemula78@gmail.com"
app_license = "mit"

after_install = "sssihms_password_vault.install.after_install"

# Row-level access is *membership*, not role. The DocPerm rows on Vault Credential /
# Vault Space grant a ceiling to the `Vault User` role; these two hooks narrow it to the
# caller's Vault Space Member level per row. Both halves are needed and neither is
# sufficient alone: has_permission gates opening/saving one document, and
# permission_query_conditions gates what SQL-backed list/report queries return. Both are
# ORM-level, so no UI can route around them.
has_permission = {
    "Vault Credential": "sssihms_password_vault.vault.permissions.credential_has_permission",
    "Vault Space": "sssihms_password_vault.vault.permissions.space_has_permission",
}
permission_query_conditions = {
    "Vault Credential": "sssihms_password_vault.vault.permissions.credential_query_conditions",
    "Vault Space": "sssihms_password_vault.vault.permissions.space_query_conditions",
}

# Close the framework's own password-retrieval RPC (frappe.client.get_password), which
# would otherwise hand back a decrypted secret with NO access-log row, bypassing the entire
# reveal audit + rate limit (Codex finding #1). The override refuses outright for any Vault
# doctype and points the caller at the audited reveal_secret endpoint; every other doctype
# falls through to the stock implementation. Registered here so it applies to the HTTP route,
# not just direct Python callers.
override_whitelisted_methods = {
    "frappe.client.get_password": "sssihms_password_vault.vault.api.get_password_override",
}

# Credential Access Log is an append-only audit trail and must outlive the credential it
# logs. Without this exemption Frappe's own delete-link check would block deleting *any*
# credential that has ever been revealed once, since the log row's `credential` Link field
# would still point at it. Same mechanism Frappe uses to exempt Communication/ToDo, and
# the same call this project's sibling app makes for Staff Document Access.
ignore_links_on_delete = ["Credential Access Log"]

# Rotation sweep: notifies each space's Manager-level members about credentials past their
# rotation_due date, at the Vault Settings re-remind cadence.
scheduler_events = {
    "daily": ["sssihms_password_vault.vault.reminders.daily_rotation_sweep"],
}
