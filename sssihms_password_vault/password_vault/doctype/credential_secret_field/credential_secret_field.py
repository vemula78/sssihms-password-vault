from __future__ import annotations

from frappe.model.document import Document


class CredentialSecretField(Document):
    """Child of Vault Credential. Validation lives in the parent controller, which is the
    only place that can see sibling rows (duplicate field keys) and the credential type
    (template conformance).

    `secret_value` is a `Password` field: Frappe encrypts it with the site encryption key
    into `__Auth`, keyed by (doctype, this row's name, "secret_value"), and leaves only
    asterisks in this table's column. Retrieval is
    `frappe.utils.password.get_decrypted_password("Credential Secret Field", row.name,
    "secret_value")` — and in this app that call appears only in the audited reveal path
    and in the health report.
    """

    pass
