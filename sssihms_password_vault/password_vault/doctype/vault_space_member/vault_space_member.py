from __future__ import annotations

from frappe.model.document import Document


class VaultSpaceMember(Document):
    """Child of Vault Space. Validation lives in the parent controller, which is the only
    place that can see the whole member list (duplicate users, at-least-one-Manager)."""

    pass
