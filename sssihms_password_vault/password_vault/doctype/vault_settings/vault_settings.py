from __future__ import annotations

import frappe
from frappe import _
from frappe.model.document import Document
from frappe.utils import cint


class VaultSettings(Document):
    """Site-wide vault settings.

    Note what is deliberately *not* here: the reveal and generator rate limits. Those are
    code constants in `vault/api.py` — a limit an admin can raise from the UI is not a
    limit. `reveal_auto_hide_seconds` is a client convenience, not a control: the secret
    has already been returned to the browser by the time it applies.
    """

    def validate(self) -> None:
        if cint(self.reminder_repeat_days) < 1:
            frappe.throw(_("Reminder repeat must be at least 1 day."))
        if cint(self.reveal_auto_hide_seconds) < 1:
            frappe.throw(_("Reveal auto-hide must be at least 1 second."))
        if not 8 <= cint(self.default_password_length) <= 128:
            frappe.throw(_("Default password length must be between 8 and 128."))
        if not 3 <= cint(self.default_passphrase_words) <= 12:
            frappe.throw(_("Default passphrase words must be between 3 and 12."))
