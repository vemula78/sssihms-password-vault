from __future__ import annotations

import frappe
from frappe import _
from frappe.model.document import Document
from frappe.utils import add_days, cint, today

from sssihms_password_vault.vault.audit import write_access_log
from sssihms_password_vault.vault.templates import (
    FIELD_KINDS,
    TEMPLATES,
    mask_value,
    template_field_keys,
)

#: Set once, never changed. Moving a credential between spaces silently changes who can
#: read it, and changing its type invalidates every child row's template conformance. Both
#: are "delete and recreate" operations, which leaves an audit trail; a quiet edit would
#: not.
IMMUTABLE_AFTER_INSERT = ("vault_space", "credential_type")


class VaultCredential(Document):
    """One shared credential. Secret values live only in `Password` fieldtype columns —
    the parent `password` field and `Credential Secret Field.secret_value` — which Frappe
    stores encrypted in `__Auth`, leaving asterisks in the table column. They are returned
    only by `vault.api.reveal_secret`, which logs first.
    """

    def validate(self) -> None:
        self._block_immutable_changes()
        self._validate_secret_rows()
        self._warn_on_unknown_template_keys()
        self._compute_masked_hints()
        self._track_rotation()

    # ------------------------------------------------------------------ validation

    def _block_immutable_changes(self) -> None:
        before = self.get_doc_before_save()
        if before is None:
            return
        for fieldname in IMMUTABLE_AFTER_INSERT:
            if self.get(fieldname) != before.get(fieldname):
                frappe.throw(
                    _(
                        "{0} cannot be changed after the credential is created. "
                        "Delete this credential and create a new one instead."
                    ).format(_(self.meta.get_label(fieldname))),
                    title=_("Vault Credential"),
                )

    def _validate_secret_rows(self) -> None:
        """Child-row hygiene. The first rule is the important one: a row flagged
        `is_secret` must leave the plaintext `value` column empty, so a secret can never
        land in an unencrypted column by UI accident (a user ticking Is Secret after typing
        into Value, or a form script writing to the wrong field)."""
        seen: set[str] = set()
        for row in self.secret_fields:
            key = (row.field_key or "").strip()
            if not key:
                frappe.throw(_("Every secret field needs a field key."))
            row.field_key = key

            if key in seen:
                frappe.throw(
                    _("Field key {0} appears more than once.").format(key),
                    title=_("Duplicate Field"),
                )
            seen.add(key)

            if row.field_kind not in FIELD_KINDS:
                frappe.throw(
                    _("{0} is not a valid field kind for {1}.").format(row.field_kind, key)
                )

            if row.is_secret and (row.value or "").strip():
                frappe.throw(
                    _(
                        "Field {0} is marked secret, so its value must be entered in "
                        "Secret Value (encrypted) and Value must be left empty."
                    ).format(row.label or key),
                    title=_("Secret In Plaintext Column"),
                )

    def _warn_on_unknown_template_keys(self) -> None:
        """Soft check: extra rows are legal (that is exactly how `custom` works), but a
        typo'd key silently breaks the health report's `is_password` accounting and the
        form script's template refresh. Surface it, do not block on it."""
        if self.credential_type == "custom" or self.credential_type not in TEMPLATES:
            return
        known = template_field_keys(self.credential_type)
        unknown = [row.field_key for row in self.secret_fields if row.field_key not in known]
        if unknown:
            frappe.msgprint(
                _("These field keys are not part of the {0} template: {1}").format(
                    self.credential_type, ", ".join(sorted(set(unknown)))
                ),
                title=_("Unrecognised Fields"),
                indicator="orange",
            )

    def _compute_masked_hints(self) -> None:
        """`masked_hint` is stored unencrypted so lists and forms can show the last four
        characters without a reveal and without an audit row — the semantics of
        `maskValue()` in the personal app. It is only recomputed when a fresh value has
        actually been supplied: on an ordinary re-save the Password field round-trips as
        asterisks, and hashing those would replace a real hint with `•••• ****`.
        """
        for row in self.secret_fields:
            if not row.is_masked:
                row.masked_hint = None
                continue
            source = row.secret_value if row.is_secret else row.value
            if _value_supplied(source):
                row.masked_hint = mask_value(source)

    def _track_rotation(self) -> None:
        """`last_rotated` and `rotation_due` follow the secrets, not the document.

        A title correction is not a rotation, so the schedule must not move for it — hence
        `_value_supplied`, which distinguishes a freshly typed secret from an untouched
        Password field round-tripping as asterisks.
        """
        if not self._secret_was_supplied():
            return

        self.last_rotated = today()
        interval = cint(self.rotation_interval_days)
        if interval > 0:
            self.rotation_due = add_days(today(), interval)
            # The rotation just happened, so the overdue-reminder clock starts fresh —
            # otherwise the next sweep would still be inside the repeat window and the
            # new due date would go unchased.
            self.last_reminded_on = None

    def _secret_was_supplied(self) -> bool:
        if _value_supplied(self.password):
            return True
        return any(
            row.is_secret and _value_supplied(row.secret_value) for row in self.secret_fields
        )

    # ------------------------------------------------------------------- audit trail

    def after_insert(self) -> None:
        write_access_log(self, action="create")

    def on_update(self) -> None:
        # Guarded on in_insert rather than on is_new(): whether Frappe runs on_update
        # during insert is a framework detail, and a create logged twice (once as create,
        # once as update) is a misleading audit trail.
        if self.flags.in_insert:
            return
        # Field values are never logged, only that an update happened. The non-secret diff
        # is in the Version row; the secret diff is deliberately nowhere.
        write_access_log(self, action="update")

    def on_trash(self) -> None:
        write_access_log(self, action="delete")


def _value_supplied(value) -> bool:
    """True when `value` is a real value the user just typed, rather than the asterisk
    placeholder Frappe round-trips for an untouched `Password` field.

    On form save Frappe sends the real new value only when the user typed one; an untouched
    Password field arrives as `"*" * n` or None. There is no way to distinguish a user who
    genuinely typed only asterisks — an acceptable trade for not resetting the rotation
    clock on every unrelated edit.
    """
    if value is None:
        return False
    text = str(value)
    if not text.strip():
        return False
    return set(text) != {"*"}
