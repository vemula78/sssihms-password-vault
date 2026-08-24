"""Whitelisted RPC surface: reveal, template lookup, generator.

Every function here does its own explicit permission check before touching anything. The
only ``ignore_permissions=True`` in this app's request path is the audit-log insert in
``vault.audit`` (and the role assignment in ``vault_space.py``); nothing here bypasses a
check to get its work done.

No secret value is ever placed in an exception message, a log line, a traceback string, or
a ``detail`` field. ``reveal_secret`` returns the value in the response body and nowhere
else.
"""

from __future__ import annotations

import frappe
from frappe import _
from frappe.rate_limiter import rate_limit
from frappe.utils import cint
from frappe.utils.password import get_decrypted_password

from sssihms_password_vault.vault.audit import write_access_log
from sssihms_password_vault.vault.permissions import (
    get_membership_level,
    is_vault_admin,
    is_vault_auditor_only,
    space_is_disabled,
)
from sssihms_password_vault.vault.templates import TEMPLATES

#: Roles allowed to use the template lookup and the generator. Neither returns anything
#: about an existing credential, so membership is not required — but an arbitrary
#: authenticated ERPNext account has no business calling them either, and a Vault Auditor
#: has no business generating credential material.
_VAULT_ROLES = frozenset({"Vault User", "Vault Admin", "System Manager"})

#: Clamps for the generator. Code constants, not Vault Settings fields: a limit an admin
#: can raise from the UI is not a limit.
_MAX_PASSWORD_LENGTH = 128
_MIN_PASSWORD_LENGTH = 8
_MAX_PASSPHRASE_WORDS = 12
_MIN_PASSPHRASE_WORDS = 3
_MIN_PIN_DIGITS = 4
_MAX_PIN_DIGITS = 12


# --------------------------------------------------------------------------- reveal


@frappe.whitelist(methods=["POST"])
@rate_limit(limit=30, seconds=300)
def reveal_secret(credential: str, field_key: str, action: str = "reveal") -> dict:
    """Decrypt and return one secret field of one credential.

    The order of operations below is load-bearing (BRIEF security requirement 2):
    permission is re-checked server-side, the access-log row is written **and committed**
    before anything is decrypted, and a denial is logged before the throw.

    ``action`` is ``"reveal"`` or ``"copy"``. Both are the same operation from the server's
    point of view — the client does the clipboard write itself — but the log distinguishes
    them, because "copied to clipboard" and "displayed on screen" are different events to
    an auditor.
    """
    if action not in ("reveal", "copy"):
        frappe.throw(_("Invalid action."))

    user = frappe.session.user

    # frappe.get_doc does not itself check read permission (that is frappe.client.get's
    # job), which is what lets the denial path below resolve a field label and log a
    # meaningful row before refusing. Raises DoesNotExistError -> 404 for a bad name.
    doc = frappe.get_doc("Vault Credential", credential)

    level = get_membership_level(user, doc.vault_space)
    denied_reason = None
    if is_vault_auditor_only(user):
        # Defence in depth: an auditor who has somehow been added to a space still cannot
        # reveal. Checked before membership so auditor-ness can never be offset by it.
        denied_reason = "auditor role cannot reveal secrets"
    elif level is None and not is_vault_admin(user):
        denied_reason = "not a member of this space"
    elif space_is_disabled(doc.vault_space):
        denied_reason = "space is disabled"

    row = _find_secret_row(doc, field_key)
    field_label = _resolve_field_label(doc, field_key, row)

    if denied_reason:
        # Log the denial BEFORE throwing — a failed grab attempt is the most interesting
        # row in the whole log, and frappe.throw rolls the transaction back, so the commit
        # has to happen here rather than at request end.
        write_access_log(
            doc,
            action=action,
            outcome="denied",
            field_key=field_key,
            field_label=field_label,
            detail=denied_reason,
        )
        frappe.db.commit()
        frappe.throw(
            _("You do not have permission to reveal this secret."),
            frappe.PermissionError,
        )

    # ---- Log BEFORE decrypting/returning (BRIEF security requirement 2b). ----
    write_access_log(
        doc,
        action=action,
        outcome="success",
        field_key=field_key,
        field_label=field_label,
    )
    # Deliberate explicit commit: Frappe commits at request end, but if anything after this
    # point raises, the reveal attempt must still be on record. A log row for a reveal that
    # then failed is acceptable; a reveal with no log row is not.
    frappe.db.commit()

    if field_key == "password":
        value = (
            get_decrypted_password(
                "Vault Credential", doc.name, "password", raise_exception=False
            )
            or ""
        )
    else:
        if row is None:
            # Checked only after the permission gate: telling a non-member which field
            # keys exist would be a disclosure in itself.
            frappe.throw(_("That field does not exist on this credential."))
        if row.is_secret:
            value = (
                get_decrypted_password(
                    "Credential Secret Field", row.name, "secret_value", raise_exception=False
                )
                or ""
            )
        else:
            # Non-secret fields go through the same audited path when the UI asks for
            # them — cheap uniformity, and one fewer branch in the client.
            value = row.value or ""

    return {
        "value": value,
        "field_label": field_label,
        "auto_hide_seconds": cint(
            frappe.db.get_single_value("Vault Settings", "reveal_auto_hide_seconds")
        )
        or 30,
    }


def _find_secret_row(doc, field_key: str):
    for row in doc.get("secret_fields") or []:
        if row.field_key == field_key:
            return row
    return None


def _resolve_field_label(doc, field_key: str, row=None) -> str:
    if field_key == "password":
        return _("Password")
    if row is not None:
        return row.label or field_key
    return field_key


# ------------------------------------------------------------------------ templates


@frappe.whitelist()
def get_templates() -> dict:
    """The credential templates, for the form script to build child rows from.

    Static data — no credential, no space, no secret — so a role check is the whole of the
    permission story here. GET is fine.
    """
    _require_vault_role()
    return TEMPLATES


# ------------------------------------------------------------------------ generator


@frappe.whitelist(methods=["POST"])
@rate_limit(limit=60, seconds=300)
def generate_credential_secret(kind: str = "password", options: str | dict | None = None) -> dict:
    """Generate a password, passphrase or PIN.

    Not audit-logged (DESIGN.md deviation 4): a generated value belongs to no credential
    yet, so a log row would have no subject and would be pure noise. It is rate-limited
    instead. The generated value is returned and never written anywhere server-side.

    Unknown option keys are ignored and numeric options are clamped, so a hostile client
    cannot ask for a one-character password or a 10-million-word passphrase.
    """
    _require_vault_role()

    opts = _parse_options(options)

    # Imported inside the function body deliberately: generator.py is PACKAGE B, and this
    # keeps PACKAGE A importable (and its own tests runnable) before B lands. It also
    # keeps the wordlist out of memory for every request that never generates anything.
    from sssihms_password_vault.vault import generator

    if kind == "password":
        value = generator.generate_password(
            length=_clamp(
                cint(opts.get("length")) or 20, _MIN_PASSWORD_LENGTH, _MAX_PASSWORD_LENGTH
            ),
            lower=_flag(opts, "lower", True),
            upper=_flag(opts, "upper", True),
            digits=_flag(opts, "digits", True),
            symbols=_flag(opts, "symbols", True),
            exclude_ambiguous=_flag(opts, "exclude_ambiguous", True),
        )
    elif kind == "passphrase":
        value = generator.generate_passphrase(
            words=_clamp(
                cint(opts.get("words")) or 5, _MIN_PASSPHRASE_WORDS, _MAX_PASSPHRASE_WORDS
            ),
            separator=str(opts.get("separator") or "-")[:3],
            capitalize=_flag(opts, "capitalize", True),
            include_number=_flag(opts, "include_number", True),
        )
    elif kind == "pin":
        value = generator.generate_pin(
            digits=_clamp(cint(opts.get("digits")) or 6, _MIN_PIN_DIGITS, _MAX_PIN_DIGITS)
        )
    else:
        frappe.throw(_("Unknown generator kind."))

    return {"value": value, "kind": kind}


def _parse_options(options: str | dict | None) -> dict:
    if isinstance(options, str):
        options = frappe.parse_json(options)
    return options if isinstance(options, dict) else {}


def _clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, value))


def _flag(opts: dict, key: str, default: bool) -> bool:
    """JSON booleans arrive as True/False, but a form-encoded POST sends "0"/"1"/"false".
    Absent means default; present means whatever cint makes of it."""
    if key not in opts:
        return default
    raw = opts[key]
    if isinstance(raw, str) and raw.strip().lower() in ("false", "no", ""):
        return False
    return bool(cint(raw)) if not isinstance(raw, bool) else raw


def _require_vault_role() -> None:
    if not (_VAULT_ROLES & set(frappe.get_roles(frappe.session.user))):
        frappe.throw(
            _("You do not have access to the password vault."),
            frappe.PermissionError,
        )
