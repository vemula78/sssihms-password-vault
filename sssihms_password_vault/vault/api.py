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

import re

import frappe
from frappe import _
from frappe.rate_limiter import rate_limit
from frappe.utils import add_to_date, cint, now_datetime
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

#: Per-user reveal budget, enforced in addition to the IP-based decorator. See
#: ``_enforce_reveal_budget`` for why the decorator alone is not a limit.
_REVEAL_LIMIT = 30
_REVEAL_WINDOW_SECONDS = 300

#: A field key is a template identifier, never free text: template keys are code
#: constants in ``vault/templates.py`` and custom rows are named by an editor from the
#: form. Validated at the door so attacker-authored markup cannot reach a log row and,
#: from there, be rendered into a Vault Admin's or Vault Auditor's report (audit finding
#: H1). The permanence of the log is what makes this a door-level check and not a
#: rendering-level one: an escaped payload is still a payload sitting in the table.
_FIELD_KEY_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,60}$")


# --------------------------------------------------------------------------- reveal


@frappe.whitelist(methods=["POST"])
@rate_limit(limit=30, seconds=300)
def reveal_secret(credential: str, field_key: str, action: str = "reveal") -> dict:
    """Decrypt and return one secret field of one credential.

    The order of operations below is load-bearing (BRIEF security requirement 2):
    vault role, then existence, then the per-user budget, then input validation, then
    membership — all before any log row — and then the access-log row is written **and
    committed** before anything is decrypted. A denial is logged before the throw.

    ``action`` is ``"reveal"`` or ``"copy"``. Both are the same operation from the server's
    point of view — the client does the clipboard write itself — but the log distinguishes
    them, because "copied to clipboard" and "displayed on screen" are different events to
    an auditor.
    """
    # A vault role is required before anything else happens, including before the
    # credential is resolved. Without this gate any authenticated ERPNext account could
    # walk the sequential VC-##### namespace and commit one attacker-authored row per
    # probe into an append-only table — an existence oracle and a log-flooding primitive
    # in one (audit finding H3). get_templates and generate_credential_secret always had
    # this check; the reveal door did not.
    _require_vault_role()
    user = frappe.session.user

    # A nonexistent credential answers exactly like an inaccessible one, so the two cannot
    # be told apart from outside. Nothing is logged on this path: there is no space to log
    # the row against, and a name that resolves to nothing is not an access attempt on
    # anything. (This is the same principle as the recovery-verifier rule in the sibling
    # personal vault: a missing thing must answer like a wrong thing, never like an open
    # door.)
    if not frappe.db.exists("Vault Credential", credential):
        frappe.throw(
            _("You do not have permission to reveal this secret."),
            frappe.PermissionError,
        )

    _enforce_reveal_budget(user)

    # frappe.get_doc does not itself check read permission (that is frappe.client.get's
    # job), which is what lets the denial path below resolve a field label and log a
    # meaningful row before refusing.
    doc = frappe.get_doc("Vault Credential", credential)

    level = get_membership_level(user, doc.vault_space)

    # `action` is coerced to a known-safe literal unconditionally, before any branch can
    # return: write_access_log validates against ACTIONS and would otherwise throw on the
    # malformed-key path and lose the audit row entirely.
    invalid_action = action not in ("reveal", "copy")
    original_action = str(action)[:40]
    if invalid_action:
        action = "reveal"

    malformed_key = not isinstance(field_key, str) or not _FIELD_KEY_RE.match(field_key or "")
    logged_field_key = "(malformed)" if malformed_key else field_key

    denied_reason = None
    if invalid_action:
        # A malformed action is itself an attempted-abuse signal, so it is logged like any
        # other denial rather than thrown unrecorded (Codex finding #4). Checked first so a
        # bad action can never be mistaken for a granted reveal.
        denied_reason = f"invalid action: {original_action!r}"
    elif malformed_key:
        denied_reason = "malformed field key"
    elif is_vault_auditor_only(user):
        # Defence in depth: an auditor who has somehow been added to a space still cannot
        # reveal. Checked before membership so auditor-ness can never be offset by it.
        denied_reason = "auditor role cannot reveal secrets"
    elif level is None and not is_vault_admin(user):
        denied_reason = "not a member of this space"
    elif space_is_disabled(doc.vault_space):
        denied_reason = "space is disabled"

    row = None if malformed_key else _find_secret_row(doc, field_key)
    field_label = "(malformed)" if malformed_key else _resolve_field_label(doc, field_key, row)

    if denied_reason is None and field_key != "password" and row is None:
        # An unknown field key is resolved to a denial *before* the success row is written.
        # It used to be discovered after the log row and the commit, which put an
        # `outcome="success"` row in a permanent, uneditable table for a reveal that
        # returned nothing and never could (audit finding M5). Ordered after the
        # membership checks so that telling a caller which field keys exist stays a
        # disclosure only members can obtain.
        denied_reason = "unknown field"

    if denied_reason:
        # Log the denial BEFORE throwing — a failed grab attempt is the most interesting
        # row in the whole log, and frappe.throw rolls the transaction back, so the commit
        # has to happen here rather than at request end.
        write_access_log(
            doc,
            action=action,
            outcome="denied",
            field_key=logged_field_key,
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
        field_key=logged_field_key,
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
        # `row` cannot be None here: an unknown field key became a logged denial above.
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


def _enforce_reveal_budget(user: str) -> None:
    """Per-user reveal budget, enforced on top of the IP-based ``@rate_limit`` decorator.

    The decorator alone is not a limit (audit findings H2 and M3):

    * its bucket identity is ``frappe.local.request_ip``, which Frappe takes from the first
      element of the caller's own ``X-Forwarded-For`` header with no trusted-proxy check —
      so varying one header yields an unlimited supply of fresh buckets;
    * its cache key embeds ``frappe.form_dict.cmd``, which the ``/api/v2`` route never
      sets, so v2 gets a second bucket that also collides with every other
      ``@rate_limit(seconds=300)`` endpoint on the site.

    Keying on the authenticated user fixes both, because neither the header nor the route
    changes who is asking.

    Counted from the access log rather than a cache counter, deliberately: the log is
    already the truthful record of every reveal attempt (successes and denials alike), it
    survives a cache flush, and the caller cannot reset it. The IP decorator stays as a
    cheap outer guard for unauthenticated flooding.

    Nothing is logged when the budget is exhausted. The rows already counted *are* the
    record, and writing one here would let a caller keep appending to an uneditable table
    at request rate — the exact abuse the budget exists to bound.
    """
    window_start = add_to_date(now_datetime(), seconds=-_REVEAL_WINDOW_SECONDS)
    recent = frappe.db.count(
        "Credential Access Log",
        filters=[
            ["user", "=", user],
            ["action", "in", ["reveal", "copy"]],
            ["timestamp", ">=", window_start],
        ],
    )
    if recent >= _REVEAL_LIMIT:
        frappe.throw(
            _("Too many reveal attempts. Wait a few minutes and try again."),
            frappe.RateLimitExceededError,
        )


def _is_vault_doctype(doctype: str) -> bool:
    """True for any doctype belonging to this app.

    Tested by module rather than against a hardcoded name set (audit finding L14): a
    Password field added to a future vault doctype is then covered the day it is created,
    and no dead entry can accumulate. The explicit floor stays for the two doctypes that
    actually hold secrets today, so a meta lookup that fails on a broken site cannot open
    the door.
    """
    if doctype in ("Vault Credential", "Credential Secret Field"):
        return True
    try:
        return frappe.get_meta(doctype).module == "Password Vault"
    except Exception:
        return False


@frappe.whitelist()
def get_password_override(doctype: str, name: str, fieldname: str):
    """Override for the framework's ``frappe.client.get_password`` (wired in hooks.py).

    The stock route decrypts any Password field for a System Manager and returns it with no
    access-log row — bypassing the whole reveal audit and rate limit (Codex finding #1). For
    Vault doctypes we refuse it outright and redirect the caller to the audited endpoint,
    logging the attempt against the credential so an out-of-band grab is on record. Every
    other doctype falls through to the framework's own implementation unchanged, so this
    override does not weaken password retrieval anywhere else in ERPNext.

    The ``@frappe.whitelist()`` decorator is required, not incidental: the override is
    resolved by dotted path and then passed through ``is_whitelisted``, so without it the
    hook cannot fire at all. It does mean this dotted path is itself a live endpoint whose
    non-vault branch is another way to reach stock ``get_password`` — same System-Manager
    gate, same return value, no escalation, and no vault secret reachable through it.
    """
    if _is_vault_doctype(doctype):
        # Audit the attempt. A Credential Secret Field name is a child row, so resolve its
        # parent credential and log against that — that path is the *more* targeted bypass,
        # because every non-login template keeps its secrets in child rows, and it used to
        # be refused with nothing on record despite the comment here claiming otherwise
        # (audit finding M8). A failure to resolve must never swallow the refusal.
        try:
            credential_name = None
            if doctype == "Vault Credential":
                credential_name = name if frappe.db.exists("Vault Credential", name) else None
            elif doctype == "Credential Secret Field":
                credential_name = frappe.db.get_value(
                    "Credential Secret Field", name, "parent"
                )
                if credential_name and not frappe.db.exists(
                    "Vault Credential", credential_name
                ):
                    credential_name = None
            if credential_name:
                write_access_log(
                    frappe.get_doc("Vault Credential", credential_name),
                    action="reveal",
                    outcome="denied",
                    field_key=str(fieldname)[:60],
                    detail=f"blocked frappe.client.get_password bypass on {doctype}",
                )
                frappe.db.commit()
        except Exception:
            # Never let an audit-write problem convert a refusal into a fall-through.
            frappe.db.rollback()
        frappe.throw(
            _("Use the audited Reveal action on this credential — direct password "
              "retrieval is disabled for the vault."),
            frappe.PermissionError,
        )

    # Non-vault doctype: reproduce the stock behaviour exactly (System-Manager-only).
    frappe.only_for("System Manager")
    return frappe.get_lazy_doc(doctype, name).get_password(fieldname)


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
