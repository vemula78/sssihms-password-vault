"""The one code path that writes Credential Access Log rows.

No role has ``create`` on Credential Access Log — that is deliberate, and it is what makes
this module the sole writer. ``write_access_log`` inserts with ``ignore_permissions=True``
for exactly that reason: not to bypass a check, but because the check exists to stop
*everything else*.

Callers must never put a secret value, a decrypted password, or an exception's message text
into ``detail``. ``detail`` is a plaintext column; it takes counts, denial reasons and
field labels, nothing else. The log stores field *keys and labels*, never values.
"""

from __future__ import annotations

import frappe
from frappe.utils import now

#: The Select options on ``Credential Access Log.action``. Validated here so a typo in a
#: caller surfaces as a clean error rather than as a row Frappe silently rejects at the
#: database layer, or worse, a filter in the access report that quietly matches nothing.
ACTIONS: tuple[str, ...] = (
    "reveal",
    "copy",
    "create",
    "update",
    "delete",
    "import",
    "membership",
    "health_report",
)

OUTCOMES: tuple[str, ...] = ("success", "denied")

#: ``credential_title`` is mandatory on the doctype (a log row with no subject is
#: unreadable in a list view), so space-level events — membership changes, CSV imports,
#: health runs — carry this fixed marker instead of a title.
SPACE_LEVEL_TITLE = "(space-level event)"

#: ``detail`` is Small Text; clamp rather than let a caller's long string fail the insert
#: and take the audit row down with it. An unwritten log row is the one outcome this
#: module must never produce.
_MAX_DETAIL = 500


def write_access_log(
    credential_doc=None,
    *,
    action: str,
    outcome: str = "success",
    field_key: str | None = None,
    field_label: str | None = None,
    detail: str | None = None,
    vault_space: str | None = None,
):
    """Append one row to the access log and return it.

    ``credential_doc`` is a Vault Credential document (or anything with ``name``,
    ``title`` and ``vault_space``). Pass None with an explicit ``vault_space`` for
    space-level events.

    The credential's name and title are *snapshotted* into the row: ``credential`` is a
    Link but the log outlives the credential (``ignore_links_on_delete`` in hooks.py), so
    after a delete the Link dangles and ``credential_title`` is the only remaining record
    of what was accessed.
    """
    if action not in ACTIONS:
        frappe.throw(f"Unknown access-log action: {action}")
    if outcome not in OUTCOMES:
        frappe.throw(f"Unknown access-log outcome: {outcome}")

    space = vault_space or (credential_doc.get("vault_space") if credential_doc else None)
    if not space:
        frappe.throw("An access-log row needs a vault space.")
    if not frappe.db.exists("Vault Space", space):
        # `vault_space` is a mandatory Link, so a name that is not a real space fails the
        # insert — and an audit row that fails to insert takes its caller down with it.
        # Say which caller and which value rather than leaving a bare LinkValidationError:
        # a placeholder marker string ("(all spaces)" and friends) is the likely cause, and
        # an org-wide event has to be logged per-space or not at all.
        frappe.throw(
            f"Cannot log a '{action}' event against '{space}': that is not a Vault Space. "
            "An org-wide event must be logged once per space it actually covered."
        )

    row = frappe.get_doc(
        {
            "doctype": "Credential Access Log",
            "credential": credential_doc.name if credential_doc else None,
            "credential_title": (
                credential_doc.get("title") if credential_doc else None
            ) or SPACE_LEVEL_TITLE,
            "vault_space": space,
            "action": action,
            "outcome": outcome,
            "field_key": field_key,
            "field_label": field_label,
            "user": frappe.session.user,
            "timestamp": now(),
            # Recorded for the "who and from where" half of an audit trail. Absent for
            # scheduler and console callers, which have no HTTP request.
            "ip_address": getattr(frappe.local, "request_ip", None),
            "detail": (detail or "")[:_MAX_DETAIL] or None,
        }
    )
    # Deliberate: no role has `create` on this doctype precisely so that nothing but this
    # function can write it. See the module docstring.
    row.insert(ignore_permissions=True)
    return row
