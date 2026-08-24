"""Password health: weak / reused detection and scoring — a port of ``health.ts`` (see
``reference/from-personal-password-manager/health.ts``), DESIGN.md §6.

Split in two halves on purpose:

- ``estimate_strength`` and ``analyze`` are pure — no Frappe import anywhere near them —
  so they run under plain ``python -m unittest`` / ``pytest`` with no bench, no site.
- ``collect_uses`` is the only function here that touches Frappe (it decrypts secrets off
  live ``Vault Credential`` documents), and it imports ``frappe`` inside its own body for
  exactly that reason: importing this module must not require frappe to be installed.

Nothing in ``analyze``'s return value carries a secret value or a hash of one — hashes are
computed and discarded inside ``analyze``'s local scope, used only to group reused
passwords into ``R1``, ``R2``, … ids. This is the "no secret values, no hashes, to the
client" requirement in DESIGN.md §6 point 5.
"""

from __future__ import annotations

import hashlib
import math
import re
from datetime import date, timedelta

#: Same 28 entries as health.ts's COMMON_PASSWORDS, verbatim.
COMMON_PASSWORDS: frozenset[str] = frozenset(
    {
        "password", "password1", "password123", "123456", "12345678", "123456789",
        "1234567890", "qwerty", "qwerty123", "abc123", "111111", "letmein", "welcome",
        "admin", "iloveyou", "india123", "india@123", "pass@123", "password@123",
        "welcome@123", "admin@123", "abcd1234", "p@ssw0rd", "monkey", "dragon",
        "sunshine", "666666", "654321",
    }
)

_LOWER = re.compile(r"[a-z]")
_UPPER = re.compile(r"[A-Z]")
_DIGIT = re.compile(r"[0-9]")
_SYMBOL = re.compile(r"[^a-zA-Z0-9]")
_ALL_ONE_CHAR = re.compile(r"^(.)\1+$")
_SEQUENCE_PREFIX = re.compile(r"^(0123|1234|2345|3456|4567|5678|6789|abcd|qwer)", re.IGNORECASE)
_REPEAT_RUN = re.compile(r"(.)\1{2,}")

#: A rotation/expiry date within this many days of "as of" is reported "due soon" rather
#: than "ok". Not pinned by DESIGN.md §6 (which names the three-state column but not a
#: threshold) — chosen to match the dashboard-style horizon used elsewhere in this app's
#: sibling reports. Not a cross-package contract; safe to retune here alone.
DUE_SOON_DAYS = 30

Strength = str  # "very-weak" | "weak" | "fair" | "strong"


def estimate_strength(password: str) -> tuple[Strength, int]:
    """Rough entropy estimate from character-class pool size, with the same repeat/sequence
    penalties as health.ts's ``estimateStrength``. Returns ``(strength, bits)``."""
    if not password:
        return "very-weak", 0
    if password.lower() in COMMON_PASSWORDS:
        return "very-weak", 10

    pool = 0
    if _LOWER.search(password):
        pool += 26
    if _UPPER.search(password):
        pool += 26
    if _DIGIT.search(password):
        pool += 10
    if _SYMBOL.search(password):
        pool += 33
    bits = len(password) * math.log2(pool or 1)

    if _ALL_ONE_CHAR.match(password):
        bits = min(bits, 8)  # all one character
    if _SEQUENCE_PREFIX.match(password):
        bits *= 0.5
    if _REPEAT_RUN.search(password):
        bits *= 0.8  # runs of 3+ repeats

    if bits < 28:
        strength: Strength = "very-weak"
    elif bits < 45:
        strength = "weak"
    elif bits < 65:
        strength = "fair"
    else:
        strength = "strong"
    return strength, round(bits)


def _date_status(value, as_of: date) -> str:
    """"" / "overdue" / "due soon" / "ok" for a rotation_due or expiry_date value that may
    be None, a date, or an ISO date string (Frappe returns Date fields as strings from
    ``frappe.get_doc`` in some contexts, as ``datetime.date`` in others)."""
    if not value:
        return ""
    d = value if isinstance(value, date) else date.fromisoformat(str(value))
    if d < as_of:
        return "overdue"
    if d <= as_of + timedelta(days=DUE_SOON_DAYS):
        return "due soon"
    return "ok"


def analyze(uses: list[dict], as_of: str | None = None) -> dict:
    """Pure. Score, weak-flag and group-by-reuse a list of password uses.

    Each item in ``uses`` is a dict with keys ``credential``, ``title``, ``vault_space``,
    ``field_key``, ``field_label``, ``value``, and optionally ``rotation_due`` /
    ``expiry_date`` (ISO date strings or ``datetime.date``, or ``None``).

    Returns ``{"rows": [...], "summary": {...}}``. Rows never carry ``value`` — only the
    verdict, bit estimate, and reuse-group id/size derived from it. ``as_of`` is an ISO
    date string; defaults to today when omitted (kept a parameter, not a hidden
    ``date.today()`` call, so this stays deterministic and testable).
    """
    as_of_date = date.fromisoformat(as_of) if as_of else date.today()

    scored = []
    for use in uses:
        strength, bits = estimate_strength(use["value"])
        scored.append({**use, "strength": strength, "bits": bits})

    weak_keys = {
        (u["credential"], u["field_key"])
        for u in scored
        if u["strength"] in ("very-weak", "weak")
    }

    # Grouping by value happens only in this function-local dict, which is discarded when
    # analyze() returns — no hash or value survives into the return value.
    by_hash: dict[str, list[dict]] = {}
    for u in scored:
        digest = hashlib.sha256(u["value"].encode("utf-8")).hexdigest()
        by_hash.setdefault(digest, []).append(u)
    reused_groups = [group for group in by_hash.values() if len(group) > 1]

    reused_group_of: dict[tuple[str, str], tuple[str, int]] = {}
    for idx, group in enumerate(reused_groups, start=1):
        gid = f"R{idx}"
        for u in group:
            reused_group_of[(u["credential"], u["field_key"])] = (gid, len(group))

    total = len(scored)
    bad = weak_keys | set(reused_group_of.keys())
    score = round(100 * (1 - len(bad) / total)) if total else 100

    rows = []
    for u in scored:
        key = (u["credential"], u["field_key"])
        gid, gsize = reused_group_of.get(key, ("", 0))
        rows.append(
            {
                "credential": u["credential"],
                "title": u["title"],
                "vault_space": u["vault_space"],
                "field_key": u["field_key"],
                "field_label": u["field_label"],
                "verdict": u["strength"],
                "bits": u["bits"],
                "reused_group": gid,
                "reused_group_size": gsize,
                "rotation_status": _date_status(u.get("rotation_due"), as_of_date),
                "expiry_status": _date_status(u.get("expiry_date"), as_of_date),
            }
        )

    summary = {
        "total_passwords": total,
        "weak_count": len(weak_keys),
        # Matches health.ts's reusedCount: the count of *uses* inside reused groups, not
        # the number of groups.
        "reused_count": sum(len(group) for group in reused_groups),
        "score": score,
    }
    return {"rows": rows, "summary": summary}


def collect_uses(credential_names: list[str]) -> list[dict]:
    """Frappe-dependent. Decrypts the primary ``password`` column and every
    ``is_password=1`` child row (``secret_fields``) for each named ``Vault Credential``,
    and returns them in the shape ``analyze`` expects.

    Imports ``frappe`` inside the function body, not at module scope, so this module stays
    importable under plain pytest with no site — see the module docstring.
    """
    import frappe
    from frappe.utils.password import get_decrypted_password

    uses: list[dict] = []
    for name in credential_names:
        doc = frappe.get_doc("Vault Credential", name)

        if doc.password:
            value = get_decrypted_password(
                "Vault Credential", doc.name, "password", raise_exception=False
            )
            if value:
                uses.append(
                    {
                        "credential": doc.name,
                        "title": doc.title,
                        "vault_space": doc.vault_space,
                        "field_key": "password",
                        "field_label": "Password",
                        "value": value,
                        "rotation_due": doc.rotation_due,
                        "expiry_date": doc.expiry_date,
                    }
                )

        for row in doc.secret_fields:
            if not row.is_password:
                continue
            if row.is_secret:
                value = get_decrypted_password(
                    "Credential Secret Field", row.name, "secret_value", raise_exception=False
                )
            else:
                value = row.value
            if not value:
                continue
            uses.append(
                {
                    "credential": doc.name,
                    "title": doc.title,
                    "vault_space": doc.vault_space,
                    "field_key": row.field_key,
                    "field_label": row.label,
                    "value": value,
                    "rotation_due": doc.rotation_due,
                    "expiry_date": doc.expiry_date,
                }
            )
    return uses


def run_health_check(credential_names: list[str], as_of: str | None = None) -> dict:
    """``collect_uses`` + ``analyze`` in one call — what the Script Report wrapper calls."""
    return analyze(collect_uses(credential_names), as_of=as_of)
