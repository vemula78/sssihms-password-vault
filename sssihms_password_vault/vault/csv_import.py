"""Generic CSV import — a port of ``importCsv.ts`` (see
``reference/from-personal-password-manager/importCsv.ts``), DESIGN.md §7.

``parse_csv_rows`` is pure (stdlib ``csv`` module only — no hand-rolled RFC-4180 state
machine is needed in Python the way the TS original needed one) and carries no Frappe
import, so it runs under plain ``python -m unittest`` / ``pytest`` with no bench.

The whitelisted RPC, ``import_credentials_csv``, is the only part of this module that
touches Frappe. The ``frappe`` import for it is wrapped in a ``try/except`` at module
scope (rather than sitting bare at the top of the file) for exactly the same reason
``health.py`` defers its Frappe import into a function body: importing *this* module must
not require Frappe to be installed, so ``test_csv_import.py`` can import ``parse_csv_rows``
with no site. Once Frappe is on the path (i.e. under bench) the RPC is defined normally.
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field

#: Same alias table as importCsv.ts's HEADER_ALIASES, verbatim.
HEADER_ALIASES: dict[str, str] = {
    "title": "title", "name": "title",
    "url": "url", "website": "url", "login uri": "url", "uri": "url",
    "username": "username", "user name": "username", "login": "username", "email": "username",
    "password": "password",
    "notes": "notes", "note": "notes",
    "otpauth": "otpauth", "otp auth": "otpauth", "totp": "otpauth", "otp secret": "otpauth",
}

MAX_IMPORT_ROWS = 5000


@dataclass
class ParsedRow:
    """One accepted data row, plus its 1-based row number in the source file (data rows
    only — the header is not counted, matching the file the user is looking at)."""

    row: int
    title: str
    username: str = ""
    password: str = ""
    url: str = ""
    notes: str = ""
    otpauth: str = ""


@dataclass
class ParseResult:
    rows: list[ParsedRow] = field(default_factory=list)
    #: [{"row": i, "reason": r}, ...] for every dropped row.
    skipped: list[dict] = field(default_factory=list)
    total_rows: int = 0
    truncated: bool = False


def parse_csv_rows(csv_text: str) -> ParseResult:
    """RFC-4180 parsing (quoted fields, embedded commas/newlines, ``""`` escapes) via the
    stdlib ``csv`` module. Header row is lower-cased/trimmed and mapped through
    ``HEADER_ALIASES``; the first header cell that maps to a given column wins, same as
    importCsv.ts's ``header.forEach`` / ``colFor[mapped] === undefined`` rule.

    Row handling mirrors ``parseCsvToLoginItems``:

    - rows beyond ``MAX_IMPORT_ROWS`` are not processed at all (``truncated=True``, and
      they do not appear in ``skipped`` either — the TS original slices before looping);
    - an all-blank row is skipped with reason ``"blank row"``;
    - a row with no title, username, password, or url at all is skipped with reason
      ``"no usable columns"``;
    - the accepted row's title falls back through ``title or url or username or
      "Imported login"``.
    """
    all_rows = list(csv.reader(io.StringIO(csv_text)))
    if not all_rows:
        return ParseResult()

    header = [h.strip().lower() for h in all_rows[0]]
    col_for: dict[str, int] = {}
    for i, h in enumerate(header):
        mapped = HEADER_ALIASES.get(h)
        if mapped and mapped not in col_for:
            col_for[mapped] = i

    data_rows = all_rows[1:]
    total_rows = len(data_rows)
    truncated = total_rows > MAX_IMPORT_ROWS
    limited = data_rows[:MAX_IMPORT_ROWS]

    def get(r: list[str], key: str) -> str:
        idx = col_for.get(key)
        if idx is None or idx >= len(r):
            return ""
        return (r[idx] or "").strip()

    rows: list[ParsedRow] = []
    skipped: list[dict] = []
    for row_num, r in enumerate(limited, start=1):
        if all((cell or "").strip() == "" for cell in r):
            skipped.append({"row": row_num, "reason": "blank row"})
            continue

        title = get(r, "title")
        username = get(r, "username")
        password = get(r, "password")
        url = get(r, "url")
        notes = get(r, "notes")
        otpauth = get(r, "otpauth")

        if not title and not username and not password and not url:
            skipped.append({"row": row_num, "reason": "no usable columns"})
            continue

        rows.append(
            ParsedRow(
                row=row_num,
                title=title or url or username or "Imported login",
                username=username,
                password=password,
                url=url,
                notes=notes,
                otpauth=otpauth,
            )
        )

    return ParseResult(rows=rows, skipped=skipped, total_rows=total_rows, truncated=truncated)


try:
    import frappe
    from frappe import _
    from frappe.rate_limiter import rate_limit
except ImportError:  # pragma: no cover - only true under plain pytest with no bench
    frappe = None  # type: ignore[assignment]


if frappe is not None:

    @frappe.whitelist(methods=["POST"])
    @rate_limit(limit=5, seconds=3600)
    def import_credentials_csv(vault_space: str, csv_text: str) -> dict:
        """Whitelisted RPC (DESIGN.md §3/§7). Permission checked before any parsing: the
        caller must be Editor+ in ``vault_space`` (or Vault Admin), and the space must
        exist and not be disabled.

        ``csv_text`` arrives as a string — the client reads the file with FileReader and
        posts text, so the file itself never lands in Frappe's File doctype and no
        secret-bearing CSV sits in ``/private/files``.
        """
        # Imported here rather than at module scope: these are Package A's pinned
        # interfaces (DESIGN.md §10), and importing them lazily keeps this RPC function
        # (unlike parse_csv_rows above) free to be defined only once Frappe — and
        # Package A's modules — are actually on the path.
        from sssihms_password_vault.vault.audit import write_access_log
        from sssihms_password_vault.vault.permissions import get_membership_level, is_vault_admin

        user = frappe.session.user
        if not frappe.db.exists("Vault Space", vault_space):
            frappe.throw(_("Vault Space not found."))
        if frappe.db.get_value("Vault Space", vault_space, "disabled"):
            frappe.throw(_("This space is disabled."), frappe.PermissionError)

        level = get_membership_level(user, vault_space)
        if not is_vault_admin(user) and level not in ("Editor", "Manager"):
            frappe.throw(
                _("You need Editor access to this space to import credentials."),
                frappe.PermissionError,
            )

        result = parse_csv_rows(csv_text)

        created = 0
        skipped = list(result.skipped)
        for row in result.rows:
            try:
                doc = frappe.get_doc(
                    {
                        "doctype": "Vault Credential",
                        "vault_space": vault_space,
                        "credential_type": "login",
                        "title": row.title,
                        "username": row.username,
                        "url": row.url,
                        "notes": row.notes,
                        "password": row.password,
                    }
                )
                if row.otpauth:
                    doc.append(
                        "secret_fields",
                        {
                            "field_key": "otpauth",
                            "label": "2FA / TOTP (otpauth URI)",
                            "field_kind": "text",
                            "is_secret": 1,
                            "secret_value": row.otpauth,
                        },
                    )
                # A normal permission-checked insert — no ignore_permissions. Each row's
                # after_insert writes its own create-row to the access log; the import as
                # a whole gets one additional summary row below.
                doc.insert()
                created += 1
            except Exception as e:
                # Exception text is deliberately excluded — it could echo a field value
                # (e.g. a uniqueness error quoting the title). Only the exception class
                # name is recorded.
                skipped.append({"row": row.row, "reason": f"insert failed: {e.__class__.__name__}"})

        write_access_log(
            None,
            vault_space=vault_space,
            action="import",
            detail=f"created={created} skipped={len(skipped)} truncated={result.truncated}",
        )

        return {
            "created": created,
            "skipped": skipped,
            "total_rows": result.total_rows,
            "truncated": result.truncated,
        }
