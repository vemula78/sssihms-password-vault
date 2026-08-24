"""ACTIONS in vault/audit.py must match the Select options on Credential Access Log.

A pure test on purpose. `audit.py` imports frappe at module scope, so the tuple is read
from source rather than imported — which is also what keeps this runnable without a bench,
where it will actually be run before a deploy.

Written after a live failure: two new actions were added to the Python tuple and not to the
doctype JSON. `write_access_log` validated them happily, and the row then died in Frappe's
Select validation at insert — inside a controller `validate()`, which turned a logged
security event into a hard error on saving a Vault Space. The tuple's own docstring says it
mirrors the Select options; nothing enforced it.
"""

from __future__ import annotations

import json
import pathlib
import re
import unittest

_HERE = pathlib.Path(__file__).resolve()
_APP = _HERE.parents[2]  # sssihms_password_vault/
_AUDIT = _APP / "vault" / "audit.py"
_LOG_JSON = (
    _APP / "password_vault" / "doctype" / "credential_access_log" / "credential_access_log.json"
)


def _select_options(fieldname: str) -> list[str]:
    doc = json.loads(_LOG_JSON.read_text())
    field = next(f for f in doc["fields"] if f["fieldname"] == fieldname)
    return field["options"].split("\n")


def _source_tuple(name: str) -> list[str]:
    """The string literals of a module-level tuple, read from source.

    Scans line by line from the assignment to its closing paren rather than using one
    DOTALL regex: a non-greedy `(.*?)\n\)` sails straight past a single-line tuple and
    swallows the next parenthesised block it finds — which is how the first version of
    this test reported `OUTCOMES` as containing "success" twice, having picked up
    `outcome: str = "success"` from a function signature further down the file.
    """
    lines = _AUDIT.read_text().splitlines()
    start = next(
        (i for i, line in enumerate(lines) if line.startswith(f"{name}: tuple[str, ...] = (")),
        None,
    )
    assert start is not None, f"could not find {name} in {_AUDIT}"

    first = lines[start]
    if first.rstrip().endswith(")"):  # single-line tuple
        return re.findall(r'"([a-z_]+)"', first.split("=", 1)[1])

    body: list[str] = []
    for line in lines[start + 1 :]:
        if line.startswith(")"):
            break
        body.append(line)
    else:  # pragma: no cover
        raise AssertionError(f"unterminated {name} tuple in {_AUDIT}")
    return re.findall(r'"([a-z_]+)"', "\n".join(body))


class AuditActionParityTests(unittest.TestCase):
    def test_actions_match_the_doctype_select(self):
        self.assertEqual(
            _source_tuple("ACTIONS"),
            _select_options("action"),
            "vault/audit.py ACTIONS and Credential Access Log's `action` Select have "
            "diverged — a row using the missing value will fail at insert, inside a "
            "controller validate(), and take its caller down with it.",
        )

    def test_outcomes_match_the_doctype_select(self):
        self.assertEqual(_source_tuple("OUTCOMES"), _select_options("outcome"))


if __name__ == "__main__":
    unittest.main()
