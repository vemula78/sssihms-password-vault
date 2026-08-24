"""Pure-parse tests for vault/csv_import.py's parse_csv_rows().

The whitelisted RPC (import_credentials_csv) needs a running site to exercise the insert
path and is not tested here — see password_vault/doctype/vault_credential/
test_vault_credential.py for that. This file only imports parse_csv_rows/ParseResult,
which have no Frappe dependency, so it runs with no bench.
"""

from __future__ import annotations

import unittest

from sssihms_password_vault.vault.csv_import import MAX_IMPORT_ROWS, parse_csv_rows


class ParseCsvRowsTests(unittest.TestCase):
    def test_empty_text(self):
        result = parse_csv_rows("")
        self.assertEqual(result.rows, [])
        self.assertEqual(result.skipped, [])
        self.assertEqual(result.total_rows, 0)
        self.assertFalse(result.truncated)

    def test_basic_chrome_shaped_csv(self):
        csv_text = "name,url,username,password,note\nGmail,https://mail.google.com,me@x.com,s3cr3t,\n"
        result = parse_csv_rows(csv_text)
        self.assertEqual(len(result.rows), 1)
        row = result.rows[0]
        self.assertEqual(row.title, "Gmail")
        self.assertEqual(row.username, "me@x.com")
        self.assertEqual(row.password, "s3cr3t")
        self.assertEqual(row.url, "https://mail.google.com")
        self.assertEqual(row.row, 1)

    def test_header_aliases_case_and_whitespace_insensitive(self):
        csv_text = "Login URI, User Name, Password\nhttps://example.com,bob,pw1\n"
        result = parse_csv_rows(csv_text)
        self.assertEqual(len(result.rows), 1)
        row = result.rows[0]
        self.assertEqual(row.url, "https://example.com")
        self.assertEqual(row.username, "bob")
        self.assertEqual(row.password, "pw1")

    def test_first_matching_header_wins(self):
        # Two headers both map to "username" (username, email) — the first one, at index
        # 0, must win, matching importCsv.ts's `colFor[mapped] === undefined` rule.
        csv_text = "username,email,password\nfirstcol,secondcol,pw\n"
        result = parse_csv_rows(csv_text)
        self.assertEqual(result.rows[0].username, "firstcol")

    def test_blank_row_skipped(self):
        csv_text = "title,username,password,url\n,,,\nSite,bob,pw,https://x.com\n"
        result = parse_csv_rows(csv_text)
        self.assertEqual(len(result.rows), 1)
        self.assertEqual(len(result.skipped), 1)
        self.assertEqual(result.skipped[0], {"row": 1, "reason": "blank row"})
        self.assertEqual(result.rows[0].row, 2)

    def test_row_with_only_notes_has_no_usable_columns(self):
        csv_text = "title,username,password,url,notes\n,,,,just a note\n"
        result = parse_csv_rows(csv_text)
        self.assertEqual(result.rows, [])
        self.assertEqual(result.skipped, [{"row": 1, "reason": "no usable columns"}])

    def test_title_fallback_chain(self):
        csv_text = "title,url,username,password\n,,bob,pw\n"
        result = parse_csv_rows(csv_text)
        # No title, no url -> falls back to username.
        self.assertEqual(result.rows[0].title, "bob")

    def test_title_fallback_to_imported_login(self):
        csv_text = "password\npw-only\n"
        result = parse_csv_rows(csv_text)
        self.assertEqual(result.rows[0].title, "Imported login")

    def test_otpauth_column_captured(self):
        csv_text = "title,username,password,otpauth\nSite,bob,pw,otpauth://totp/Example\n"
        result = parse_csv_rows(csv_text)
        self.assertEqual(result.rows[0].otpauth, "otpauth://totp/Example")

    def test_quoted_field_with_embedded_comma_and_newline(self):
        csv_text = 'title,username,password,notes\n"Bank, Ltd",bob,pw,"line one\nline two"\n'
        result = parse_csv_rows(csv_text)
        self.assertEqual(len(result.rows), 1)
        self.assertEqual(result.rows[0].title, "Bank, Ltd")
        self.assertEqual(result.rows[0].notes, "line one\nline two")

    def test_quoted_double_quote_escape(self):
        csv_text = 'title,notes\n"Say ""hi""",n\n'
        result = parse_csv_rows(csv_text)
        self.assertEqual(result.rows[0].title, 'Say "hi"')

    def test_unmapped_headers_are_ignored(self):
        csv_text = "title,favorite,username,password\nSite,true,bob,pw\n"
        result = parse_csv_rows(csv_text)
        self.assertEqual(result.rows[0].title, "Site")
        self.assertEqual(result.rows[0].username, "bob")

    def test_truncation_beyond_max_rows(self):
        header = "title,username,password\n"
        body = "".join(f"Site{i},user{i},pw{i}\n" for i in range(MAX_IMPORT_ROWS + 10))
        result = parse_csv_rows(header + body)
        self.assertTrue(result.truncated)
        self.assertEqual(result.total_rows, MAX_IMPORT_ROWS + 10)
        self.assertEqual(len(result.rows), MAX_IMPORT_ROWS)

    def test_row_numbers_are_1_based_data_rows_excluding_header(self):
        csv_text = "title,username,password\nA,a,1\nB,b,2\nC,c,3\n"
        result = parse_csv_rows(csv_text)
        self.assertEqual([r.row for r in result.rows], [1, 2, 3])


if __name__ == "__main__":
    unittest.main()
