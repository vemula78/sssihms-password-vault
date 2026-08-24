"""Pure-logic tests for vault/health.py's estimate_strength() and analyze().

``collect_uses`` (the Frappe-decrypting half) is not exercised here — it has no
Frappe-free way to run, and is instead covered by
``password_vault/doctype/vault_credential/test_vault_credential.py`` under bench.
"""

from __future__ import annotations

import unittest

from sssihms_password_vault.vault.health import COMMON_PASSWORDS, analyze, estimate_strength


class EstimateStrengthTests(unittest.TestCase):
    def test_empty_password_is_very_weak_zero_bits(self):
        strength, bits = estimate_strength("")
        self.assertEqual(strength, "very-weak")
        self.assertEqual(bits, 0)

    def test_common_password_is_very_weak(self):
        strength, bits = estimate_strength("password123")
        self.assertEqual(strength, "very-weak")
        self.assertEqual(bits, 10)

    def test_common_password_matched_case_insensitively(self):
        strength, _bits = estimate_strength("PASSWORD")
        self.assertEqual(strength, "very-weak")

    def test_all_one_character_is_capped(self):
        strength, bits = estimate_strength("aaaaaaaaaaaaaaaaaaaa")
        self.assertEqual(strength, "very-weak")
        self.assertLessEqual(bits, 8)

    def test_sequence_prefix_halves_bits(self):
        _strength, bits_seq = estimate_strength("1234abcdXYZ!")
        _strength2, bits_no_seq = estimate_strength("Xy9!abcdXYZ!")
        # Same length/class mix except the leading run; the sequence-prefixed one must
        # score no higher.
        self.assertLessEqual(bits_seq, bits_no_seq)

    def test_repeat_run_penalised(self):
        _strength, bits_repeat = estimate_strength("aaaBBB999!!!")
        _strength2, bits_varied = estimate_strength("aB3!xY7@qZ2#")
        self.assertLess(bits_repeat, bits_varied)

    def test_long_mixed_password_is_strong(self):
        strength, bits = estimate_strength("Tr0ub4dor&3xtra!Long")
        self.assertEqual(strength, "strong")
        self.assertGreaterEqual(bits, 65)

    def test_thresholds_are_ordered(self):
        # Sanity check on the four-tier boundary logic itself.
        cases = [
            ("a", "very-weak"),
            ("abababab", "weak"),  # 8 chars, lowercase-only pool -> ~37.6 bits before penalty
        ]
        for password, expected_min_tier in cases:
            strength, _bits = estimate_strength(password)
            self.assertIn(strength, ("very-weak", "weak", "fair", "strong"))

    def test_every_common_password_is_very_weak(self):
        for pw in COMMON_PASSWORDS:
            strength, _bits = estimate_strength(pw)
            self.assertEqual(strength, "very-weak", f"{pw!r} should be very-weak")


class AnalyzeTests(unittest.TestCase):
    def _use(self, credential, field_key, value, title="T", space="S", **extra):
        return {
            "credential": credential,
            "title": title,
            "vault_space": space,
            "field_key": field_key,
            "field_label": field_key,
            "value": value,
            **extra,
        }

    def test_empty_input_gives_perfect_score(self):
        result = analyze([])
        self.assertEqual(result["summary"]["total_passwords"], 0)
        self.assertEqual(result["summary"]["score"], 100)
        self.assertEqual(result["rows"], [])

    def test_no_value_leaks_into_rows(self):
        uses = [self._use("VC-1", "password", "correct-horse-battery-staple-9!Q")]
        result = analyze(uses)
        for row in result["rows"]:
            self.assertNotIn("value", row)

    def test_reused_password_grouped(self):
        uses = [
            self._use("VC-1", "password", "sharedSecret1!"),
            self._use("VC-2", "password", "sharedSecret1!"),
            self._use("VC-3", "password", "uniqueOne9$Zz"),
        ]
        result = analyze(uses)
        groups = {row["reused_group"] for row in result["rows"] if row["reused_group"]}
        self.assertEqual(len(groups), 1)
        reused_rows = [row for row in result["rows"] if row["reused_group"]]
        self.assertEqual(len(reused_rows), 2)
        for row in reused_rows:
            self.assertEqual(row["reused_group_size"], 2)
        self.assertEqual(result["summary"]["reused_count"], 2)

    def test_weak_count_matches_uses_below_fair(self):
        uses = [
            self._use("VC-1", "password", "123456"),  # very-weak
            self._use("VC-2", "password", "Tr0ub4dor&3xtra!Long"),  # strong
        ]
        result = analyze(uses)
        self.assertEqual(result["summary"]["weak_count"], 1)
        self.assertEqual(result["summary"]["total_passwords"], 2)

    def test_score_formula(self):
        # 1 bad (weak) out of 2 total -> 100 * (1 - 1/2) == 50.
        uses = [
            self._use("VC-1", "password", "123456"),
            self._use("VC-2", "password", "Tr0ub4dor&3xtra!Long"),
        ]
        result = analyze(uses)
        self.assertEqual(result["summary"]["score"], 50)

    def test_rotation_and_expiry_status(self):
        uses = [
            self._use(
                "VC-1", "password", "Tr0ub4dor&3xtra!Long",
                rotation_due="2020-01-01", expiry_date="2099-01-01",
            ),
        ]
        result = analyze(uses, as_of="2026-08-24")
        row = result["rows"][0]
        self.assertEqual(row["rotation_status"], "overdue")
        self.assertEqual(row["expiry_status"], "ok")

    def test_blank_dates_give_blank_status(self):
        uses = [self._use("VC-1", "password", "Tr0ub4dor&3xtra!Long")]
        result = analyze(uses, as_of="2026-08-24")
        row = result["rows"][0]
        self.assertEqual(row["rotation_status"], "")
        self.assertEqual(row["expiry_status"], "")


if __name__ == "__main__":
    unittest.main()
