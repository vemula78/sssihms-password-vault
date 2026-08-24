"""Pure-logic tests for vault/generator.py and vault/wordlist.py.

Runs with no bench, no site: ``python -m unittest`` (or pytest) from the repo root, since
neither module imports Frappe. See DESIGN.md §9.
"""

from __future__ import annotations

import re
import unittest

from sssihms_password_vault.vault.generator import (
    AMBIGUOUS,
    SETS,
    generate_password,
    generate_passphrase,
    generate_pin,
)
from sssihms_password_vault.vault.wordlist import WORDLIST


class WordlistTests(unittest.TestCase):
    def test_exact_length(self):
        self.assertEqual(len(WORDLIST), 1296)

    def test_all_lowercase_ascii(self):
        for word in WORDLIST:
            self.assertTrue(word.isascii(), f"{word!r} is not ASCII")
            self.assertTrue(word.islower(), f"{word!r} is not lowercase")

    def test_no_duplicates(self):
        self.assertEqual(len(WORDLIST), len(set(WORDLIST)))


class GeneratePasswordTests(unittest.TestCase):
    def test_default_length_and_floor(self):
        pw = generate_password()
        self.assertEqual(len(pw), 20)

    def test_requested_length_below_floor_uses_floor(self):
        pw = generate_password(length=3, lower=True, upper=False, digits=False, symbols=False)
        self.assertEqual(len(pw), 8)  # max(3, 1 pool, 8) == 8

    def test_length_honoured_above_floor(self):
        pw = generate_password(length=40)
        self.assertEqual(len(pw), 40)

    def test_no_charset_selected_raises(self):
        with self.assertRaises(ValueError):
            generate_password(lower=False, upper=False, digits=False, symbols=False)

    def test_guarantees_one_char_per_selected_set(self):
        for _ in range(50):
            pw = generate_password(length=12, lower=True, upper=True, digits=True, symbols=True)
            self.assertTrue(re.search(r"[a-z]", pw))
            self.assertTrue(re.search(r"[A-Z]", pw))
            self.assertTrue(re.search(r"[0-9]", pw))
            self.assertTrue(re.search(r"[^a-zA-Z0-9]", pw))

    def test_single_charset_never_needs_other_classes(self):
        pw = generate_password(length=16, lower=True, upper=False, digits=False, symbols=False)
        self.assertTrue(all(c in SETS["lower"] for c in pw))

    def test_exclude_ambiguous_strips_lookalikes(self):
        for _ in range(50):
            pw = generate_password(length=64, exclude_ambiguous=True)
            self.assertFalse(any(c in AMBIGUOUS for c in pw))

    def test_ambiguous_allowed_when_not_excluded(self):
        # Statistical, not absolute: over enough draws at length 200 some ambiguous
        # character should appear if they are not being stripped.
        found = False
        for _ in range(20):
            pw = generate_password(length=200, exclude_ambiguous=False)
            if any(c in AMBIGUOUS for c in pw):
                found = True
                break
        self.assertTrue(found)

    def test_randomness_not_constant(self):
        samples = {generate_password() for _ in range(20)}
        self.assertGreater(len(samples), 1)


class GeneratePassphraseTests(unittest.TestCase):
    def test_word_count_and_separator(self):
        phrase = generate_passphrase(words=5, separator="-", include_number=False)
        self.assertEqual(len(phrase.split("-")), 5)

    def test_minimum_three_words_enforced(self):
        phrase = generate_passphrase(words=1, include_number=False)
        self.assertEqual(len(phrase.split("-")), 3)

    def test_capitalize(self):
        phrase = generate_passphrase(words=4, capitalize=True, include_number=False)
        for word in phrase.split("-"):
            self.assertTrue(word[0].isupper())

    def test_no_capitalize(self):
        phrase = generate_passphrase(words=4, capitalize=False, include_number=False)
        for word in phrase.split("-"):
            self.assertTrue(word[0].islower())

    def test_include_number_appends_digits_to_exactly_one_word(self):
        phrase = generate_passphrase(words=6, capitalize=False, include_number=True)
        words = phrase.split("-")
        self.assertEqual(len(words), 6)
        trailing_digit_words = [w for w in words if w and w[-1].isdigit()]
        self.assertEqual(len(trailing_digit_words), 1)

    def test_custom_separator(self):
        phrase = generate_passphrase(words=3, separator=" ", include_number=False)
        self.assertEqual(len(phrase.split(" ")), 3)

    def test_words_come_from_wordlist(self):
        phrase = generate_passphrase(words=5, capitalize=False, include_number=False)
        for word in phrase.split("-"):
            self.assertIn(word, WORDLIST)


class GeneratePinTests(unittest.TestCase):
    def test_default_digit_count(self):
        pin = generate_pin()
        self.assertEqual(len(pin), 6)
        self.assertTrue(pin.isdigit())

    def test_custom_digit_count(self):
        pin = generate_pin(digits=4)
        self.assertEqual(len(pin), 4)

    def test_leading_zeros_are_legal(self):
        # Not parsed as an int anywhere; a leading-zero PIN must round-trip as a string.
        found_leading_zero = any(generate_pin(digits=4).startswith("0") for _ in range(200))
        self.assertTrue(found_leading_zero)


if __name__ == "__main__":
    unittest.main()
