"""Password / passphrase / PIN generation — a port of ``generator.ts`` (see
``reference/from-personal-password-manager/generator.ts``) onto the stdlib ``secrets``
module (DESIGN.md §5).

No Frappe import anywhere in this file: it is pure logic, testable with plain
``python -m unittest`` / ``pytest`` and no bench, no site.

All randomness comes from ``secrets.randbelow`` — rejection-sampled and unbiased, the exact
analogue of libsodium's ``randombytes_uniform`` that the TypeScript original uses.
**Never** ``random.*`` and never ``random.shuffle`` (Mersenne Twister, not
cryptographically safe): the Fisher–Yates shuffle below is hand-written over
``secrets.randbelow`` for that reason.
"""

from __future__ import annotations

import secrets

#: Character pools. Kept identical to generator.ts, including symbol selection.
SETS: dict[str, str] = {
    "lower": "abcdefghijklmnopqrstuvwxyz",
    "upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "digits": "0123456789",
    "symbols": "!@#$%^&*()-_=+[]{};:,.?/",
}

#: Look-alike characters stripped when ``exclude_ambiguous`` is set: zero/capital-O,
#: one/lowercase-L/capital-I, pipe.
AMBIGUOUS: frozenset[str] = frozenset("0O1lI|")

#: Minimum length floor generator.ts also enforces, regardless of the requested length.
_MIN_LENGTH = 8


def _strip_ambiguous(pool: str) -> str:
    return "".join(c for c in pool if c not in AMBIGUOUS)


def generate_password(
    length: int = 20,
    lower: bool = True,
    upper: bool = True,
    digits: bool = True,
    symbols: bool = True,
    exclude_ambiguous: bool = True,
) -> str:
    """Semantics identical to ``generatePassword`` in generator.ts:

    - pools = the selected character sets, each stripped of ``AMBIGUOUS`` when
      ``exclude_ambiguous`` is set;
    - raises ``ValueError`` if no set is selected;
    - effective length = ``max(length, number_of_selected_sets, 8)``;
    - guarantees at least one character from each selected (cleaned) pool — one
      ``secrets.randbelow`` pick per pool — then fills the remainder uniformly from the
      concatenation of the cleaned pools;
    - shuffles the whole result with a hand-written Fisher–Yates over
      ``secrets.randbelow``.
    """
    pools: list[str] = []
    if lower:
        pools.append(SETS["lower"])
    if upper:
        pools.append(SETS["upper"])
    if digits:
        pools.append(SETS["digits"])
    if symbols:
        pools.append(SETS["symbols"])
    if not pools:
        raise ValueError("Select at least one character set")

    cleaned = [_strip_ambiguous(pool) if exclude_ambiguous else pool for pool in pools]
    all_chars = "".join(cleaned)
    effective_length = max(length, len(cleaned), _MIN_LENGTH)

    chars = [pool[secrets.randbelow(len(pool))] for pool in cleaned]
    while len(chars) < effective_length:
        chars.append(all_chars[secrets.randbelow(len(all_chars))])

    # Fisher-Yates, secrets.randbelow only — see module docstring.
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]

    return "".join(chars)


def generate_passphrase(
    words: int = 5,
    separator: str = "-",
    capitalize: bool = True,
    include_number: bool = True,
) -> str:
    """EFF short wordlist 2.0 (``vault.wordlist.WORDLIST``, ~10.34 bits/word).

    ``n = max(3, words)`` words are drawn (uniformly, with replacement — the TS original
    does the same, so a phrase can repeat a word). Each is capitalized in place when
    ``capitalize`` is set. When ``include_number`` is set, ``str(secrets.randbelow(100))``
    is appended to exactly one word at a uniformly chosen position. Joined with
    ``separator``.
    """
    # Imported here, not at module level, so a caller that only needs generate_password /
    # generate_pin never pays for loading the 1,296-word list.
    from .wordlist import WORDLIST

    n = max(3, words)
    picked: list[str] = []
    for _ in range(n):
        word = WORDLIST[secrets.randbelow(len(WORDLIST))]
        if capitalize:
            word = word[0].upper() + word[1:]
        picked.append(word)

    if include_number:
        pos = secrets.randbelow(len(picked))
        picked[pos] = picked[pos] + str(secrets.randbelow(100))

    return separator.join(picked)


def generate_pin(digits: int = 6) -> str:
    """A numeric PIN of ``digits`` digits. Leading zeros are legal, exactly as
    generator.ts's ``generatePin`` — this is not parsed as an integer anywhere."""
    return "".join(str(secrets.randbelow(10)) for _ in range(digits))
