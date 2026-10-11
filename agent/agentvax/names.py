"""Payee names: finding allowlist names in trusted or untrusted text (whole-word, case-insensitive, longest name
first), and the identity hash of a name."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Sequence

from eth_utils import keccak

_WHITESPACE = re.compile(r"\s+")


def normalise_name(name: str) -> str:
    """NFC, case-folded, runs of whitespace collapsed to one space, trimmed."""
    return _WHITESPACE.sub(" ", unicodedata.normalize("NFC", name).casefold()).strip()


def identity_hash(name: str) -> str:
    """``keccak256(utf8(normalise_name(name)))`` as 0x-prefixed hex: the on-chain identity of a payee.

    The owner can recompute it from the name alone. Raises ``ValueError`` for a name that is empty once normalised.
    """
    normal = normalise_name(name)
    if not normal:
        raise ValueError("a payee name must not be empty")
    return "0x" + keccak(normal.encode("utf-8")).hex()


def find_names(text: str, names: Sequence[str]) -> tuple[tuple[int, int], ...]:
    """Pairs of (index into ``names``, position in ``text``), one per name found, in order of position.

    A longer name wins over a shorter one that it contains, so "Acme Power" is not also read as "Acme".
    """
    order = sorted(range(len(names)), key=lambda i: -len(names[i]))
    taken: list[tuple[int, int]] = []
    found: list[tuple[int, int]] = []
    for index in order:
        pattern = re.compile(r"(?<!\w)" + re.escape(names[index]) + r"(?!\w)", re.IGNORECASE)
        for match in pattern.finditer(text):
            if any(match.start() < end and start < match.end() for start, end in taken):
                continue
            taken.append((match.start(), match.end()))
            found.append((index, match.start()))
            break
    return tuple(sorted(found, key=lambda pair: pair[1]))
