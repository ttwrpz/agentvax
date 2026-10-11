"""Reading of token amounts from plain text, in base units.

Used by the validator to trace an amount back to the owner's instruction and by the mock model rules. It is
deterministic and never calls a model.
"""

from __future__ import annotations

import re

from pydantic import Field

from agentvax.resources import load_model
from agentvax.types import TOKEN_DECIMALS, TOKEN_UNIT, Strict

_NUMBER = re.compile(r"(?<![\w.,])(\d{1,3}(?:,\d{3})+|\d+)(?:\.(\d{1,%d}))?(?![\w])" % TOKEN_DECIMALS)
_ISO_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_NEXT_WORD = re.compile(r"\s*([A-Za-z%]+)")


class AmountRules(Strict):
    non_amount_units: tuple[str, ...] = Field(min_length=1)


class AmountMatch(Strict):
    value: int
    start: int
    end: int


def _rules() -> AmountRules:
    return load_model(AmountRules, "data/amount_rules.json")


def find_amounts(text: str) -> tuple[AmountMatch, ...]:
    """Every number in ``text`` that reads as a token amount, with its position.

    Ordinals such as "1st", counts such as "12 months" and percentages are not amounts.
    """
    units = frozenset(_rules().non_amount_units)
    found: list[AmountMatch] = []
    scanned = _ISO_DATE.sub(lambda date: " " * len(date.group()), text)
    for match in _NUMBER.finditer(scanned):
        following = _NEXT_WORD.match(scanned, match.end())
        if following and (following.group(1).lower() in units or following.group(1) == "%"):
            continue
        if scanned[match.end() : match.end() + 1] == "%":
            continue
        whole = int(match.group(1).replace(",", ""))
        fraction = (match.group(2) or "").ljust(TOKEN_DECIMALS, "0")
        value = whole * TOKEN_UNIT + (int(fraction) if fraction else 0)
        found.append(AmountMatch(value=value, start=match.start(), end=match.end()))
    return tuple(found)


def parse_amounts(text: str) -> tuple[int, ...]:
    """The distinct amounts in ``text`` in order of first appearance."""
    seen: list[int] = []
    for match in find_amounts(text):
        if match.value not in seen:
            seen.append(match.value)
    return tuple(seen)


def format_amount(base_units: int) -> str:
    """Whole units, with decimals only when they are not zero: 300000000 becomes "300"."""
    whole, fraction = divmod(base_units, TOKEN_UNIT)
    if fraction == 0:
        return f"{whole:,}"
    return f"{whole:,}.{str(fraction).rjust(TOKEN_DECIMALS, '0').rstrip('0')}"
