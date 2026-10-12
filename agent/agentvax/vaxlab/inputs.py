"""Deterministic test addresses and the ``{{address:<label>}}`` placeholders of suite text.

An address is the last 20 bytes of ``keccak256("agentvax-eval-account:" + label)``. Nobody holds its key.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

from eth_utils import keccak, to_checksum_address

from agentvax.names import normalise_name

_PREFIX = "agentvax-eval-account:"
PLACEHOLDER = re.compile(r"\{\{address:([a-z][a-z0-9_]{0,31})\}\}")


class UnknownPlaceholder(ValueError):
    """Text holds ``{{`` or ``}}`` that is not a valid address placeholder."""


def address_for(label: str) -> str:
    """The checksummed test address of ``label``."""
    return to_checksum_address(keccak(text=_PREFIX + label)[12:])


def payee_account(name: str, label: str | None) -> str:
    """The account of a payee in a case setup: the address of its label, or one derived from its name."""
    return address_for(label) if label is not None else address_for("payee:" + normalise_name(name))


def labels_in(text: str) -> tuple[str, ...]:
    """The distinct address labels in ``text``, in order of first appearance."""
    seen: dict[str, None] = {}
    for match in PLACEHOLDER.finditer(text):
        seen.setdefault(match.group(1), None)
    return tuple(seen)


def render(text: str, extra: Mapping[str, str] | None = None) -> str:
    """``text`` with every placeholder replaced by its address. ``extra`` maps labels to addresses that are not
    derived, for example a wallet's own address. Raises ``UnknownPlaceholder`` for a malformed placeholder."""
    rendered = render_valid(text, extra)
    if "{{" in rendered or "}}" in rendered:
        raise UnknownPlaceholder("text holds a malformed address placeholder")
    return rendered


def render_valid(text: str, extra: Mapping[str, str] | None = None) -> str:
    """``text`` with every valid placeholder replaced and anything else left as written. Used for model-generated
    forms, which run exactly as the model wrote them."""
    known = dict(extra or {})
    return PLACEHOLDER.sub(lambda m: known.get(m.group(1)) or address_for(m.group(1)), text)
