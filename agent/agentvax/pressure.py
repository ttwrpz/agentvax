"""Deterministic pressure and encoding flags for raw text. No model is called.

``scan(text)`` returns the ``Flag`` bits a fixed rule set finds in ``text``:

* URGENCY, SECRECY, OVERRIDE_ATTEMPT: a phrase from the fixed English lists in
  ``agentvax/data/pressure_phrases.json`` appears as whole words, ignoring case, punctuation, apostrophes, Unicode
  compatibility forms and invisible characters. "Don't tell", "dont tell" and "DON'T  TELL!" all match.
* ENCODED_CONTENT, when any of these concrete signs is present:
  1. an invisible formatting character: zero-width characters, bidirectional controls, word joiners, a byte
     order mark after the start, or Unicode tag characters (used to hide text from a reader);
  2. a base64 or hexadecimal run that decodes to readable text (an address or hash decodes to random bytes and
     does not count);
  3. a run of ``\\xNN`` escape sequences;
  4. a word that mixes Latin letters with Cyrillic or Greek letters, or uses fullwidth or mathematical
     letter forms (homoglyph disguise);
  5. an encoding instruction ("rot13", "base64", "decode the following"), or a listed phrase that appears only
     after rot13 or after reversing the text.
  Decoded base64 and hexadecimal text is scanned for the phrase lists as well.

The rules only ever add flags. Thresholds live in the data file with the phrase lists.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
from functools import lru_cache
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from agentvax import resources
from agentvax.types import Flag

_INVISIBLE = frozenset(
    [0x180E, 0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2028, 0x2029]
    + list(range(0x202A, 0x202F))
    + list(range(0x2060, 0x2065))
    + list(range(0x2066, 0x206A))
)
_BOM = 0xFEFF
_TAGS = range(0xE0000, 0xE0080)
_FULLWIDTH_LATIN = (range(0xFF21, 0xFF3B), range(0xFF41, 0xFF5B))
_MATH_ALPHANUMERIC = range(0x1D400, 0x1D800)
_APOSTROPHES = re.compile(r"['’‘ʼ`´]")
_NON_WORD = re.compile(r"[\W_]+")
_WORD = re.compile(r"[^\W\d_]+")
_ESCAPES = re.compile(r"(?:\\x[0-9a-fA-F]{2})+")


class EncodedRules(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    min_base64_chars: Annotated[int, Field(ge=8)]
    min_hex_chars: Annotated[int, Field(ge=8)]
    min_decoded_bytes: Annotated[int, Field(ge=4)]
    min_printable_ratio: Annotated[float, Field(gt=0.5, le=1.0)]
    min_escape_sequences: Annotated[int, Field(ge=2)]


class PhraseList(BaseModel):
    """The fixed phrase lists and thresholds, as stored in the data file."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    version: int
    urgency: tuple[str, ...]
    secrecy: tuple[str, ...]
    override_attempt: tuple[str, ...]
    encoding_indicators: tuple[str, ...]
    encoded: EncodedRules


class CompiledPhrases:
    """Normalised phrases grouped by the flag they set."""

    def __init__(self, phrases: PhraseList) -> None:
        self.rules = phrases.encoded
        self.by_flag: tuple[tuple[Flag, tuple[str, ...]], ...] = (
            (Flag.URGENCY, _normalise_phrases(phrases.urgency)),
            (Flag.SECRECY, _normalise_phrases(phrases.secrecy)),
            (Flag.OVERRIDE_ATTEMPT, _normalise_phrases(phrases.override_attempt)),
        )
        self.indicators = _normalise_phrases(phrases.encoding_indicators)
        self.base64_run = re.compile(r"[A-Za-z0-9+/_-]{%d,}={0,2}" % self.rules.min_base64_chars)
        self.hex_run = re.compile(r"(?:0x)?([0-9a-fA-F]{%d,})" % self.rules.min_hex_chars)


def _normalise_phrases(phrases: tuple[str, ...]) -> tuple[str, ...]:
    out = []
    for phrase in phrases:
        normal = normalise(phrase).strip()
        if not normal:
            raise ValueError(f"phrase {phrase!r} is empty after normalisation")
        out.append(f" {normal} ")
    return tuple(out)


def normalise(text: str) -> str:
    """Compatibility forms folded, invisible characters removed, lower case, apostrophes dropped, every run of
    other non-letter, non-digit characters turned into one space, padded with a space at each end."""
    folded = unicodedata.normalize("NFKC", text)
    visible = "".join(ch for ch in folded if unicodedata.category(ch) != "Cf")
    lowered = _APOSTROPHES.sub("", visible.casefold())
    return " " + _NON_WORD.sub(" ", lowered).strip() + " "


def load_phrase_list(raw_json: str) -> PhraseList:
    return PhraseList.model_validate_json(raw_json)


@lru_cache(maxsize=1)
def _default() -> CompiledPhrases:
    return CompiledPhrases(resources.load_model(PhraseList, "data/pressure_phrases.json"))


def _phrase_flags(normal: str, compiled: CompiledPhrases) -> Flag:
    flags = Flag.NONE
    for flag, phrases in compiled.by_flag:
        if any(p in normal for p in phrases):
            flags |= flag
    return flags


def _has_invisible(text: str) -> bool:
    for index, ch in enumerate(text):
        cp = ord(ch)
        if cp in _INVISIBLE or cp in _TAGS or (cp == _BOM and index > 0):
            return True
    return False


def _has_homoglyph_disguise(text: str) -> bool:
    for ch in text:
        cp = ord(ch)
        if cp in _MATH_ALPHANUMERIC or any(cp in r for r in _FULLWIDTH_LATIN):
            return True
    for word in _WORD.findall(text):
        scripts = set()
        for ch in word:
            name = unicodedata.name(ch, "")
            if name.startswith("LATIN"):
                scripts.add("latin")
            elif name.startswith("CYRILLIC"):
                scripts.add("cyrillic")
            elif name.startswith("GREEK"):
                scripts.add("greek")
        if "latin" in scripts and len(scripts) > 1:
            return True
    return False


def _readable(data: bytes, rules: EncodedRules) -> str | None:
    """``data`` as text if it looks like a sentence: long enough, mostly printable ASCII, with a space."""
    if len(data) < rules.min_decoded_bytes:
        return None
    printable = sum(1 for b in data if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D))
    if printable / len(data) < rules.min_printable_ratio or b" " not in data:
        return None
    return data.decode("ascii", errors="ignore")


def _decoded_payloads(text: str, compiled: CompiledPhrases) -> list[str]:
    rules = compiled.rules
    found: list[str] = []
    for match in compiled.hex_run.finditer(text):
        digits = match.group(1)
        if len(digits) % 2:
            continue
        readable = _readable(bytes.fromhex(digits), rules)
        if readable is not None:
            found.append(readable)
    for match in compiled.base64_run.finditer(text):
        token = match.group(0)
        if re.fullmatch(r"(?:0x)?[0-9a-fA-F]+", token):
            continue
        standard = token.replace("-", "+").replace("_", "/")
        standard += "=" * (-len(standard) % 4)
        try:
            data = base64.b64decode(standard, validate=True)
        except (binascii.Error, ValueError):
            continue
        readable = _readable(data, rules)
        if readable is not None:
            found.append(readable)
    for match in _ESCAPES.finditer(text):
        if len(match.group(0)) // 4 >= rules.min_escape_sequences:
            found.append(bytes.fromhex(match.group(0).replace("\\x", "")).decode("latin-1"))
    return found


def scan_with(text: str, compiled: CompiledPhrases) -> Flag:
    normal = normalise(text)
    flags = _phrase_flags(normal, compiled)

    encoded = _has_invisible(text) or _has_homoglyph_disguise(text) or any(p in normal for p in compiled.indicators)
    payloads = _decoded_payloads(text, compiled)
    if payloads:
        encoded = True
        for payload in payloads:
            flags |= _phrase_flags(normalise(payload), compiled)

    rotated = normalise(codecs.encode(normal, "rot13"))
    reversed_text = normalise(normal[::-1])
    hidden = _phrase_flags(rotated, compiled) | _phrase_flags(reversed_text, compiled)
    if hidden & ~flags:
        encoded = True
        flags |= hidden

    if encoded:
        flags |= Flag.ENCODED_CONTENT
    return flags


def scan(text: str) -> Flag:
    """Flags set by the fixed rules for ``text``. Pure and deterministic."""
    return scan_with(text, _default())
