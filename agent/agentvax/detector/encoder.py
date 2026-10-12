"""Hashing-vectoriser text encoder. Offline and deterministic, with no vocabulary and no download.

Features are words, word n-grams and padded character n-grams after Unicode folding, hashed with BLAKE2b into a
signed, unit-length vector. Python's salted ``hash`` is never used.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from typing import Annotated, Literal

import numpy as np
from pydantic import BaseModel, ConfigDict, Field, model_validator

ENCODER_KIND = "hashing-v1"
_WORD = re.compile(r"[^\W_]+")


class EncoderSpec(BaseModel):
    """Parameters of the encoder. Stored inside every model file, so a model always names its encoder."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    kind: Literal["hashing-v1"]
    dimension: Annotated[int, Field(ge=16, le=1 << 20)]
    char_ngram_min: Annotated[int, Field(ge=1, le=8)]
    char_ngram_max: Annotated[int, Field(ge=1, le=8)]
    word_ngram_max: Annotated[int, Field(ge=1, le=3)]

    @model_validator(mode="after")
    def _ordered(self) -> EncoderSpec:
        if self.char_ngram_min > self.char_ngram_max:
            raise ValueError("char_ngram_min must not exceed char_ngram_max")
        return self


def _words(text: str) -> list[str]:
    folded = unicodedata.normalize("NFKC", text)
    visible = "".join(ch for ch in folded if unicodedata.category(ch) != "Cf")
    return _WORD.findall(visible.casefold())


def features(text: str, spec: EncoderSpec) -> list[str]:
    """The feature strings of ``text``, in a fixed order."""
    words = _words(text)
    out = [f"w:{w}" for w in words]
    for n in range(2, spec.word_ngram_max + 1):
        out += [f"b:{' '.join(words[i : i + n])}" for i in range(len(words) - n + 1)]
    for word in words:
        padded = f" {word} "
        for n in range(spec.char_ngram_min, spec.char_ngram_max + 1):
            out += [f"c:{padded[i : i + n]}" for i in range(len(padded) - n + 1)]
    return out


def _slot(feature: str, dimension: int) -> tuple[int, float]:
    value = int.from_bytes(hashlib.blake2b(feature.encode("utf-8"), digest_size=8).digest(), "big")
    return value % dimension, (-1.0 if value >> 63 else 1.0)


class HashingEncoder:
    """Turns text into a unit-length vector of ``spec.dimension`` floats."""

    def __init__(self, spec: EncoderSpec) -> None:
        self.spec = spec

    def encode(self, text: str) -> np.ndarray:
        vector = np.zeros(self.spec.dimension, dtype=np.float64)
        for feature in features(text, self.spec):
            index, sign = _slot(feature, self.spec.dimension)
            vector[index] += sign
        norm = float(np.linalg.norm(vector))
        return vector / norm if norm > 0 else vector

    def encode_many(self, texts: list[str]) -> np.ndarray:
        if not texts:
            return np.zeros((0, self.spec.dimension), dtype=np.float64)
        return np.vstack([self.encode(t) for t in texts])
