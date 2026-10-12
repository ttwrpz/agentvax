"""Detector model: ``s(x) = sigmoid(w . phi(x) + b)``, banded by two thresholds, stored as canonical JSON.

The file holds numbers and fixed strings only. The loader accepts only already-canonical bytes, so one model has
one hash, and rejects NaN, infinities, duplicate or unknown keys and a wrong weight length.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Annotated, Any, Literal

import numpy as np
from eth_utils import keccak
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from agentvax.detector.encoder import EncoderSpec, HashingEncoder
from agentvax.types import UINT32_MAX, Band

MODEL_FORMAT = "agentvax-detector-v1"
MODEL_FILE = "detector_model.json"
"""File name of a released model in the directory that a federation run or an evidence run writes it to."""


class ModelFormatError(ValueError):
    """The bytes are not a valid canonical detector model."""


class ModelHashMismatch(ValueError):
    """The model's hash is not the anchored hash."""


class Thresholds(BaseModel):
    """``score >= high`` is HIGH, ``score >= medium`` is MEDIUM, anything lower is LOW."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, allow_inf_nan=False)

    medium: Annotated[float, Field(gt=0.0, lt=1.0)]
    high: Annotated[float, Field(gt=0.0, lt=1.0)]

    @model_validator(mode="after")
    def _ordered(self) -> Thresholds:
        if not self.medium < self.high:
            raise ValueError("medium threshold must be below high threshold")
        return self


class DetectorModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, allow_inf_nan=False)

    format: Literal["agentvax-detector-v1"]
    version: Annotated[int, Field(ge=1, le=UINT32_MAX)]
    encoder: EncoderSpec
    weights: tuple[float, ...]
    bias: float
    thresholds: Thresholds

    @model_validator(mode="after")
    def _consistent(self) -> DetectorModel:
        if len(self.weights) != self.encoder.dimension:
            raise ValueError(f"{len(self.weights)} weights for dimension {self.encoder.dimension}")
        if not all(math.isfinite(w) for w in self.weights) or not math.isfinite(self.bias):
            raise ValueError("weights and bias must be finite")
        return self

    @classmethod
    def from_arrays(
        cls, version: int, encoder: EncoderSpec, weights: np.ndarray, bias: float, thresholds: Thresholds
    ) -> DetectorModel:
        return cls(
            format=MODEL_FORMAT,
            version=version,
            encoder=encoder,
            weights=tuple(float(w) for w in weights),
            bias=float(bias),
            thresholds=thresholds,
        )

    def weight_vector(self) -> np.ndarray:
        return np.asarray(self.weights, dtype=np.float64)


def canonical_bytes(model: DetectorModel) -> bytes:
    """The one byte form of ``model`` that is hashed and stored."""
    return json.dumps(
        model.model_dump(mode="python"), sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def model_hash(model: DetectorModel) -> str:
    """keccak256 of the canonical bytes, as ``0x`` hex. This is what the aggregator anchors on chain."""
    return "0x" + keccak(canonical_bytes(model)).hex()


def _reject_constant(name: str) -> Any:
    raise ModelFormatError(f"non-finite number {name} in model file")


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ModelFormatError(f"duplicate key {key!r} in model file")
        out[key] = value
    return out


def parse_model(data: bytes) -> DetectorModel:
    """Validates ``data`` as a canonical model file. Raises ``ModelFormatError`` for anything else."""
    try:
        text = data.decode("ascii")
        json.loads(text, parse_constant=_reject_constant, object_pairs_hook=_no_duplicates)
        model = DetectorModel.model_validate_json(text)
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
        raise ModelFormatError(str(exc)) from exc
    if canonical_bytes(model) != data:
        raise ModelFormatError("model file is not in canonical form")
    return model


def load_model(path: Path) -> DetectorModel:
    return parse_model(path.read_bytes())


def load_if_hash_matches(path: Path, anchored_hash: str) -> DetectorModel:
    """Loads the model at ``path`` only if the keccak256 of its exact bytes equals ``anchored_hash``."""
    data = path.read_bytes()
    actual = "0x" + keccak(data).hex()
    if actual.lower() != anchored_hash.lower():
        raise ModelHashMismatch(f"model hash {actual} does not match anchored hash {anchored_hash}")
    return parse_model(data)


def save_model(model: DetectorModel, path: Path) -> str:
    """Writes the canonical bytes to ``path`` and returns the model hash."""
    path.write_bytes(canonical_bytes(model))
    return model_hash(model)


def _sigmoid(z: np.ndarray | float) -> np.ndarray | float:
    return 0.5 * (1.0 + np.tanh(0.5 * np.asarray(z)))


class Detector:
    """Scores text with a loaded model."""

    def __init__(self, model: DetectorModel) -> None:
        self.model = model
        self._encoder = HashingEncoder(model.encoder)
        self._w = model.weight_vector()
        self._b = model.bias

    def score(self, text: str) -> float:
        return float(_sigmoid(float(self._w @ self._encoder.encode(text)) + self._b))

    def band_of_score(self, score: float) -> Band:
        t = self.model.thresholds
        if score >= t.high:
            return Band.HIGH
        if score >= t.medium:
            return Band.MEDIUM
        return Band.LOW

    def band(self, text: str) -> Band:
        return self.band_of_score(self.score(text))


def sigmoid(z: np.ndarray) -> np.ndarray:
    """Logistic function, computed through tanh so it never overflows."""
    return np.asarray(_sigmoid(z))
