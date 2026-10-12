"""Training of the detector head: logistic regression by mini-batch gradient descent in numpy.

Deterministic, with batch order from a seeded generator. Also used for each wallet's local update in federation.

    python -m agentvax.detector.train --out agent/agentvax/detector/data/seed_model.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Annotated

import numpy as np
from pydantic import BaseModel, ConfigDict, Field

from agentvax import resources
from agentvax.detector.encoder import EncoderSpec, HashingEncoder
from agentvax.detector.model import DetectorModel, Thresholds, save_model, sigmoid
from agentvax.types import UINT32_MAX


class TrainingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, allow_inf_nan=False)

    version: Annotated[int, Field(ge=1, le=UINT32_MAX)]
    encoder: EncoderSpec
    thresholds: Thresholds
    epochs: Annotated[int, Field(ge=1, le=100_000)]
    learning_rate: Annotated[float, Field(gt=0.0)]
    l2: Annotated[float, Field(ge=0.0)]
    batch_size: Annotated[int, Field(ge=1)]
    seed: Annotated[int, Field(ge=0)]


class LabelledTexts(BaseModel):
    """Seed data: texts labelled benign (0) or attack-like (1)."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    benign: tuple[str, ...]
    attack: tuple[str, ...]

    def texts_and_labels(self) -> tuple[list[str], np.ndarray]:
        texts = list(self.benign) + list(self.attack)
        labels = np.concatenate([np.zeros(len(self.benign)), np.ones(len(self.attack))])
        return texts, labels


def gradient(w: np.ndarray, b: float, x: np.ndarray, y: np.ndarray, l2: float) -> tuple[np.ndarray, float]:
    """Gradient of the mean log loss plus ``l2 / 2 * |w|^2`` at ``(w, b)``."""
    error = sigmoid(x @ w + b) - y
    return x.T @ error / len(y) + l2 * w, float(np.mean(error))


def train_logistic(
    x: np.ndarray,
    y: np.ndarray,
    config: TrainingConfig,
    init_weights: np.ndarray | None = None,
    init_bias: float = 0.0,
) -> tuple[np.ndarray, float]:
    """Mini-batch gradient descent. Returns ``(weights, bias)``."""
    if x.ndim != 2 or x.shape[1] != config.encoder.dimension or len(y) != x.shape[0]:
        raise ValueError("training data does not match the encoder dimension")
    w = np.zeros(x.shape[1]) if init_weights is None else np.array(init_weights, dtype=np.float64)
    b = float(init_bias)
    rng = np.random.default_rng(config.seed)
    for _ in range(config.epochs):
        order = rng.permutation(len(y))
        for start in range(0, len(y), config.batch_size):
            batch = order[start : start + config.batch_size]
            gw, gb = gradient(w, b, x[batch], y[batch], config.l2)
            w -= config.learning_rate * gw
            b -= config.learning_rate * gb
    return w, b


def train_model(data: LabelledTexts, config: TrainingConfig) -> DetectorModel:
    texts, labels = data.texts_and_labels()
    x = HashingEncoder(config.encoder).encode_many(texts)
    w, b = train_logistic(x, labels, config)
    return DetectorModel.from_arrays(config.version, config.encoder, w, b, config.thresholds)


def default_training_config() -> TrainingConfig:
    return resources.load_model(TrainingConfig, "detector/data/train_config.json")


def default_seed_data() -> LabelledTexts:
    return resources.load_model(LabelledTexts, "detector/data/seed_texts.json")


def seed_model_path() -> Path:
    """Path of the built-in seed model shipped with the package, for handing to the guardian process."""
    return resources.file_path("detector/data/seed_model.json")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train the detector head and write a canonical model file.")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--data", type=Path, help="labelled texts (default: the packaged seed texts)")
    parser.add_argument("--config", type=Path, help="training configuration (default: the packaged one)")
    args = parser.parse_args(argv)
    data = LabelledTexts.model_validate_json(args.data.read_text("utf-8")) if args.data else default_seed_data()
    config = (
        TrainingConfig.model_validate_json(args.config.read_text("utf-8")) if args.config else default_training_config()
    )
    digest = save_model(train_model(data, config), args.out)
    print(json.dumps({"out": str(args.out), "version": config.version, "model_hash": digest}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
