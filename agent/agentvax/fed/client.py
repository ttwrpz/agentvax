"""The Flower client of one wallet.

``fit`` trains locally, clips, encodes and masks. Only the masked update and the example count leave the wallet.
Parameters travel as ``[weights (dimension,), bias (1,)]``.
"""

from __future__ import annotations

import hashlib

import numpy as np
from flwr.client import NumPyClient
from flwr.common import NDArrays, Scalar

from agentvax.detector.encoder import HashingEncoder
from agentvax.detector.model import DetectorModel, sigmoid
from agentvax.detector.train import TrainingConfig, train_logistic
from agentvax.fed import canary
from agentvax.fed.config import FedConfig
from agentvax.fed.data import CanarySet, LocalDataset
from agentvax.fed.secure import PairwiseMasker, Quantiser, clip, l2_norm

ROUND_KEY = "round"
VERSION_KEY = "version"
_LOG_EPSILON = 1e-12


def model_to_ndarrays(model: DetectorModel) -> NDArrays:
    return [model.weight_vector(), np.array([model.bias], dtype=np.float64)]


def ndarrays_to_vector(parameters: NDArrays) -> np.ndarray:
    """The flat vector ``(weights..., bias)`` of a parameter list."""
    if len(parameters) != 2 or parameters[1].shape != (1,):
        raise ValueError("parameters must be [weights, bias]")
    return np.concatenate([np.asarray(parameters[0], dtype=np.float64), np.asarray(parameters[1], dtype=np.float64)])


def vector_to_ndarrays(vector: np.ndarray) -> NDArrays:
    flat = np.asarray(vector, dtype=np.float64)
    return [flat[:-1].copy(), flat[-1:].copy()]


def model_from_vector(template: DetectorModel, vector: np.ndarray, version: int) -> DetectorModel:
    """A model with ``template``'s encoder and thresholds and the weights and bias in ``vector``."""
    flat = np.asarray(vector, dtype=np.float64)
    return DetectorModel.from_arrays(version, template.encoder, flat[:-1], float(flat[-1]), template.thresholds)


def derived_seed(base_seed: int, *parts: object) -> int:
    """A training seed derived from the configured seed and a label, the same on every machine."""
    label = "|".join([str(base_seed), *(str(p) for p in parts)]).encode("utf-8")
    return int.from_bytes(hashlib.blake2b(label, digest_size=8).digest(), "big")


def training_config(model: DetectorModel, config: FedConfig, epochs: int, seed: int) -> TrainingConfig:
    return TrainingConfig(
        version=model.version,
        encoder=model.encoder,
        thresholds=model.thresholds,
        epochs=epochs,
        learning_rate=config.learning_rate,
        l2=config.l2,
        batch_size=config.batch_size,
        seed=seed,
    )


def encode_dataset(model: DetectorModel, dataset: LocalDataset) -> tuple[np.ndarray, np.ndarray]:
    texts, labels = dataset.texts_and_labels()
    return HashingEncoder(model.encoder).encode_many(texts), labels


def train_local_model(
    start: DetectorModel, dataset: LocalDataset, config: FedConfig, epochs: int, seed: int
) -> DetectorModel:
    """``start`` trained further on ``dataset`` alone, with no federation, clipping or masking."""
    x, y = encode_dataset(start, dataset)
    w, b = train_logistic(
        x, y, training_config(start, config, epochs, seed), init_weights=start.weight_vector(), init_bias=start.bias
    )
    return DetectorModel.from_arrays(start.version, start.encoder, w, b, start.thresholds)


def canary_log_loss(model: DetectorModel, canary_set: CanarySet) -> float:
    """Mean log loss of ``model`` on the canary set, reported as Flower's evaluation loss."""
    texts = list(canary_set.benign) + list(canary_set.attack)
    labels = np.concatenate([np.zeros(len(canary_set.benign)), np.ones(len(canary_set.attack))])
    x = HashingEncoder(model.encoder).encode_many(texts)
    p = np.clip(sigmoid(x @ model.weight_vector() + model.bias), _LOG_EPSILON, 1.0 - _LOG_EPSILON)
    return float(-np.mean(labels * np.log(p) + (1.0 - labels) * np.log(1.0 - p)))


class WalletClient(NumPyClient):
    """One wallet in the federation. Holds its data, its canary set and the model it currently runs."""

    def __init__(
        self,
        wallet_id: str,
        dataset: LocalDataset,
        canary_set: CanarySet,
        current: DetectorModel,
        config: FedConfig,
        masker: PairwiseMasker,
    ) -> None:
        if masker.wallet_id != wallet_id or dataset.wallet_id != wallet_id:
            raise ValueError("dataset, masker and client must belong to the same wallet")
        self.wallet_id = wallet_id
        self._dataset = dataset
        self._canary = canary_set
        self._current = current
        self._config = config
        self._masker = masker
        self._quantiser = Quantiser(config.fraction_bits)
        self._x, self._y = encode_dataset(current, dataset)
        self.last_verdict: canary.CanaryVerdict | None = None
        # Norm of each round's update before clipping. Kept by the wallet for its own report, never sent.
        self.raw_update_norms: dict[int, float] = {}

    @property
    def current(self) -> DetectorModel:
        return self._current

    @property
    def num_examples(self) -> int:
        return self._dataset.size

    def get_parameters(self, config: dict[str, Scalar]) -> NDArrays:
        return model_to_ndarrays(self._current)

    def local_update(self, parameters: NDArrays, round_number: int) -> np.ndarray:
        """``w_local - w_global`` after the configured local epochs, before clipping."""
        start = ndarrays_to_vector(parameters)
        seed = derived_seed(self._config.seed, "fit", self.wallet_id, round_number)
        w, b = train_logistic(
            self._x,
            self._y,
            training_config(self._current, self._config, self._config.local_epochs, seed),
            init_weights=start[:-1],
            init_bias=float(start[-1]),
        )
        return np.concatenate([w, [b]]) - start

    def prepare_update(self, parameters: NDArrays, round_number: int) -> np.ndarray:
        """The update this wallet contributes: its local update clipped to norm C."""
        update = self.local_update(parameters, round_number)
        self.raw_update_norms[round_number] = l2_norm(update)
        return clip(update, self._config.clip_norm)

    def masked(self, update: np.ndarray, round_number: int) -> NDArrays:
        """``update`` encoded in fixed point and masked, ready to leave the wallet."""
        return vector_to_ndarrays(self._masker.mask(self._quantiser.encode(update), round_number))

    def fit(self, parameters: NDArrays, config: dict[str, Scalar]) -> tuple[NDArrays, int, dict[str, Scalar]]:
        round_number = int(config[ROUND_KEY])
        update = self.prepare_update(parameters, round_number)
        return self.masked(update, round_number), self.num_examples, {}

    def evaluate(self, parameters: NDArrays, config: dict[str, Scalar]) -> tuple[float, int, dict[str, Scalar]]:
        """Canary check of the candidate in ``parameters`` against the model this wallet runs."""
        candidate = model_from_vector(self._current, ndarrays_to_vector(parameters), int(config[VERSION_KEY]))
        verdict = canary.check(self._current, candidate, self._canary, self._config.canary)
        self.last_verdict = verdict
        size = len(self._canary.benign) + len(self._canary.attack)
        metrics: dict[str, Scalar] = {
            "accepted": verdict.accepted,
            "recall": verdict.candidate.recall,
            "false_positive_rate": verdict.candidate.false_positive_rate,
        }
        return canary_log_loss(candidate, self._canary), size, metrics

    def adopt(self, model: DetectorModel) -> None:
        """Runs ``model`` from now on. Called only for a model every wallet's canary accepted."""
        if model.encoder != self._current.encoder:
            raise ValueError("a federated model must keep the encoder")
        self._current = model
