"""The aggregator's side of a federation round.

The masked updates are averaged with Flower's FedAvg, the average is added to the global model, and every
wallet canary-checks the candidate. It is adopted only if all accept. The aggregator never sees an unmasked update.
"""

from __future__ import annotations

from collections.abc import Sequence

import numpy as np
from flwr.common import NDArrays
from flwr.server.strategy.aggregate import aggregate
from pydantic import BaseModel, ConfigDict

from agentvax.detector.model import DetectorModel, model_hash
from agentvax.fed.canary import CanaryScore
from agentvax.fed.client import (
    ROUND_KEY,
    VERSION_KEY,
    WalletClient,
    model_from_vector,
    model_to_ndarrays,
    ndarrays_to_vector,
)
from agentvax.fed.config import FedConfig
from agentvax.fed.secure import MaskingError, Quantiser, l2_norm, require_exact


class _Record(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, allow_inf_nan=False)


class WalletRoundRecord(_Record):
    wallet_id: str
    accepted: bool
    current: CanaryScore
    candidate: CanaryScore


class RoundRecord(_Record):
    round: int
    candidate_version: int
    candidate_hash: str
    mean_update_norm: float
    adopted: bool
    wallets: tuple[WalletRoundRecord, ...]


class FederationOutcome(_Record):
    initial: DetectorModel
    model: DetectorModel
    """The model every wallet runs after the last round."""
    rounds: tuple[RoundRecord, ...]
    masked: bool
    clipped: bool

    @property
    def canary_passed(self) -> bool:
        """True if the final model is a federated model that every wallet's canary accepted."""
        adopted = [r for r in self.rounds if r.adopted]
        return bool(adopted) and adopted[-1].candidate_hash == model_hash(self.model)


def masked_value_limit(config: FedConfig, n_wallets: int) -> float:
    """Largest magnitude a component of a masked, clipped, encoded update can have."""
    return Quantiser(config.fraction_bits).max_units(config.clip_norm) + (n_wallets - 1) * 2.0**config.mask_bits


def aggregate_masked(results: Sequence[tuple[NDArrays, int]], config: FedConfig) -> np.ndarray:
    """The average update, decoded from fixed point, from the wallets' masked updates.

    Uses Flower's FedAvg ``aggregate``. Raises ``MaskingError`` if the example counts differ or a received value
    is not an integer in the range of a masked honest update, because the masks would then not cancel exactly.
    """
    if len(results) < 2:
        raise MaskingError("masked aggregation needs at least two wallets")
    counts = {n for _, n in results}
    if len(counts) != 1 or next(iter(counts)) < 1:
        raise MaskingError("pairwise masks cancel only if every wallet reports the same example count")
    limit = masked_value_limit(config, len(results))
    require_exact(len(results), next(iter(counts)), config.clip_norm, config.fraction_bits, config.mask_bits)
    for parameters, _ in results:
        vector = ndarrays_to_vector(parameters)
        if not np.all(np.isfinite(vector)) or not np.array_equal(vector, np.rint(vector)):
            raise MaskingError("a masked update must be integer-valued")
        if float(np.max(np.abs(vector))) > limit:
            raise MaskingError("a masked update is outside the range of a clipped update")
    mean = aggregate([(list(parameters), n) for parameters, n in results])
    return Quantiser(config.fraction_bits).decode(ndarrays_to_vector(mean))


def run_round(
    clients: Sequence[WalletClient], global_model: DetectorModel, round_number: int, config: FedConfig
) -> tuple[DetectorModel, RoundRecord]:
    """One round. Returns the model every wallet runs afterwards (the candidate if adopted, otherwise
    ``global_model``) and the record of the round."""
    ordered = sorted(clients, key=lambda c: c.wallet_id)
    parameters = model_to_ndarrays(global_model)
    fits = [c.fit(parameters, {ROUND_KEY: round_number}) for c in ordered]
    mean_update = aggregate_masked([(p, n) for p, n, _ in fits], config)
    candidate = model_from_vector(
        global_model, ndarrays_to_vector(parameters) + mean_update, global_model.version + 1
    )
    candidate_parameters = model_to_ndarrays(candidate)
    records = []
    for c in ordered:
        _, _, metrics = c.evaluate(candidate_parameters, {VERSION_KEY: candidate.version})
        verdict = c.last_verdict
        if verdict is None:
            raise RuntimeError(f"wallet {c.wallet_id} returned no canary verdict")
        records.append(
            WalletRoundRecord(
                wallet_id=c.wallet_id,
                accepted=bool(metrics["accepted"]),
                current=verdict.current,
                candidate=verdict.candidate,
            )
        )
    adopted = all(r.accepted for r in records)
    if adopted:
        for c in ordered:
            c.adopt(candidate)
    record = RoundRecord(
        round=round_number,
        candidate_version=candidate.version,
        candidate_hash=model_hash(candidate),
        mean_update_norm=l2_norm(mean_update),
        adopted=adopted,
        wallets=tuple(records),
    )
    return (candidate if adopted else global_model), record


def federate(clients: Sequence[WalletClient], initial: DetectorModel, config: FedConfig) -> FederationOutcome:
    """``config.rounds`` rounds from ``initial``. Every client must currently run ``initial``."""
    if any(c.current != initial for c in clients):
        raise ValueError("every wallet must start from the initial model")
    model = initial
    rounds = []
    for round_number in range(1, config.rounds + 1):
        model, record = run_round(clients, model, round_number, config)
        rounds.append(record)
    return FederationOutcome(initial=initial, model=model, rounds=tuple(rounds), masked=True, clipped=True)
