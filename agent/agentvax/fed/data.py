"""Training, test and canary texts of the federation experiment.

Kept apart from the evaluation suites, which this module never reads. Data files are ``attacks.json``,
``benign.json`` and ``canary.json``.
"""

from __future__ import annotations

from typing import Annotated

import numpy as np
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, model_validator

from agentvax import resources
from agentvax.fed.config import FAMILY_NAMES, FamilyName, FedConfig

Texts = tuple[Annotated[str, Field(min_length=1)], ...]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class Split(_Strict):
    train: Texts
    test: Texts

    @model_validator(mode="after")
    def _disjoint(self) -> Split:
        if set(self.train) & set(self.test):
            raise ValueError("a text appears in both the training and the test set")
        return self


class AttackCorpus(_Strict):
    direct: Split
    indirect: Split
    memory: Split
    encoded: Split
    recipient_substitution: Split

    def family(self, name: FamilyName) -> Split:
        split: Split = getattr(self, name)
        return split


class CanarySet(_Strict):
    """A wallet's private examples for checking a candidate model. Never used for training."""

    benign: Texts
    attack: Texts

    @model_validator(mode="after")
    def _both_classes(self) -> CanarySet:
        if not self.benign or not self.attack:
            raise ValueError("a canary set needs benign and attack examples")
        return self


class FederationData(_Strict):
    attacks: AttackCorpus
    benign: Split
    canaries: dict[str, CanarySet]

    @model_validator(mode="after")
    def _no_leaks(self) -> FederationData:
        held_out: set[str] = set(self.benign.test)
        training: set[str] = set(self.benign.train)
        for name in FAMILY_NAMES:
            held_out |= set(self.attacks.family(name).test)
            training |= set(self.attacks.family(name).train)
        canary: set[str] = set()
        for c in self.canaries.values():
            canary |= set(c.benign) | set(c.attack)
        if training & held_out or training & canary or held_out & canary:
            raise ValueError("training, test and canary texts must be disjoint")
        return self


_CANARIES: TypeAdapter[dict[str, CanarySet]] = TypeAdapter(dict[str, CanarySet])


class LocalDataset(_Strict):
    """What one wallet trains on: its seeded family's training texts and an equal number of benign texts."""

    wallet_id: str
    attack: Texts
    benign: Texts

    @property
    def size(self) -> int:
        return len(self.attack) + len(self.benign)

    def texts_and_labels(self) -> tuple[list[str], np.ndarray]:
        texts = list(self.benign) + list(self.attack)
        labels = np.concatenate([np.zeros(len(self.benign)), np.ones(len(self.attack))])
        return texts, labels


def load_federation_data() -> FederationData:
    return FederationData(
        attacks=resources.load_model(AttackCorpus, "fed/data/attacks.json"),
        benign=resources.load_model(Split, "fed/data/benign.json"),
        canaries=_load_canaries(),
    )


def _load_canaries() -> dict[str, CanarySet]:
    return _CANARIES.validate_json(resources.read_text("fed/data/canary.json"))


def local_datasets(data: FederationData, config: FedConfig) -> dict[str, LocalDataset]:
    """Each wallet's local training set. The benign training texts are shuffled once with the configured seed
    and dealt out in disjoint slices, each as large as that wallet's attack set, so every wallet holds the same
    number of examples (pairwise masks cancel only under equal FedAvg weights)."""
    sizes = {w.id: len(data.attacks.family(w.seeded_family).train) for w in config.wallets}
    if len(set(sizes.values())) != 1:
        raise ValueError("every seeded family must have the same number of training texts")
    per_wallet = next(iter(sizes.values()))
    if per_wallet * len(config.wallets) > len(data.benign.train):
        raise ValueError("not enough benign training texts for disjoint equal slices")
    order = np.random.default_rng(config.seed).permutation(len(data.benign.train))
    out: dict[str, LocalDataset] = {}
    for index, seeding in enumerate(config.wallets):
        picked = order[index * per_wallet : (index + 1) * per_wallet]
        out[seeding.id] = LocalDataset(
            wallet_id=seeding.id,
            attack=data.attacks.family(seeding.seeded_family).train,
            benign=tuple(data.benign.train[int(i)] for i in picked),
        )
    return out
