"""Configuration of a federation run, read from ``agentvax/fed/data/fed_config.json``.

Every number that shapes the run lives in that file, not in code.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentvax import resources
from agentvax.types import Family

FamilyName = Literal["direct", "indirect", "memory", "encoded", "recipient_substitution"]
FAMILY_NAMES: tuple[FamilyName, ...] = ("direct", "indirect", "memory", "encoded", "recipient_substitution")
WALLET_ID_PATTERN = r"^[A-Z]$"

CONFIG_RESOURCE = "fed/data/fed_config.json"


def family_of(name: FamilyName) -> Family:
    """The on-chain family number of an attack family name."""
    return Family[name.upper()]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, allow_inf_nan=False)


class WalletSeeding(_Strict):
    """One federation participant and the attack family its local data holds."""

    id: Annotated[str, Field(pattern=WALLET_ID_PATTERN)]
    seeded_family: FamilyName


class CanaryTolerance(_Strict):
    """A wallet rejects a candidate model whose canary recall is lower than its current model's by more than
    ``max_recall_drop``, or whose canary false-positive rate is higher by more than ``max_fpr_rise``."""

    max_recall_drop: Annotated[float, Field(ge=0.0, le=1.0)]
    max_fpr_rise: Annotated[float, Field(ge=0.0, le=1.0)]


class FedConfig(_Strict):
    initial_model: Annotated[str, Field(min_length=1)]
    """Packaged path of the model every wallet runs before the first round."""
    seed: Annotated[int, Field(ge=0)]
    rounds: Annotated[int, Field(ge=1, le=1000)]
    local_epochs: Annotated[int, Field(ge=1, le=100_000)]
    learning_rate: Annotated[float, Field(gt=0.0)]
    l2: Annotated[float, Field(ge=0.0)]
    batch_size: Annotated[int, Field(ge=1)]
    clip_norm: Annotated[float, Field(gt=0.0)]
    """C: every honest update is scaled down to at most this L2 norm before it is masked."""
    fraction_bits: Annotated[int, Field(ge=8, le=40)]
    """Updates are sent as integers in units of 2**-fraction_bits, so masked sums are exact."""
    mask_bits: Annotated[int, Field(ge=16, le=50)]
    """Each pairwise mask component is a uniform integer in [-2**mask_bits, 2**mask_bits)."""
    canary: CanaryTolerance
    hostile_scale: Annotated[float, Field(gt=0.0)]
    """How many times C a poisoned update is scaled to, in the hostile-wallet suite."""
    wallets: tuple[WalletSeeding, ...]
    held_out_families: tuple[FamilyName, ...]

    @model_validator(mode="after")
    def _families_partitioned(self) -> FedConfig:
        ids = [w.id for w in self.wallets]
        seeded = [w.seeded_family for w in self.wallets]
        if len(self.wallets) < 2:
            raise ValueError("a federation needs at least two wallets for pairwise masking")
        if len(set(ids)) != len(ids):
            raise ValueError("wallet ids must be distinct")
        if len(set(seeded)) != len(seeded):
            raise ValueError("each wallet must be seeded with a different family")
        if set(seeded) & set(self.held_out_families):
            raise ValueError("a held-out family cannot also seed a wallet")
        if set(seeded) | set(self.held_out_families) != set(FAMILY_NAMES):
            raise ValueError("every family must either seed a wallet or be held out")
        return self

    def wallet(self, wallet_id: str) -> WalletSeeding:
        for seeding in self.wallets:
            if seeding.id == wallet_id:
                return seeding
        raise KeyError(f"no wallet {wallet_id!r} in the federation")


def default_fed_config() -> FedConfig:
    return resources.load_model(FedConfig, CONFIG_RESOURCE)
