"""The evidence plan: what each row asks of the agent, helper key funding per network, and the evidence document text.

These live in ``evidence/data/plan.json`` and ``text.json``. Token amounts are whole MockUSD and native amounts
are ether, as decimal strings, converted to base units here.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Annotated

from pydantic import Field, field_validator

from agentvax.resources import load_model
from agentvax.types import TOKEN_DECIMALS, Strict

NATIVE_DECIMALS = 18
ROW_IDS: tuple[str, ...] = tuple(f"E{i:02d}" for i in range(1, 15))
WALLET_LABELS: tuple[str, ...] = ("A", "B", "C")


def to_units(amount: str, decimals: int) -> int:
    """``amount``, a non-negative decimal string, in base units. Raises ``ValueError`` if it has more decimals than
    the asset or is not a number."""
    try:
        value = Decimal(amount)
    except InvalidOperation as exc:
        raise ValueError(f"{amount!r} is not a decimal amount") from exc
    scaled = value * (Decimal(10) ** decimals)
    if value < 0 or scaled != scaled.to_integral_value():
        raise ValueError(f"{amount!r} is negative or has more than {decimals} decimals")
    return int(scaled)


def tokens(amount: str) -> int:
    return to_units(amount, TOKEN_DECIMALS)


def wei(amount: str) -> int:
    return to_units(amount, NATIVE_DECIMALS)


def _token_amount(value: str) -> str:
    tokens(value)
    return value


def _native_amount(value: str) -> str:
    wei(value)
    return value


class WalletPlan(Strict):
    payees: tuple[Annotated[str, Field(min_length=1)], ...]
    tokens: str
    """MockUSD the wallet holds before the rows start."""

    @field_validator("tokens")
    @classmethod
    def _amount(cls, value: str) -> str:
        return _token_amount(value)


class InstructionRow(Strict):
    instruction: Annotated[str, Field(min_length=1)]


class DocumentRow(Strict):
    instruction: Annotated[str, Field(min_length=1)]
    document: Annotated[str, Field(min_length=1)]


class ScheduleRow(Strict):
    payee: Annotated[str, Field(min_length=1)]
    amount: str
    max_runs: Annotated[int, Field(ge=1, le=100)]
    first_due_lead_seconds: Annotated[int, Field(ge=1, le=3_600)]
    """Seconds after the latest block that the first occurrence falls due."""

    @field_validator("amount")
    @classmethod
    def _amount(cls, value: str) -> str:
        return _token_amount(value)


class ObligationPlan(Strict):
    payee: Annotated[str, Field(min_length=1)]
    amount: str
    due_in_seconds: Annotated[int, Field(ge=1)]

    @field_validator("amount")
    @classmethod
    def _amount(cls, value: str) -> str:
        return _token_amount(value)


class WorkedExampleRow(Strict):
    instruction: Annotated[str, Field(min_length=1)]
    balance: str
    discretionary: str
    """D the contract must report before the request. Checked, never assumed."""
    obligations: tuple[ObligationPlan, ...]

    @field_validator("balance", "discretionary")
    @classmethod
    def _amount(cls, value: str) -> str:
        return _token_amount(value)


class CapsuleRow(Strict):
    attack_instruction: Annotated[str, Field(min_length=1)]
    attack_document: Annotated[str, Field(min_length=1)]
    replay_instruction: Annotated[str, Field(min_length=1)]
    replay_document: Annotated[str, Field(min_length=1)]


class SubstitutionRow(Strict):
    payee: Annotated[str, Field(min_length=1)]
    instruction: Annotated[str, Field(min_length=1)]
    document: Annotated[str, Field(min_length=1, pattern=r"\{account\}")]
    """``{account}`` is replaced by a fresh address that no one holds a key for."""


class RowPlans(Strict):
    E03: InstructionRow
    E04: ScheduleRow
    E05: InstructionRow
    E06: InstructionRow
    E07: InstructionRow
    E08: InstructionRow
    E09: DocumentRow
    E10: WorkedExampleRow
    E11: CapsuleRow
    E13: SubstitutionRow


class Funding(Strict):
    """Native amounts in ether for one network. Sized for a faucet grant on the test networks."""

    agent_before_top_up: str
    """What the agent of wallet A holds before E06. Must be below the profile's agent balance floor."""
    agent_working: str
    """What each agent is topped up to for the other rows (wallet A's agent only after E06)."""
    peer_owner: str
    registrar: str
    aggregator: str
    wallet_fee_reserve: str
    """Native fee reserve sent to wallet A, which pays the E06 top-up."""
    owner_spare: str
    """What the owner key must hold beyond the funding above, for deployment and its own transactions."""

    @field_validator("*")
    @classmethod
    def _amount(cls, value: str) -> str:
        return _native_amount(value)


class Timing(Strict):
    wait_margin_seconds: Annotated[int, Field(ge=1, le=60)]
    """Chain seconds past a delay's end before the run acts, so that the next block is clearly after it."""
    poll_seconds: Annotated[float, Field(gt=0, le=60)]
    progress_seconds: Annotated[float, Field(gt=0)]
    stall_seconds: Annotated[float, Field(gt=0)]
    """How long the chain may produce no new block during a wait before the run gives up."""


class EvidencePlan(Strict):
    profile: Annotated[str, Field(min_length=1)]
    mission: Annotated[str, Field(min_length=1, max_length=2_000)]
    payees: tuple[Annotated[str, Field(min_length=1)], ...]
    wallets: dict[str, WalletPlan]
    rows: RowPlans
    funding: dict[str, Funding]
    """Keyed by chain id as text."""
    local_owner_native: str
    """Native balance given to the generated owner key in the local self-test."""
    explorers: dict[str, str]
    network_names: dict[str, str]
    timing: Timing
    anvil_startup_seconds: Annotated[float, Field(gt=0)]

    @field_validator("wallets")
    @classmethod
    def _labels(cls, value: dict[str, WalletPlan]) -> dict[str, WalletPlan]:
        if tuple(sorted(value)) != WALLET_LABELS:
            raise ValueError(f"the plan must describe wallets {WALLET_LABELS}")
        return value

    def funding_for(self, chain_id: int) -> Funding:
        try:
            return self.funding[str(chain_id)]
        except KeyError:
            raise ValueError(f"the evidence plan has no funding for chain id {chain_id}") from None

    def explorer_for(self, chain_id: int, configured: str | None) -> str | None:
        """The explorer base URL: the one configured in the environment, or the plan's default for the chain."""
        base = configured or self.explorers.get(str(chain_id))
        return base.rstrip("/") if base else None

    def network_name(self, chain_id: int) -> str:
        return self.network_names.get(str(chain_id), f"chain {chain_id}")


class EvidenceText(Strict):
    """Wording of ``docs/EVIDENCE.md``. Every sentence a reader sees comes from here."""

    title: str
    intro: tuple[str, ...]
    contracts_heading: str
    contracts_columns: tuple[str, str]
    rows_heading: str
    rows_columns: tuple[str, str, str]
    setup_heading: str
    setup_intro: str
    setup_columns: tuple[str, str]
    model_mock: str
    model_live: str
    rows: dict[str, str]
    setup_steps: dict[str, str]

    @field_validator("rows")
    @classmethod
    def _every_row(cls, value: dict[str, str]) -> dict[str, str]:
        if tuple(sorted(value)) != ROW_IDS:
            raise ValueError("the evidence text must describe every row E01 to E14")
        return value


def load_plan() -> EvidencePlan:
    return load_model(EvidencePlan, "evidence/data/plan.json")


def load_text() -> EvidenceText:
    return load_model(EvidenceText, "evidence/data/text.json")
