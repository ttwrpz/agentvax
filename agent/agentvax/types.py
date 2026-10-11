"""Primitives shared by every AgentVax module.

These mirror the on-chain types in ``contracts/src/lib/AgentVaxTypes.sol``. Numeric values are part of the
external interface (EIP-712 fields, capsule fields) and never change. Models that belong to one boundary,
such as reader output or planner decisions, live with the module that owns that boundary.
"""

from __future__ import annotations

from enum import IntEnum, IntFlag
from typing import Annotated

from eth_utils import keccak
from pydantic import BaseModel, ConfigDict, Field
from eth_abi import encode as abi_encode

UINT8_MAX = 2**8 - 1
UINT16_MAX = 2**16 - 1
UINT32_MAX = 2**32 - 1
UINT64_MAX = 2**64 - 1
UINT256_MAX = 2**256 - 1

Uint8 = Annotated[int, Field(ge=0, le=UINT8_MAX)]
Uint16 = Annotated[int, Field(ge=0, le=UINT16_MAX)]
Uint32 = Annotated[int, Field(ge=0, le=UINT32_MAX)]
Uint64 = Annotated[int, Field(ge=0, le=UINT64_MAX)]
Uint256 = Annotated[int, Field(ge=0, le=UINT256_MAX)]
Address = Annotated[str, Field(pattern=r"^0x[0-9a-fA-F]{40}$")]
Bytes32 = Annotated[str, Field(pattern=r"^0x[0-9a-fA-F]{64}$")]

TOKEN_DECIMALS = 6
TOKEN_UNIT = 10**TOKEN_DECIMALS

ALLOWED_CHAIN_IDS: frozenset[int] = frozenset({31337, 84532, 11155111})
"""Anvil, Base Sepolia, Sepolia. Every sending path refuses any other chain id."""

EIP712_NAME = "AgentVax PolicyWallet"
EIP712_VERSION = "1"

INTENT_TYPE = "Intent(uint8 task,uint32 payeeId,uint256 amount,uint64 scheduleId,bytes32 purposeHash,uint256 nonce)"
ATTESTATION_TYPE = "Attestation(bytes32 intentHash,uint8 band,uint8 source,uint16 flags,uint64 validUntil)"
SCHEDULE_TERMS_TYPE = "ScheduleTerms(uint64 period,uint64 firstDue,uint32 maxRuns)"

MAX_ATTESTATION_TTL = 15 * 60
"""Mirrors ``IntentLogic.MAX_ATTESTATION_TTL``: the contract refuses an attestation whose ``validUntil`` lies more
than this many seconds after the block it is submitted in. The constant is internal to the library, so it is
mirrored here like the other interface values in this module."""


class Strict(BaseModel):
    """Base for every boundary model: no coercion, no unknown fields, immutable."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class Task(IntEnum):
    PAYMENT = 1
    SCHEDULE_CREATE = 2
    SWEEP = 3
    FEE_TOPUP = 4


class CapsuleAction(IntEnum):
    PAYMENT = 1
    SCHEDULE_CREATE = 2
    SWEEP = 3
    PAYEE_OR_MANDATE_CHANGE = 4


class Band(IntEnum):
    LOW = 0
    MEDIUM = 1
    HIGH = 2


class Source(IntEnum):
    OWNER_INSTRUCTION = 0
    EXTERNAL_CONTENT = 1


class Tier(IntEnum):
    L1 = 1
    L2 = 2
    L3 = 3


class DecidingCheck(IntEnum):
    ALLOWED = 1
    AFFORDABLE = 2
    SAFE_NOW = 3
    ALLOWANCE = 4


class Family(IntEnum):
    DIRECT = 1
    INDIRECT = 2
    MEMORY = 3
    ENCODED = 4
    RECIPIENT_SUBSTITUTION = 5


class Channel(IntEnum):
    """Bit index of a channel in the capsule ``channel`` field and the wallet channel profile."""

    OWNER_CHAT = 0
    WEB_PAGE = 1
    MESSAGE = 2
    MEMORY = 3
    TOKEN_METADATA = 4


class Flag(IntFlag):
    NONE = 0
    KNOWN_PAYEE_IDENTITY = 1 << 0
    NEW_DESTINATION = 1 << 1
    URGENCY = 1 << 2
    SECRECY = 1 << 3
    OVERRIDE_ATTEMPT = 1 << 4
    ENCODED_CONTENT = 1 << 5
    AMOUNT_ANOMALY = 1 << 6
    MEMORY_SOURCED = 1 << 7


PRESSURE_FLAGS = Flag.URGENCY | Flag.SECRECY | Flag.OVERRIDE_ATTEMPT
ALL_FLAGS = Flag(0xFF)


class Mandate(Strict):
    """The owner's mandate, field for field as in the contract. Token amounts in base units, durations in seconds."""

    reserve: Uint256
    c1: Uint256
    d1: Uint256
    c2: Uint256
    delay: Uint64
    loosening_delay: Uint64
    pressure_hold: Uint64
    refill_period: Uint64
    horizon: Uint64
    expiry: Uint64
    allowance_max: Uint32
    channel_profile: Annotated[int, Field(ge=0, le=0x1F)]
    charge_external: Uint8
    charge_over_half_d: Uint8
    charge_anomaly: Uint8
    charge_first_payment: Uint8
    charge_partial_capsule: Uint8
    fee_top_up_cap: Uint256
    fee_daily_budget: Uint256
    agent_balance_floor: Uint256
    native_reserve: Uint256

    def as_tuple(self) -> tuple[int, ...]:
        """ABI tuple in contract field order."""
        return tuple(getattr(self, name) for name in type(self).model_fields)


class ScheduleTerms(Strict):
    period: Uint64
    first_due: Uint64
    max_runs: Annotated[int, Field(ge=1, le=UINT32_MAX)]

    def as_tuple(self) -> tuple[int, int, int]:
        return (self.period, self.first_due, self.max_runs)

    def purpose_hash(self) -> str:
        """``keccak256(abi.encode(SCHEDULE_TERMS_TYPEHASH, period, firstDue, maxRuns))``, as the contract computes."""
        typehash = keccak(text=SCHEDULE_TERMS_TYPE)
        encoded = abi_encode(["bytes32", "uint64", "uint64", "uint32"], [typehash, *self.as_tuple()])
        return "0x" + keccak(encoded).hex()


ZERO_BYTES32 = "0x" + "00" * 32


class Intent(Strict):
    """The EIP-712 intent the agent submits. For PAYMENT, ``schedule_id`` is a 1-based obligation reference."""

    task: Task
    payee_id: Uint32
    amount: Uint256
    schedule_id: Uint64
    purpose_hash: Bytes32
    nonce: Uint256

    def as_tuple(self) -> tuple[int, int, int, int, bytes, int]:
        return (
            int(self.task),
            self.payee_id,
            self.amount,
            self.schedule_id,
            bytes.fromhex(self.purpose_hash[2:]),
            self.nonce,
        )


class Attestation(Strict):
    """The EIP-712 attestation the guardian signs."""

    intent_hash: Bytes32
    band: Band
    source: Source
    flags: Uint16
    valid_until: Uint64

    def as_tuple(self) -> tuple[bytes, int, int, int, int]:
        return (
            bytes.fromhex(self.intent_hash[2:]),
            int(self.band),
            int(self.source),
            self.flags,
            self.valid_until,
        )


class Capsule(Strict):
    """An immunity capsule as stored in the bulletin."""

    family: Family
    channel: Channel
    features: Uint16
    action: CapsuleAction
    restriction: Annotated[int, Field(ge=2, le=3)]
    expiry: Uint64
    guard_version: Uint32
    issuer: Address
    attestations: Uint8


class DecisionEvent(Strict):
    """The ``Decision`` event emitted by the wallet for every decision."""

    intent_hash: Bytes32
    tier: Tier
    deciding_check: DecidingCheck
    capsule_id: Uint256


class PayeeView(Strict):
    """A payee as read from the wallet. ``payee_id`` is 1-based."""

    payee_id: Annotated[int, Field(ge=1, le=UINT32_MAX)]
    identity_hash: Bytes32
    account: Address
    active: bool
    paid_count: Uint32
    max_paid: Uint256


class ObligationView(Strict):
    """An open obligation as read from the wallet. ``obligation_id`` is 1-based."""

    obligation_id: Annotated[int, Field(ge=1, le=UINT64_MAX)]
    payee_id: Uint32
    amount: Uint256
    due: Uint64
    schedule_id: Uint64
    by_agent: bool


class WalletView(Strict):
    """A read-only snapshot of one wallet, produced by the chain client and consumed by the validator,
    the planner context, the explanations and the interface. Every number here is read from the chain."""

    chain_id: int
    wallet: Address
    block_time: Uint64
    nonce: Uint256
    token_balance: Uint256
    native_balance: Uint256
    agent_native_balance: Uint256
    discretionary: Uint256
    allowance_points: Annotated[float, Field(ge=0)]
    frozen: bool
    min_schedule_period: Uint64
    """``Ledger.MIN_SCHEDULE_PERIOD`` read from the wallet, so the validator never keeps its own copy."""
    mandate: Mandate
    mandate_hash: Bytes32
    payees: tuple[PayeeView, ...]
    obligations: tuple[ObligationView, ...]

    def payee(self, payee_id: int) -> PayeeView | None:
        return next((p for p in self.payees if p.payee_id == payee_id), None)
