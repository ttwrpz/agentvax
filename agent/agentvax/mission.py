"""Mission text to a proposed mandate.

The mission model only reads numbers out of the owner's words. Deterministic bounds checks decide whether the
result is acceptable. The mandate is shown back to the owner and nothing here can write it to the chain: a write
needs an ``OwnerSignedMandate``, which carries a signature only the owner's signer can make. This module holds no
key and cannot sign.
"""

from __future__ import annotations

from enum import IntEnum
from typing import Protocol

from eth_abi import encode as abi_encode
from eth_account import Account
from eth_account.messages import SignableMessage, encode_defunct
from eth_keys.exceptions import BadSignature
from eth_utils import keccak
from pydantic import Field, model_validator

from agentvax.amounts import format_amount
from agentvax.config import MandateTemplate
from agentvax.llm.base import LanguageModel, Message, MessageRole, Role
from agentvax.llm.prompts import system_prompt
from agentvax.text import Strings, describe_duration
from agentvax.types import (
    ALLOWED_CHAIN_IDS,
    Address,
    Bytes32,
    Mandate,
    Strict,
    Uint64,
    Uint256,
)

MAX_DELAY = 30 * 86_400
MAX_LOOSENING_DELAY = 30 * 86_400
MAX_PRESSURE_HOLD = 7 * 86_400
"""The bounds of ``MandateRules`` in the wallet contract."""

_ABI_TYPES = [
    "uint256",
    "uint256",
    "uint256",
    "uint256",
    "uint64",
    "uint64",
    "uint64",
    "uint64",
    "uint64",
    "uint64",
    "uint32",
    "uint8",
    "uint8",
    "uint8",
    "uint8",
    "uint8",
    "uint8",
    "uint256",
    "uint256",
    "uint256",
    "uint256",
]


class MissionProblem(IntEnum):
    LIMITS_OUT_OF_ORDER = 1
    DELAY_OUT_OF_RANGE = 2
    LOOSENING_DELAY_OUT_OF_RANGE = 3
    HOLD_OUT_OF_RANGE = 4
    NOT_OWNER_SIGNED = 5
    UNSUPPORTED_CHAIN = 6
    WRONG_TARGET = 7


class MissionError(Exception):
    """A proposed mandate is out of bounds or a write was attempted without the owner's signature."""

    def __init__(self, problem: MissionProblem) -> None:
        super().__init__(problem.name)
        self.problem = problem


class MissionRequest(Strict):
    mission: str = Field(min_length=1, max_length=4000)


class MissionReading(Strict):
    """What the mission model returns. Amounts in base units, durations in seconds, null when not stated."""

    reserve: Uint256 | None = None
    c1: Uint256 | None = None
    d1: Uint256 | None = None
    c2: Uint256 | None = None
    delay: Uint64 | None = None
    loosening_delay: Uint64 | None = None
    pressure_hold: Uint64 | None = None


def mandate_hash(mission: str, mandate: Mandate) -> str:
    """``keccak256(abi.encode(keccak256(bytes(mission)), mandate))``, exactly as the wallet contract computes it.

    The mandate struct has only static fields, so it is encoded in place after the mission hash.
    """
    encoded = abi_encode(["bytes32", *_ABI_TYPES], [keccak(text=mission), *mandate.as_tuple()])
    return "0x" + keccak(encoded).hex()


class MandateProposal(Strict):
    mission: str
    mandate: Mandate
    mandate_hash: Bytes32

    @model_validator(mode="after")
    def _hash_matches(self) -> MandateProposal:
        if self.mandate_hash != mandate_hash(self.mission, self.mandate):
            raise ValueError("the mandate hash does not match the mission and the mandate")
        return self


def check_bounds(mandate: Mandate) -> None:
    """Raise ``MissionError`` unless the mandate is ordered and within the contract's bounds."""
    if mandate.c1 > mandate.c2 or mandate.c1 > mandate.d1:
        raise MissionError(MissionProblem.LIMITS_OUT_OF_ORDER)
    if not 0 < mandate.delay <= MAX_DELAY:
        raise MissionError(MissionProblem.DELAY_OUT_OF_RANGE)
    if not 0 < mandate.loosening_delay <= MAX_LOOSENING_DELAY:
        raise MissionError(MissionProblem.LOOSENING_DELAY_OUT_OF_RANGE)
    if not 0 < mandate.pressure_hold <= MAX_PRESSURE_HOLD:
        raise MissionError(MissionProblem.HOLD_OUT_OF_RANGE)


def propose_mandate(llm: LanguageModel, mission: str, now: int, template: MandateTemplate) -> MandateProposal:
    """Read ``mission`` through the mission model and build a proposal. Unstated fields take their value from
    ``template``, the mandate of the deployment profile (see ``agentvax.config.load_profile``)."""
    request = MissionRequest(mission=mission)
    messages = [
        Message(role=MessageRole.SYSTEM, content=system_prompt(Role.MISSION)),
        Message(role=MessageRole.USER, content=request.model_dump_json()),
    ]
    reading = llm.complete(Role.MISSION, messages, MissionReading)
    fields = template.mandate(now).model_dump()
    fields.update({name: value for name, value in reading.model_dump().items() if value is not None})
    mandate = Mandate(**fields)
    check_bounds(mandate)
    return MandateProposal(mission=mission, mandate=mandate, mandate_hash=mandate_hash(mission, mandate))


def show_back(strings: Strings, proposal: MandateProposal) -> tuple[str, ...]:
    """The mandate in plain sentences, for the owner to read before signing."""
    m = proposal.mandate
    return (
        strings.render("mandate.reserve", amount=format_amount(m.reserve)),
        strings.render("mandate.c1", amount=format_amount(m.c1)),
        strings.render("mandate.d1", amount=format_amount(m.d1)),
        strings.render("mandate.c2", amount=format_amount(m.c2), delay=describe_duration(strings, m.delay)),
        strings.render("mandate.loosening", delay=describe_duration(strings, m.loosening_delay)),
        strings.render("mandate.pressure_hold", delay=describe_duration(strings, m.pressure_hold)),
        strings.render("mandate.hash", digest=proposal.mandate_hash),
    )


def signing_message(proposal: MandateProposal, wallet: str, chain_id: int) -> SignableMessage:
    """The message the owner's signer signs to approve writing ``proposal`` to ``wallet`` on ``chain_id``."""
    if chain_id not in ALLOWED_CHAIN_IDS:
        raise MissionError(MissionProblem.UNSUPPORTED_CHAIN)
    digest = keccak(
        abi_encode(["bytes32", "address", "uint256"], [bytes.fromhex(proposal.mandate_hash[2:]), wallet, chain_id])
    )
    return encode_defunct(primitive=digest)


class OwnerSignedMandate(Strict):
    """A proposal with the owner's signature. Only an owner signer can produce the signature field."""

    proposal: MandateProposal
    wallet: Address
    chain_id: int
    owner: Address
    signature: str = Field(pattern=r"^0x[0-9a-fA-F]{130}$")


class MandateSink(Protocol):
    """Writes a mandate to one wallet on one chain. ``agentvax.chain.owner.OwnerMandateSink`` is the production
    sink: it sends ``setMandate`` signed by the owner's signer."""

    @property
    def wallet(self) -> str: ...

    @property
    def chain_id(self) -> int: ...

    def set_mandate(self, mandate: Mandate, mission: str) -> None:
        """Write the mandate to the wallet."""
        ...


class MandatePublisher:
    """Passes a mandate to the sink only when the owner's signature checks out and names the sink's wallet and
    chain."""

    def __init__(self, sink: MandateSink, owner: str) -> None:
        self._sink = sink
        self._owner = owner.lower()

    def publish(self, signed: OwnerSignedMandate) -> None:
        if signed.wallet.lower() != self._sink.wallet.lower() or signed.chain_id != self._sink.chain_id:
            raise MissionError(MissionProblem.WRONG_TARGET)
        if signed.owner.lower() != self._owner:
            raise MissionError(MissionProblem.NOT_OWNER_SIGNED)
        message = signing_message(signed.proposal, signed.wallet, signed.chain_id)
        try:
            recovered = Account.recover_message(message, signature=signed.signature)
        except (ValueError, TypeError, BadSignature) as error:
            raise MissionError(MissionProblem.NOT_OWNER_SIGNED) from error
        if recovered.lower() != self._owner:
            raise MissionError(MissionProblem.NOT_OWNER_SIGNED)
        self._sink.set_mandate(signed.proposal.mandate, signed.proposal.mission)


def problem_text(strings: Strings, error: MissionError) -> str:
    """The sentence shown to the owner for a mission problem."""
    return strings.render(f"mission.problem.{error.problem.name.lower()}")
