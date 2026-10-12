"""The deterministic validator. No model is called here.

It checks a planner draft against the schema, against provenance and against the wallet's state, and it sets the
flags that rules (not models) decide. A draft passes only if the amount can be traced to the owner's
instruction, to the mandate and wallet or to a reader field of a referenced document, and the
payee to one of those or to memory. Memory may identify a payee, which sets MEMORY_SOURCED, but it is never the
source of an amount.
"""

from __future__ import annotations

import re
from enum import IntEnum

from agentvax.amounts import parse_amounts
from agentvax.names import find_names
from agentvax.planner import IntentDraft, PlannerContext, Provenance, ProvenanceKind
from agentvax.reader import DestinationStatus, ReaderOutput
from agentvax.resources import load_model
from agentvax.schedules import read_schedule
from agentvax.text import Strings
from agentvax.types import (
    ZERO_BYTES32,
    Flag,
    Intent,
    ScheduleTerms,
    Strict,
    Task,
    WalletView,
)

_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")

_READER_FLAGS = (
    Flag.URGENCY | Flag.SECRECY | Flag.OVERRIDE_ATTEMPT | Flag.ENCODED_CONTENT | Flag.NEW_DESTINATION
)
"""The flags a reading may contribute. A reading can never claim a known identity, memory use or an anomaly."""

_PAYEELESS = (Task.SWEEP, Task.FEE_TOPUP)


class RejectionCode(IntEnum):
    SHAPE = 1
    RAW_ADDRESS = 2
    WALLET_FROZEN = 3
    UNKNOWN_PAYEE = 4
    INACTIVE_PAYEE = 5
    LABEL_MISMATCH = 6
    UNSOURCED_PAYEE = 7
    UNSOURCED_AMOUNT = 8
    OBLIGATION_MISMATCH = 9
    MALFORMED_SCHEDULE = 10
    INSUFFICIENT_BALANCE = 11
    UNSOURCED_SCHEDULE = 12
    """The draft's task or schedule terms are not the ones the instruction states (``agentvax.schedules``)."""
    CONTRADICTORY_INSTRUCTION = 13
    """The instruction also says not to pay or send, so no intent can be traced to it."""


class InstructionRules(Strict):
    negated_action_patterns: tuple[str, ...]


def contradicts_itself(text: str) -> bool:
    """True if the instruction also tells the agent not to pay, send or move money. Such an instruction never
    becomes an intent: the agent asks instead."""
    rules = load_model(InstructionRules, "data/instruction_rules.json")
    lowered = text.lower()
    return any(re.search(p, lowered) for p in rules.negated_action_patterns)


class Rejected(Strict):
    code: RejectionCode


class Validated(Strict):
    """A draft that passed. ``flags`` go on to the attestation step as additions."""

    intent: Intent
    flags: int
    schedule: ScheduleTerms | None


ValidationResult = Validated | Rejected


def _document(tag: Provenance, context: PlannerContext) -> ReaderOutput | None:
    if tag.kind is not ProvenanceKind.READER or tag.index is None or tag.index >= len(context.documents):
        return None
    return context.documents[tag.index]


def _shape_ok(draft: IntentDraft) -> bool:
    if draft.amount == 0:
        return False
    if draft.task in _PAYEELESS:
        return (
            draft.payee_id == 0
            and draft.payee_label is None
            and draft.obligation_ref == 0
            and draft.schedule is None
            and draft.payee_source.kind is ProvenanceKind.MANDATE
            and draft.amount_source.kind is ProvenanceKind.MANDATE
        )
    if draft.payee_id == 0:
        return False
    if draft.task is Task.SCHEDULE_CREATE:
        return draft.schedule is not None and draft.obligation_ref == 0
    return draft.schedule is None


def _payee_sourced(draft: IntentDraft, context: PlannerContext, name: str, obligation_payee: int | None) -> bool:
    tag = draft.payee_source
    if tag.kind is ProvenanceKind.INSTRUCTION:
        return bool(find_names(context.instruction.text, [name]))
    if tag.kind is ProvenanceKind.READER:
        document = _document(tag, context)
        return document is not None and document.payee_id == draft.payee_id
    if tag.kind is ProvenanceKind.MEMORY:
        return any(fact.payee_id == draft.payee_id for fact in context.memory)
    return obligation_payee is not None and obligation_payee == draft.payee_id


def _amount_sourced(draft: IntentDraft, context: PlannerContext, obligation_amount: int | None) -> bool:
    tag = draft.amount_source
    if tag.kind is ProvenanceKind.INSTRUCTION:
        return draft.amount in parse_amounts(context.instruction.text)
    if tag.kind is ProvenanceKind.READER:
        document = _document(tag, context)
        return (
            document is not None
            and document.amount == draft.amount
            and document.payee_id in (None, draft.payee_id)
        )
    if tag.kind is ProvenanceKind.MEMORY:
        return False
    if draft.task is Task.SWEEP:
        return draft.amount == context.mandate.discretionary
    if draft.task is Task.FEE_TOPUP:
        return draft.amount == context.mandate.fee_top_up_cap
    return obligation_amount is not None and obligation_amount == draft.amount


def validate_draft(draft: IntentDraft, context: PlannerContext, view: WalletView) -> ValidationResult:
    """Turn a draft into a ``Validated`` intent with flags, or say why it is rejected."""
    if _ADDRESS.search(draft.model_dump_json()):
        return Rejected(code=RejectionCode.RAW_ADDRESS)
    if not _shape_ok(draft):
        return Rejected(code=RejectionCode.SHAPE)
    if view.frozen:
        return Rejected(code=RejectionCode.WALLET_FROZEN)
    if contradicts_itself(context.instruction.text):
        return Rejected(code=RejectionCode.CONTRADICTORY_INSTRUCTION)

    name = ""
    payee_task = draft.task not in _PAYEELESS
    if payee_task:
        payee = view.payee(draft.payee_id)
        listed = next((p for p in context.allowlist if p.payee_id == draft.payee_id), None)
        if payee is None or listed is None:
            return Rejected(code=RejectionCode.UNKNOWN_PAYEE)
        if not payee.active:
            return Rejected(code=RejectionCode.INACTIVE_PAYEE)
        name = listed.name
        if draft.payee_label is not None and draft.payee_label != name:
            return Rejected(code=RejectionCode.LABEL_MISMATCH)

    obligation = None
    if draft.obligation_ref:
        obligation = next((o for o in view.obligations if o.obligation_id == draft.obligation_ref), None)
        if obligation is None or obligation.payee_id != draft.payee_id:
            return Rejected(code=RejectionCode.OBLIGATION_MISMATCH)

    if payee_task and not _payee_sourced(draft, context, name, obligation.payee_id if obligation else None):
        return Rejected(code=RejectionCode.UNSOURCED_PAYEE)
    if not _amount_sourced(draft, context, obligation.amount if obligation else None):
        return Rejected(code=RejectionCode.UNSOURCED_AMOUNT)

    if draft.schedule is not None and (
        draft.schedule.period < view.min_schedule_period or draft.schedule.first_due < view.block_time
    ):
        return Rejected(code=RejectionCode.MALFORMED_SCHEDULE)
    stated = read_schedule(context.instruction.text, context.now)
    if draft.task is Task.SCHEDULE_CREATE and (stated.terms is None or draft.schedule != stated.terms):
        return Rejected(code=RejectionCode.UNSOURCED_SCHEDULE)
    if draft.task is Task.PAYMENT and stated.recurring:
        return Rejected(code=RejectionCode.UNSOURCED_SCHEDULE)

    available = view.native_balance if draft.task is Task.FEE_TOPUP else view.token_balance
    if draft.amount > available:
        return Rejected(code=RejectionCode.INSUFFICIENT_BALANCE)

    flags = Flag.NONE
    if payee_task:
        flags |= Flag.KNOWN_PAYEE_IDENTITY
    tags = (draft.payee_source, draft.amount_source)
    if any(tag.kind is ProvenanceKind.MEMORY for tag in tags):
        flags |= Flag.MEMORY_SOURCED
    used = {tag.index for tag in tags if tag.kind is ProvenanceKind.READER and tag.index is not None}
    used |= {i for i, d in enumerate(context.documents) if payee_task and d.payee_id == draft.payee_id}
    for index in sorted(used):
        document = context.documents[index]
        flags |= Flag(document.flags) & _READER_FLAGS
        if document.destination is DestinationStatus.DIFFERS_FROM_ALLOWLIST:
            flags |= Flag.NEW_DESTINATION

    intent = Intent(
        task=draft.task,
        payee_id=draft.payee_id,
        amount=draft.amount,
        schedule_id=draft.obligation_ref,
        purpose_hash=draft.schedule.purpose_hash() if draft.schedule else ZERO_BYTES32,
        nonce=view.nonce,
    )
    return Validated(intent=intent, flags=int(flags), schedule=draft.schedule)


def rejection_text(strings: Strings, rejection: Rejected) -> str:
    """The sentence shown to the owner for a rejection."""
    return strings.render(f"rejection.{rejection.code.name.lower()}")
