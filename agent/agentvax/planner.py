"""The privileged planner.

The planner sees the owner's instruction, the mandate numbers, structured memory facts and typed readings of
documents. Every field of ``PlannerContext`` is either owner-trusted text (the instruction and payee names the
owner chose) or a number, enum or flag. Untrusted text has no field to travel in. The planner proposes an
``IntentDraft`` or asks one question. It authorises nothing: the validator checks every draft and the contract
decides.
"""

from __future__ import annotations

from collections.abc import Sequence
from enum import IntEnum
from typing import Annotated

from pydantic import Field, model_validator

from agentvax.llm.base import LanguageModel, Message, MessageRole, Role
from agentvax.llm.prompts import system_prompt
from agentvax.memory import PayeeFact
from agentvax.reader import AllowlistEntry, ReaderOutput
from agentvax.text import Strings
from agentvax.types import ScheduleTerms, Strict, Task, Uint32, Uint64, Uint256, WalletView
from agentvax.amounts import format_amount


class OwnerInstruction(Strict):
    """Text typed by the owner in an authenticated session. This is the only free text the planner sees."""

    text: str = Field(min_length=1, max_length=2000)


class MandateSummary(Strict):
    reserve: Uint256
    c1: Uint256
    d1: Uint256
    c2: Uint256
    fee_top_up_cap: Uint256
    balance: Uint256
    discretionary: Uint256


class PayeeName(Strict):
    name: str = Field(min_length=1, max_length=64)
    payee_id: Annotated[int, Field(ge=1, le=2**32 - 1)]


class ObligationFact(Strict):
    obligation_id: Annotated[int, Field(ge=1)]
    payee_id: Uint32
    amount: Uint256
    due: Uint64


class PlannerContext(Strict):
    instruction: OwnerInstruction
    now: Uint64
    mandate: MandateSummary
    allowlist: tuple[PayeeName, ...]
    obligations: tuple[ObligationFact, ...]
    memory: tuple[PayeeFact, ...]
    documents: tuple[ReaderOutput, ...]


def build_context(
    instruction: OwnerInstruction,
    view: WalletView,
    entries: Sequence[AllowlistEntry],
    memory: Sequence[PayeeFact],
    documents: Sequence[ReaderOutput],
) -> PlannerContext:
    """Assemble the planner's context from the wallet snapshot and the owner's allowlist. Only active payees are listed."""
    active = {p.payee_id for p in view.payees if p.active}
    mandate = view.mandate
    return PlannerContext(
        instruction=instruction,
        now=view.block_time,
        mandate=MandateSummary(
            reserve=mandate.reserve,
            c1=mandate.c1,
            d1=mandate.d1,
            c2=mandate.c2,
            fee_top_up_cap=mandate.fee_top_up_cap,
            balance=view.token_balance,
            discretionary=view.discretionary,
        ),
        allowlist=tuple(PayeeName(name=e.name, payee_id=e.payee_id) for e in entries if e.payee_id in active),
        obligations=tuple(
            ObligationFact(obligation_id=o.obligation_id, payee_id=o.payee_id, amount=o.amount, due=o.due)
            for o in view.obligations
        ),
        memory=tuple(memory),
        documents=tuple(documents),
    )


class ProvenanceKind(IntEnum):
    INSTRUCTION = 0
    MANDATE = 1
    READER = 2
    MEMORY = 3


class Provenance(Strict):
    """Where a value came from. ``MANDATE`` covers the mandate numbers and values read from the wallet, such as D.
    ``MEMORY`` may identify a payee only: the validator refuses an amount whose source is memory.
    ``index`` is the position of the document in the context and is required exactly for ``READER``."""

    kind: ProvenanceKind
    index: Annotated[int, Field(ge=0)] | None = None

    @model_validator(mode="after")
    def _index_matches_kind(self) -> Provenance:
        if (self.kind is ProvenanceKind.READER) != (self.index is not None):
            raise ValueError("an index is given exactly for a reader source")
        return self


class IntentDraft(Strict):
    """A proposal, not an authority. ``payee_label`` echoes the allowlist name of the payee and nothing else."""

    task: Task
    payee_id: Uint32
    payee_label: str | None = Field(default=None, max_length=64)
    amount: Uint256
    obligation_ref: Uint64 = 0
    schedule: ScheduleTerms | None = None
    amount_source: Provenance
    payee_source: Provenance


class QuestionCode(IntEnum):
    AMOUNT_MISSING = 1
    PAYEE_MISSING = 2
    PAYEE_AMBIGUOUS = 3
    AMOUNT_AMBIGUOUS = 4
    INSTRUCTION_UNCLEAR = 5
    NOTHING_TO_SAVE = 6
    SCHEDULE_UNCLEAR = 7
    """A recurring payment whose period, number of payments or start the owner did not state exactly once."""


class Question(Strict):
    """One clarifying question. The user sees a template from ``strings.json`` filled with these typed values."""

    code: QuestionCode
    payee_id: Uint32 | None = None
    amount: Uint256 | None = None
    candidates: tuple[Uint32, ...] = ()


class PlannerReply(Strict):
    """The wire form of a planner decision: exactly one of the two fields is set."""

    intent: IntentDraft | None = None
    question: Question | None = None

    @model_validator(mode="after")
    def _exactly_one(self) -> PlannerReply:
        if (self.intent is None) == (self.question is None):
            raise ValueError("a reply holds either an intent or a question")
        return self


PlannerDecision = IntentDraft | Question


def plan(llm: LanguageModel, context: PlannerContext) -> PlannerDecision:
    """Ask the planner model for a decision on ``context``. Raises ``LLMError`` on any failure."""
    messages = [
        Message(role=MessageRole.SYSTEM, content=system_prompt(Role.PLANNER)),
        Message(role=MessageRole.USER, content=context.model_dump_json()),
    ]
    reply = llm.complete(Role.PLANNER, messages, PlannerReply)
    return reply.intent if reply.intent is not None else reply.question  # type: ignore[return-value]


def question_text(strings: Strings, question: Question, context: PlannerContext) -> str:
    """The sentence shown to the owner for a question."""
    names = {p.payee_id: p.name for p in context.allowlist}
    payee = names.get(question.payee_id, "") if question.payee_id is not None else ""
    options = ", ".join(names[c] for c in question.candidates if c in names)
    amount = format_amount(question.amount) if question.amount is not None else ""
    return strings.render(f"question.{question.code.name.lower()}", payee=payee, options=options, amount=amount)
