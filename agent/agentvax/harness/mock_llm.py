"""``MockLLM``: a deterministic stand-in for a language model, driven by rule tables in ``harness/data/``.

It needs no network and is labelled ``mock`` wherever it is shown. Production modules never import it.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import datetime, timezone

from pydantic import BaseModel, Field

from agentvax.amounts import find_amounts, parse_amounts
from agentvax.llm.base import LLMError, Message, MessageRole, Role, T
from agentvax.mission import MissionReading, MissionRequest
from agentvax.names import find_names
from agentvax.planner import (
    IntentDraft,
    PlannerContext,
    PlannerReply,
    Provenance,
    ProvenanceKind,
    Question,
    QuestionCode,
)
from agentvax.reader import DocumentKind, ReaderReading, ReaderRequest
from agentvax.resources import load_model
from agentvax.schedules import mentions_recurrence, read_schedule
from agentvax.types import Flag, ScheduleTerms, Strict, Task
from agentvax.validator import contradicts_itself

_DATA = "harness/data/"
_MANDATE = Provenance(kind=ProvenanceKind.MANDATE)
_INSTRUCTION = Provenance(kind=ProvenanceKind.INSTRUCTION)


class _KindRule(Strict):
    kind: str
    patterns: tuple[str, ...]


class _ReaderRules(Strict):
    document_kinds: tuple[_KindRule, ...]
    flag_patterns: dict[str, tuple[str, ...]]
    encoded_patterns: tuple[str, ...]
    amount_markers: tuple[str, ...]
    marker_window: int = Field(gt=0)
    date_pattern: str


class _TaskRule(Strict):
    task: str
    patterns: tuple[str, ...]


class _PlannerRules(Strict):
    tasks: tuple[_TaskRule, ...]
    reference_patterns: tuple[str, ...]
    usual_amount_patterns: tuple[str, ...]


class _FieldRule(Strict):
    field: str
    kind: str
    patterns: tuple[str, ...]


class _MissionRules(Strict):
    amount_group: str
    duration_group: str
    duration_units: dict[str, int]
    fields: tuple[_FieldRule, ...]


def _matches_any(patterns: Sequence[str], text: str) -> bool:
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)


class MockLLM:
    """Implements the ``LanguageModel`` protocol by rules."""

    def __init__(self, data_dir: str = _DATA) -> None:
        self._reader = load_model(_ReaderRules, data_dir + "reader_rules.json")
        self._planner = load_model(_PlannerRules, data_dir + "planner_rules.json")
        self._mission = load_model(_MissionRules, data_dir + "mission_rules.json")

    def complete(self, role: Role, messages: Sequence[Message], schema: type[T]) -> T:
        user = next((m for m in reversed(messages) if m.role is MessageRole.USER), None)
        if user is None:
            raise LLMError("no user message")
        try:
            reply: BaseModel
            if role is Role.READER and schema is ReaderReading:
                reply = self._read(ReaderRequest.model_validate_json(user.content))
            elif role is Role.PLANNER and schema is PlannerReply:
                reply = self._plan(PlannerContext.model_validate_json(user.content))
            elif role is Role.MISSION and schema is MissionReading:
                reply = self._read_mission(MissionRequest.model_validate_json(user.content))
            else:
                raise LLMError(f"the mock has no rule for role {role.value} with schema {schema.__name__}")
        except ValueError as error:
            raise LLMError("the mock could not parse its input") from error
        if not isinstance(reply, schema):
            raise LLMError("the mock produced the wrong type")
        return reply

    # ----------------------------------------------------------------------------------------- reader

    def _read(self, request: ReaderRequest) -> ReaderReading:
        rules = self._reader
        text = request.content
        kind = DocumentKind.OTHER
        for rule in rules.document_kinds:
            if _matches_any(rule.patterns, text):
                kind = DocumentKind[rule.kind]
                break
        named = find_names(text, request.allowlist_names)
        flags = Flag.NONE
        for name, patterns in rules.flag_patterns.items():
            if _matches_any(patterns, text):
                flags |= Flag[name]
        without_addresses = re.sub(r"0x[0-9a-fA-F]{40}", " ", text)
        if any(re.search(p, without_addresses) for p in rules.encoded_patterns):
            flags |= Flag.ENCODED_CONTENT
        return ReaderReading(
            document_kind=kind,
            payee_index=named[0][0] if named else None,
            amount=self._document_amount(text),
            due=self._due(text),
            flags=int(flags),
        )

    def _document_amount(self, text: str) -> int | None:
        rules = self._reader
        found = find_amounts(text)
        marked = {
            m.value
            for m in found
            if any(
                marker in text[max(0, m.start - rules.marker_window) : m.start].lower()
                for marker in rules.amount_markers
            )
        }
        if len(marked) == 1:
            return next(iter(marked))
        distinct = {m.value for m in found}
        return next(iter(distinct)) if len(distinct) == 1 else None

    def _due(self, text: str) -> int | None:
        match = re.search(self._reader.date_pattern, text)
        if match is None:
            return None
        try:
            moment = datetime(int(match.group(1)), int(match.group(2)), int(match.group(3)), tzinfo=timezone.utc)
        except ValueError:
            return None
        return int(moment.timestamp())

    # ---------------------------------------------------------------------------------------- planner

    def _plan(self, ctx: PlannerContext) -> PlannerReply:
        """One intent only when the instruction fixes every field, otherwise one question. A recurring payment is
        read by ``agentvax.schedules``. An instruction that also says not to pay, or that asks for two different
        tasks, gets a question."""
        text = ctx.instruction.text
        if contradicts_itself(text):
            return _ask(QuestionCode.INSTRUCTION_UNCLEAR)
        matched = [Task[r.task] for r in self._planner.tasks if _matches_any(r.patterns, text)]
        others = sorted(set(matched) - {Task.PAYMENT})
        recurring = mentions_recurrence(text)
        if len(others) > 1 or (recurring and others):
            return _ask(QuestionCode.INSTRUCTION_UNCLEAR)
        if recurring:
            task: Task | None = Task.SCHEDULE_CREATE
        elif others:
            task = others[0]
        else:
            task = Task.PAYMENT if matched else None
        if task is None:
            return _ask(QuestionCode.INSTRUCTION_UNCLEAR)
        if task is Task.SWEEP:
            if ctx.mandate.discretionary == 0:
                return _ask(QuestionCode.NOTHING_TO_SAVE)
            return _draft(task, 0, None, ctx.mandate.discretionary, _MANDATE, _MANDATE)
        if task is Task.FEE_TOPUP:
            if ctx.mandate.fee_top_up_cap == 0:
                return _ask(QuestionCode.INSTRUCTION_UNCLEAR)
            return _draft(task, 0, None, ctx.mandate.fee_top_up_cap, _MANDATE, _MANDATE)
        return self._plan_payee_task(task, ctx)

    def _plan_payee_task(self, task: Task, ctx: PlannerContext) -> PlannerReply:
        rules = self._planner
        text = ctx.instruction.text
        names = [p.name for p in ctx.allowlist]
        by_id = {p.payee_id: p.name for p in ctx.allowlist}
        ids = sorted({ctx.allowlist[i].payee_id for i, _ in find_names(text, names)})
        refers = _matches_any(rules.reference_patterns, text)
        usual = _matches_any(rules.usual_amount_patterns, text)

        amounts = parse_amounts(text)
        payee_tag = _INSTRUCTION
        if len(ids) > 1:
            return _ask(QuestionCode.PAYEE_AMBIGUOUS, candidates=tuple(ids))
        if ids:
            payee_id = ids[0]
        else:
            options = [
                (i, d.payee_id)
                for i, d in enumerate(ctx.documents)
                if refers and d.payee_id is not None and d.payee_id in by_id
            ]
            remembered = sorted(
                {f.payee_id for f in ctx.memory if len(amounts) == 1 and f.usual_amount == amounts[0]} & set(by_id)
            )
            if len(options) == 1 and options[0][1] is not None:
                payee_id = options[0][1]
                payee_tag = Provenance(kind=ProvenanceKind.READER, index=options[0][0])
            elif not options and usual and len(remembered) == 1:
                payee_id, payee_tag = remembered[0], Provenance(kind=ProvenanceKind.MEMORY)
            else:
                return _ask(QuestionCode.PAYEE_MISSING)

        if len(amounts) > 1:
            return _ask(QuestionCode.AMOUNT_AMBIGUOUS, payee_id=payee_id)
        if amounts:
            amount, amount_tag = amounts[0], _INSTRUCTION
        else:
            docs = [
                (i, d.amount)
                for i, d in enumerate(ctx.documents)
                if refers and d.amount is not None and d.payee_id in (None, payee_id)
            ]
            if len(docs) == 1 and docs[0][1] is not None:
                amount, amount_tag = docs[0][1], Provenance(kind=ProvenanceKind.READER, index=docs[0][0])
            else:
                return _ask(QuestionCode.AMOUNT_MISSING, payee_id=payee_id)

        label = by_id[payee_id]
        if task is Task.SCHEDULE_CREATE:
            reading = read_schedule(text, ctx.now)
            if reading.terms is None:
                return _ask(QuestionCode.SCHEDULE_UNCLEAR, payee_id=payee_id)
            return _draft(task, payee_id, label, amount, amount_tag, payee_tag, schedule=reading.terms)
        obligation = next(
            (o.obligation_id for o in ctx.obligations if o.payee_id == payee_id and o.amount == amount), 0
        )
        return _draft(task, payee_id, label, amount, amount_tag, payee_tag, obligation_ref=obligation)

    # ---------------------------------------------------------------------------------------- mission

    def _read_mission(self, request: MissionRequest) -> MissionReading:
        rules = self._mission
        values: dict[str, int] = {}
        for rule in rules.fields:
            for pattern in rule.patterns:
                expanded = pattern.replace("{amount}", rules.amount_group).replace("{duration}", rules.duration_group)
                match = re.search(expanded, request.mission, re.IGNORECASE)
                if match is None:
                    continue
                if rule.kind == "amount":
                    parsed = parse_amounts(match.group("amount"))
                    if parsed:
                        values[rule.field] = parsed[0]
                else:
                    unit = match.group("unit").lower().rstrip("s")
                    values[rule.field] = int(match.group("number")) * rules.duration_units[unit]
                break
        return MissionReading(**values)


def _ask(code: QuestionCode, payee_id: int | None = None, candidates: tuple[int, ...] = ()) -> PlannerReply:
    return PlannerReply(question=Question(code=code, payee_id=payee_id, candidates=candidates))


def _draft(
    task: Task,
    payee_id: int,
    label: str | None,
    amount: int,
    amount_tag: Provenance,
    payee_tag: Provenance,
    obligation_ref: int = 0,
    schedule: ScheduleTerms | None = None,
) -> PlannerReply:
    return PlannerReply(
        intent=IntentDraft(
            task=task,
            payee_id=payee_id,
            payee_label=label,
            amount=amount,
            obligation_ref=obligation_ref,
            schedule=schedule,
            amount_source=amount_tag,
            payee_source=payee_tag,
        )
    )
