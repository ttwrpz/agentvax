"""The evaluation summary, as written to ``results/summary.<mode>.json``.

The model is strict. ``mode`` is ``mock`` or ``live``. Every value is reduced from the ledger by
``agentvax.eval.ledger.reduce``.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from agentvax.eval.suites_schema import FamilyName

Count = Annotated[int, Field(ge=0)]
Rate = Annotated[float, Field(ge=0.0, le=1.0)]


class SummaryModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class TaskSuiteSummary(SummaryModel):
    n: Count
    success: Count
    wrong_executions: Count
    ambiguous_n: Count
    ambiguous_handled: Count


class AffordabilitySummary(SummaryModel):
    n: Count
    agree: Count


class VaxlabSummary(SummaryModel):
    families: tuple[FamilyName, ...]
    attacks: Count
    reworded_attacks: Count
    unauthorized_tx: Count
    value_beyond_l1: Count
    reworded_matched_rate: Rate


class ProbingSummary(SummaryModel):
    sequence_length: Count
    odd_executed_before_owner: Count
    within_allowance: bool


class PanickedOwnerSummary(SummaryModel):
    prompts_approved: Count
    value_left_before_delay: Count


class CapsuleSummary(SummaryModel):
    tx_before_restriction: Count
    non_applicable_unrestricted: bool
    false_capsule_loosened: Count
    false_capsule_max_restriction: Annotated[int, Field(ge=0, le=3)]
    autonomy_returned_after_expiry: bool


class FrictionSummary(SummaryModel):
    new_payee_wait_seconds: Count
    pressure_hold_seconds: Count
    allowance_recovery_seconds: Count


class GasStat(SummaryModel):
    """Gas used by mined, successful transactions to one entry point during observed case steps."""

    count: Count
    median: Count
    p95: Count


class Summary(SummaryModel):
    mode: Literal["mock", "live"]
    hard_policy_violations: Count
    safe_autonomy_rate: Rate
    escalation_rate: Rate
    detector_fpr: Rate
    task_suite: TaskSuiteSummary
    affordability: AffordabilitySummary
    vaxlab: VaxlabSummary
    probing: ProbingSummary
    panicked_owner: PanickedOwnerSummary
    capsule: CapsuleSummary
    friction: FrictionSummary
    gas: dict[str, GasStat]
    """Keyed by entry point: a wallet function by name (``submit``, ``executePending``), a function of another
    contract prefixed with it (``bulletin.attest``)."""

    def to_json(self) -> str:
        return self.model_dump_json(indent=2) + "\n"
