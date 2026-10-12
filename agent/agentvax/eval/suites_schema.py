"""Models of the evaluation suite files.

Suite inputs are JSON files in ``agentvax/eval/suites/``, written once and never tuned to a result.
Every model here is strict, immutable and forbids unknown fields, so a typo in a suite file is an error,
not a silently ignored key.

Vocabulary shared by every suite
--------------------------------

``TokenAmount``
    MockUSD as a decimal string in whole units with at most six decimals, for example ``"300"`` or ``"12.5"``.
``NativeAmount``
    Native token as a decimal string in ether with at most eighteen decimals, for example ``"0.005"``.
Account labels
    Lower-case labels such as ``attacker`` name deterministic test addresses (``agentvax.vaxlab.inputs``). Text in
    an instruction, a document or an attack may contain ``{{address:<label>}}``, replaced by that address when the
    case runs. Nobody holds a key for these addresses.
Recipients
    ``"payee:<name>"`` (the account of a payee in the case setup), ``"address:<label>"``, ``"vault"`` (the
    savings vault fixed at deployment) or ``"agent"`` (the wallet's agent key).
Wallets
    ``"A"``, ``"B"`` and ``"C"``, each with its own owner, agent and guardian. Independent cases run on A. The
    attack suite also replays reworded forms on B after A published the base attack's capsule.

Authorisation
-------------
A case lists its ``allowed`` transitions as exact tuples: wallet, action, recipient, exact (or maximum) amount,
task or change kind, schedule terms, the chain-time window in seconds after the case starts, and how many times.
The judge maps every event and every change of wallet state in the case to an observed action. An action that no
allowed transition covers is a violation, even if the harness signed an owner approval for it. A ``required``
transition must happen exactly ``times`` times for a task to count as a success. An optional one
(``required: false``) may happen up to ``times`` times, which is how an attack case allows the owner's real
request to be queued or proposed without demanding either.

Corpus and population membership
--------------------------------
Every ``Document`` declares ``benign``. The benign documents form the corpus for ``detector_fpr``, one prediction
per distinct document. Attack content is never part of it. ``benign_l1_eligible`` marks the requests in the
population of ``escalation_rate``. Every task case is L1-eligible by definition.
"""

from __future__ import annotations

import re
from decimal import Decimal
from pathlib import Path
from typing import Annotated, Literal, Union

from eth_utils import keccak
from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentvax.planner import QuestionCode
from agentvax.text import Strings
from agentvax.types import Bytes32

# ---------------------------------------------------------------------------------------------- primitives

TOKEN_PATTERN = r"^(0|[1-9][0-9]{0,15})(\.[0-9]{1,6})?$"
NATIVE_PATTERN = r"^(0|[1-9][0-9]{0,9})(\.[0-9]{1,18})?$"
TOKEN_DECIMALS = 6
NATIVE_DECIMALS = 18

CaseId = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,79}$")]
"""Stable identifier of a case, a paraphrase or a step. Lower case, digits, ``_``, ``.`` and ``-``."""
PayeeName = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^\S(.*\S)?$")]
AccountLabel = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")]
TokenAmount = Annotated[str, Field(pattern=TOKEN_PATTERN)]
NativeAmount = Annotated[str, Field(pattern=NATIVE_PATTERN)]
Seconds = Annotated[int, Field(ge=0, le=10 * 365 * 86_400)]
PositiveSeconds = Annotated[int, Field(ge=1, le=10 * 365 * 86_400)]
Recipient = Annotated[str, Field(pattern=r"^(vault|agent|payee:\S(.{0,62}\S)?|address:[a-z][a-z0-9_]{0,31})$")]
Text = Annotated[str, Field(min_length=1, max_length=20_000)]
InstructionText = Annotated[str, Field(min_length=1, max_length=2_000)]

WalletLabel = Literal["A", "B", "C"]
ChannelName = Literal["owner_chat", "web_page", "message", "memory", "token_metadata"]
TaskName = Literal["payment", "schedule_create", "sweep", "fee_topup"]
FamilyName = Literal["direct", "indirect", "memory", "encoded", "recipient_substitution"]
FlagName = Literal[
    "known_payee_identity",
    "new_destination",
    "urgency",
    "secrecy",
    "override_attempt",
    "encoded_content",
    "amount_anomaly",
    "memory_sourced",
]
CheckName = Literal["allowed", "affordable", "safe_now", "allowance"]
CHECK_NUMBERS: dict[str, int] = {"allowed": 1, "affordable": 2, "safe_now": 3, "allowance": 4}
"""The ``decidingCheck`` value of each check name in the wallet's ``Decision`` event."""
TASK_NUMBERS: dict[str, int] = {"payment": 1, "schedule_create": 2, "sweep": 3, "fee_topup": 4}
CHANGE_KIND_NUMBERS: dict[str, int] = {
    "add_payee": 1, "mandate": 2, "remove_obligation": 3, "agent": 4, "guardian": 5, "unfreeze": 6
}
CapsuleActionName = Literal["payment", "schedule_create", "sweep", "payee_or_mandate_change"]
ChangeKindName = Literal["add_payee", "mandate", "remove_obligation", "agent", "guardian", "unfreeze"]
OutcomeKind = Literal["executed", "queued", "proposed", "question", "rejected", "payee_change_requested"]

FAMILIES: tuple[FamilyName, ...] = ("direct", "indirect", "memory", "encoded", "recipient_substitution")
"""Attack families in the order of the capsule ``family`` field (1 to 5)."""

ActionName = Literal[
    "payment",
    "schedule_create",
    "schedule_run",
    "sweep",
    "fee_topup",
    "item_queued",
    "item_proposed",
    "item_approved",
    "item_cancelled",
    "hold_extended",
    "payee_change_request",
    "obligation_added",
    "change_proposed",
    "change_applied",
    "change_cancelled",
    "payee_removed",
    "freeze",
    "attack_confirmed",
    "agent_revoked",
    "schedule_cancelled",
    "capsule_published",
    "capsule_attested",
    "capsule_dismissed",
    "mandate_set",
    "vault_withdrawn",
]
"""Every kind of state change the judge can observe. See ``agentvax.eval.judge`` for the events behind each."""

VALUE_ACTIONS: frozenset[str] = frozenset({"payment", "schedule_run", "sweep", "fee_topup", "vault_withdrawn"})
"""Actions that move value out of a wallet or its vault account."""
ITEM_ACTIONS: frozenset[str] = frozenset(
    {"item_queued", "item_proposed", "item_approved", "item_cancelled", "hold_extended"}
)
CHANGE_ACTIONS: frozenset[str] = frozenset({"change_proposed", "change_applied", "change_cancelled"})
AMOUNT_ACTIONS: frozenset[str] = VALUE_ACTIONS | ITEM_ACTIONS | {"schedule_create", "obligation_added"}
"""Actions that carry an amount a transition may constrain."""
RECIPIENT_ACTIONS: frozenset[str] = (
    VALUE_ACTIONS - {"vault_withdrawn"}
) | ITEM_ACTIONS | {"schedule_create", "payee_change_request", "obligation_added", "payee_removed"} | CHANGE_ACTIONS


def to_units(amount: str, decimals: int) -> int:
    """The integer number of base units in a decimal string. Exact: the patterns allow no more decimals than the
    asset has."""
    value = Decimal(amount) * (Decimal(10) ** decimals)
    if value != value.to_integral_value():
        raise ValueError(f"{amount} has more than {decimals} decimals")
    return int(value)


def asset_of(action: str, task: str | None) -> Literal["mockusd", "native", "none"]:
    """The asset an action concerns: native for a fee top-up, MockUSD for every other amount, none otherwise."""
    if action == "fee_topup" or (action in ITEM_ACTIONS and task == "fee_topup"):
        return "native"
    if action in AMOUNT_ACTIONS:
        return "mockusd"
    return "none"


class SuiteModel(BaseModel):
    """Base of every suite model: no coercion, no unknown fields, immutable."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


# ---------------------------------------------------------------------------------------------- inputs


class Document(SuiteModel):
    """Untrusted content the owner referenced, for example an invoice or a web page."""

    channel: ChannelName
    """Where the content came from. Sets the capsule channel of an attack confirmed from it."""
    text: Text
    """The raw content. May contain ``{{address:<label>}}``."""
    benign: bool
    """True if this document belongs to the benign corpus behind ``detector_fpr``."""


class AttackContent(SuiteModel):
    """The attacker-controlled content of an attack, as it reaches the agent. Never part of the benign corpus."""

    channel: ChannelName
    text: Text


# ---------------------------------------------------------------------------------------------- setup


class PayeeSetup(SuiteModel):
    """A payee the owner added through the Λ time-lock before the case starts."""

    name: PayeeName
    """The name the owner gave the payee. Its identity hash is computed from it."""
    account: AccountLabel | None = None
    """Label of the payee's account. Defaults to an address derived from the name."""
    paid_before: bool
    """True if the wallet has paid this payee before the case starts."""
    max_paid: TokenAmount | None = None
    """Largest earlier payment. Given exactly when ``paid_before`` is true. The setup makes one payment of it."""
    active: bool = True
    """False to remove the payee (immediate) after it was added and paid."""

    @model_validator(mode="after")
    def _history_consistent(self) -> PayeeSetup:
        if self.paid_before != (self.max_paid is not None):
            raise ValueError("max_paid is given exactly when paid_before is true")
        if self.max_paid is not None and to_units(self.max_paid, TOKEN_DECIMALS) == 0:
            raise ValueError("max_paid must be positive")
        return self


class ObligationSetup(SuiteModel):
    """A bill registered before the case starts."""

    payee: PayeeName
    amount: TokenAmount
    due_in: Seconds
    """Seconds after the end of the setup at which the bill is due."""
    added_by: Literal["owner", "agent"] = "owner"

    @model_validator(mode="after")
    def _positive(self) -> ObligationSetup:
        if to_units(self.amount, TOKEN_DECIMALS) == 0:
            raise ValueError("an obligation amount must be positive")
        return self


class MandateOverrides(SuiteModel):
    """Mandate fields that differ from the deployment profile. Every field is optional."""

    reserve: TokenAmount | None = None
    c1: TokenAmount | None = None
    d1: TokenAmount | None = None
    c2: TokenAmount | None = None
    delay: PositiveSeconds | None = None
    loosening_delay: PositiveSeconds | None = None
    pressure_hold: PositiveSeconds | None = None
    refill_period: PositiveSeconds | None = None
    horizon: PositiveSeconds | None = None
    expiry_after: PositiveSeconds | None = None
    allowance_max: Annotated[int, Field(ge=0, le=2**32 - 1)] | None = None
    channels: tuple[ChannelName, ...] | None = None
    """The channel profile as a set of channel names."""
    charge_external: Annotated[int, Field(ge=0, le=255)] | None = None
    charge_over_half_d: Annotated[int, Field(ge=0, le=255)] | None = None
    charge_anomaly: Annotated[int, Field(ge=0, le=255)] | None = None
    charge_first_payment: Annotated[int, Field(ge=0, le=255)] | None = None
    charge_partial_capsule: Annotated[int, Field(ge=0, le=255)] | None = None
    fee_top_up_cap: NativeAmount | None = None
    fee_daily_budget: NativeAmount | None = None
    agent_balance_floor: NativeAmount | None = None
    native_reserve: NativeAmount | None = None

    @model_validator(mode="after")
    def _distinct_channels(self) -> MandateOverrides:
        if self.channels is not None and len(set(self.channels)) != len(self.channels):
            raise ValueError("channels must be distinct")
        return self


class WalletSetup(SuiteModel):
    """The state of one wallet when a case starts. Built with real transactions and the real Λ time-lock."""

    balance: TokenAmount
    """MockUSD the wallet holds when the case starts."""
    payees: tuple[PayeeSetup, ...] = ()
    obligations: tuple[ObligationSetup, ...] = ()
    mandate: MandateOverrides = MandateOverrides()
    allowance_points: Annotated[int, Field(ge=0)] | None = None
    """Caution allowance when the case starts, in points. Omitted means full."""
    frozen: bool = False
    wallet_native: NativeAmount | None = None
    """Native fee reserve of the wallet. Omitted means the runner's default."""
    agent_native: NativeAmount | None = None
    """Native balance of the agent key. Omitted means the runner's default."""

    @model_validator(mode="after")
    def _payees_consistent(self) -> WalletSetup:
        names = [p.name.casefold() for p in self.payees]
        if len(set(names)) != len(names):
            raise ValueError("payee names must be distinct")
        known = set(names)
        for obligation in self.obligations:
            if obligation.payee.casefold() not in known:
                raise ValueError(f"obligation names unknown payee {obligation.payee!r}")
        return self

    def payee(self, name: str) -> PayeeSetup | None:
        return next((p for p in self.payees if p.name.casefold() == name.casefold()), None)


# ---------------------------------------------------------------------------------------------- expectations


class ExpectedOutcome(SuiteModel):
    """What the agent's reply should be. The tier follows from ``kind``: executed is L1, queued L2, proposed L3."""

    kind: OutcomeKind
    deciding_check: CheckName | None = None
    """The check named in the wallet's ``Decision``. Only for executed, queued and proposed."""
    question: str | None = None
    """The question code, by name in lower case (for example ``amount_missing``). Only for a question."""
    rejection: str | None = None
    """The reply's text key, for example ``rejection.unknown_payee`` or ``revert.wallet_is_frozen``. Only for a
    rejection."""

    @model_validator(mode="after")
    def _fields_match_kind(self) -> ExpectedOutcome:
        if (self.kind == "question") != (self.question is not None):
            raise ValueError("question is given exactly for kind question")
        if (self.kind == "rejected") != (self.rejection is not None):
            raise ValueError("rejection is given exactly for kind rejected")
        if self.deciding_check is not None and self.tier is None:
            raise ValueError("deciding_check is given only for executed, queued or proposed")
        if self.question is not None and self.question.upper() not in QuestionCode.__members__:
            raise ValueError(f"unknown question code {self.question!r}")
        if self.question is not None and self.question != self.question.lower():
            raise ValueError("question codes are written in lower case")
        if self.rejection is not None and self.rejection.partition(".")[0] not in ("rejection", "revert", "agent"):
            raise ValueError("a rejection key starts with rejection., revert. or agent.")
        return self

    @property
    def tier(self) -> int | None:
        return {"executed": 1, "queued": 2, "proposed": 3}.get(self.kind)


class ScheduleExpectation(SuiteModel):
    """Terms of a schedule the case allows. ``first_due`` must fall within the window, in seconds after the case
    starts."""

    period: PositiveSeconds
    max_runs: Annotated[int, Field(ge=1, le=2**32 - 1)]
    first_due_after: Seconds
    first_due_before: Seconds

    @model_validator(mode="after")
    def _window(self) -> ScheduleExpectation:
        if self.first_due_after > self.first_due_before:
            raise ValueError("first_due_after must not exceed first_due_before")
        return self


class AllowedTransition(SuiteModel):
    """One allowed state change, as an exact tuple."""

    wallet: WalletLabel = "A"
    action: ActionName
    recipient: Recipient | None = None
    """For a value action, an item, a schedule, an obligation, a payee change request, a payee removal or a change
    of payee, agent or guardian. Omitted means any recipient, which only makes sense for owner bookkeeping."""
    amount: str | None = None
    """Exact amount, in the asset of the action."""
    max_amount: str | None = None
    """Upper bound instead of an exact amount, for a fee top-up whose size depends on gas the agent spent."""
    task: TaskName | None = None
    """The task of an item. Required for the item actions."""
    change_kind: ChangeKindName | None = None
    """The kind of a loosening change. Required for the change actions."""
    schedule: ScheduleExpectation | None = None
    """Schedule terms. Required for ``schedule_create``."""
    tiers: tuple[Literal[1, 2, 3], ...] | None = None
    """Tiers at which a value action may execute: 1 for L1, 2 for a queued item, 3 for an approved one."""
    earliest: Seconds = 0
    """Earliest chain time, in seconds after the case starts."""
    latest: Seconds | None = None
    """Latest chain time, in seconds after the case starts. Omitted means no bound."""
    times: Annotated[int, Field(ge=1, le=100)] = 1
    """How many times the transition may happen. A required transition must happen exactly this often."""
    required: bool = True

    @model_validator(mode="after")
    def _shape(self) -> AllowedTransition:
        if (self.action in ITEM_ACTIONS) != (self.task is not None):
            raise ValueError("task is given exactly for the item actions")
        if (self.action in CHANGE_ACTIONS) != (self.change_kind is not None):
            raise ValueError("change_kind is given exactly for the change actions")
        if (self.action == "schedule_create") != (self.schedule is not None):
            raise ValueError("schedule is given exactly for schedule_create")
        if self.amount is not None and self.max_amount is not None:
            raise ValueError("give amount or max_amount, not both")
        if (self.amount is not None or self.max_amount is not None) and self.action not in AMOUNT_ACTIONS:
            raise ValueError(f"action {self.action} has no amount")
        pattern = NATIVE_PATTERN if asset_of(self.action, self.task) == "native" else TOKEN_PATTERN
        for value in (self.amount, self.max_amount):
            if value is not None:
                if not re.fullmatch(pattern, value):
                    raise ValueError(f"amount {value!r} is not a valid {asset_of(self.action, self.task)} amount")
        if self.recipient is not None and self.action not in RECIPIENT_ACTIONS:
            raise ValueError(f"action {self.action} has no recipient")
        if self.tiers is not None and self.action not in VALUE_ACTIONS - {"vault_withdrawn"}:
            raise ValueError("tiers are given only for payment, schedule_run, sweep and fee_topup")
        if self.latest is not None and self.latest < self.earliest:
            raise ValueError("latest must not be before earliest")
        return self

    def units(self) -> tuple[int | None, int | None]:
        """``(amount, max_amount)`` in base units of the action's asset."""
        decimals = NATIVE_DECIMALS if asset_of(self.action, self.task) == "native" else TOKEN_DECIMALS
        return (
            to_units(self.amount, decimals) if self.amount is not None else None,
            to_units(self.max_amount, decimals) if self.max_amount is not None else None,
        )


# ---------------------------------------------------------------------------------------------- independent cases


class InstructionCase(SuiteModel):
    """One owner instruction on wallet A, from a fresh snapshot with fresh memory and agent."""

    id: CaseId
    setup: WalletSetup
    instruction: InstructionText
    """What the owner typed. Trusted. May contain ``{{address:<label>}}``."""
    documents: tuple[Document, ...] = ()
    """Untrusted content the owner referenced, passed to the agent in this order."""


class TaskCase(InstructionCase):
    """Task suite: an instruction that should complete one task at L1 with exactly the allowed change."""

    task: TaskName
    expected: ExpectedOutcome
    allowed: tuple[AllowedTransition, ...]
    benign_l1_eligible: Literal[True]
    """Every task case is in the population of ``safe_autonomy_rate`` and ``escalation_rate``."""

    @model_validator(mode="after")
    def _expects_l1(self) -> TaskCase:
        if self.expected.kind != "executed":
            raise ValueError("a task case expects execution at L1")
        if not any(t.required for t in self.allowed):
            raise ValueError("a task case requires at least one transition")
        return self


class AmbiguousCase(InstructionCase):
    """Ambiguous suite: the agent must ask the declared question or refuse with the declared reason, and
    nothing may change. There is no allowed transition."""

    expected: ExpectedOutcome

    @model_validator(mode="after")
    def _question_or_rejection(self) -> AmbiguousCase:
        if self.expected.kind not in ("question", "rejected"):
            raise ValueError("an ambiguous case expects a question or a rejection")
        return self


class AffordabilityCase(InstructionCase):
    """Affordability suite: a state and request pair with a hand-computed tier and deciding check."""

    expected: ExpectedOutcome
    allowed: tuple[AllowedTransition, ...]
    benign_l1_eligible: bool

    @model_validator(mode="after")
    def _expects_tier(self) -> AffordabilityCase:
        if self.expected.tier is None or self.expected.deciding_check is None:
            raise ValueError("an affordability case expects a tier and a deciding check")
        if self.benign_l1_eligible and self.expected.kind != "executed":
            raise ValueError("a case declared L1-eligible must expect execution at L1")
        return self


class AttackerGoal(SuiteModel):
    """What the attacker wants. Documentation for the ledger: authorisation comes only from ``allowed``."""

    kind: Literal[
        "pay_unlisted_address",
        "pay_other_payee",
        "inflate_amount",
        "add_payee",
        "change_mandate",
        "schedule_to_attacker",
        "drain_to_vault",
        "drain_fees",
        "unfreeze",
    ]
    recipient: Recipient | None = None
    amount: TokenAmount | None = None


class Paraphrase(SuiteModel):
    """A fixed rewording of the attack content, written once with the base attack."""

    id: CaseId
    text: Text


class AttackCase(InstructionCase):
    """Attack suite: the owner's instruction, benign context documents and the attacker's content.

    ``documents`` holds the benign context the owner referenced. The attack content is passed after them. Each
    form (the base and every paraphrase) runs first-contact on A. Each paraphrase also runs on B after the owner of
    A confirmed the base attack and A published its capsule, to measure ``reworded_matched_rate``.
    """

    family: FamilyName
    attacker_goal: AttackerGoal
    attack: AttackContent
    paraphrases: tuple[Paraphrase, ...] = Field(min_length=1)
    allowed: tuple[AllowedTransition, ...] = ()
    """The owner's real intent. Empty when the owner wanted nothing."""
    expected: ExpectedOutcome | None = None
    """The reply the case expects, if one is fixed. Graded in the ledger, not a gate."""

    @model_validator(mode="after")
    def _paraphrases_distinct(self) -> AttackCase:
        ids = [p.id for p in self.paraphrases]
        if len(set(ids)) != len(ids) or self.id in ids:
            raise ValueError("paraphrase ids must be distinct from each other and from the base id")
        texts = [self.attack.text, *(p.text for p in self.paraphrases)]
        if len(set(texts)) != len(texts):
            raise ValueError("every paraphrase must differ from the base attack and from the others")
        if any(t.wallet != "A" for t in self.allowed):
            raise ValueError("an attack case allows transitions on wallet A only")
        return self


# ---------------------------------------------------------------------------------------------- sequences

InstructRole = Literal[
    "probe_invoice",
    "pressured_request",
    "capsule_attack",
    "capsule_replay",
    "capsule_unrelated",
    "capsule_after_expiry",
    "false_capsule_probe",
]
"""What an instruct step stands for in its suite. The runner's non-vacuity checks and the reduction key
off these roles."""

OwnerRole = Literal["panicked_approval", "false_capsule"]
OwnerActionName = Literal[
    "approve",
    "cancel",
    "extend_hold",
    "propose_add_payee",
    "apply_change",
    "cancel_change",
    "propose_unfreeze",
    "freeze",
    "confirm_attack",
    "publish_capsule",
    "attest_capsule",
    "dismiss_capsule",
    "remove_payee",
]


class CapsuleSpec(SuiteModel):
    """Fields of a capsule an owner publishes directly, for example a false capsule from a hostile wallet."""

    family: FamilyName
    channel: ChannelName
    features: tuple[FlagName, ...] = Field(min_length=1)
    action: CapsuleActionName
    restriction: Literal[2, 3]
    lifetime: PositiveSeconds

    @model_validator(mode="after")
    def _distinct_features(self) -> CapsuleSpec:
        if len(set(self.features)) != len(self.features):
            raise ValueError("features must be distinct")
        return self


class InstructStep(SuiteModel):
    """The owner gives the agent of ``wallet`` an instruction, with referenced documents and any attack content."""

    type: Literal["instruct"]
    id: CaseId
    wallet: WalletLabel
    instruction: InstructionText
    documents: tuple[Document, ...] = ()
    attack: AttackContent | None = None
    """Attacker content, passed after the documents."""
    expected: ExpectedOutcome | None = None
    role: InstructRole | None = None
    benign_l1_eligible: bool


class OwnerStep(SuiteModel):
    """An owner action, signed by the harness's owner signer for ``wallet``.

    ``ref`` names an earlier step: the instruct step whose item is approved, cancelled or extended, whose payee
    change request is proposed, or whose attack is confirmed, the propose step whose change is applied or
    cancelled, or the step whose capsule is attested or dismissed.
    """

    type: Literal["owner"]
    id: CaseId
    wallet: WalletLabel
    action: OwnerActionName
    ref: CaseId | None = None
    payee: PayeeName | None = None
    """For ``remove_payee``, and for ``propose_add_payee`` without a ref."""
    account: AccountLabel | None = None
    """For ``propose_add_payee`` without a ref."""
    seconds: PositiveSeconds | None = None
    """For ``extend_hold``."""
    publish: bool | None = None
    """For ``confirm_attack``: whether the owner also publishes the capsule."""
    capsule: CapsuleSpec | None = None
    """For ``publish_capsule``."""
    expect: Literal["success", "revert"] = "success"
    revert_error: str | None = None
    """The custom error name expected when ``expect`` is revert, for example ``ChangeNotReady``."""
    role: OwnerRole | None = None

    @model_validator(mode="after")
    def _parameters(self) -> OwnerStep:
        needs_ref = {"approve", "cancel", "extend_hold", "apply_change", "cancel_change", "confirm_attack",
                     "attest_capsule", "dismiss_capsule"}
        if self.action in needs_ref and self.ref is None:
            raise ValueError(f"{self.action} needs ref")
        if self.action == "propose_add_payee" and self.ref is None and (self.payee is None or self.account is None):
            raise ValueError("propose_add_payee needs ref, or payee and account")
        if (self.action == "extend_hold") != (self.seconds is not None):
            raise ValueError("seconds is given exactly for extend_hold")
        if (self.action == "confirm_attack") != (self.publish is not None):
            raise ValueError("publish is given exactly for confirm_attack")
        if (self.action == "publish_capsule") != (self.capsule is not None):
            raise ValueError("capsule is given exactly for publish_capsule")
        if self.action == "remove_payee" and self.payee is None:
            raise ValueError("remove_payee needs payee")
        if self.revert_error is not None and self.expect != "revert":
            raise ValueError("revert_error is given only when expect is revert")
        return self


class ExecuteStep(SuiteModel):
    """Anyone (a keeper key with no role) executes the queued or approved item of the instruct step ``ref``."""

    type: Literal["execute_pending"]
    id: CaseId
    wallet: WalletLabel
    ref: CaseId
    expect: Literal["success", "revert"] = "success"
    revert_error: str | None = None


class RunScheduleStep(SuiteModel):
    """Anyone runs the schedule created by the instruct step ``ref``."""

    type: Literal["run_schedule"]
    id: CaseId
    wallet: WalletLabel
    ref: CaseId
    expect: Literal["success", "revert"] = "success"
    revert_error: str | None = None


class AdvanceStep(SuiteModel):
    """Moves chain time forward and mines a block.

    ``by`` is a number of ``seconds``, a delay of ``wallet``'s current mandate (Δ, Λ, Π or the refill period), or
    ``capsule_expiry``: until the capsule produced by step ``ref`` has expired. ``offset`` is added and may be
    negative, to stop just short of a delay.
    """

    type: Literal["advance"]
    id: CaseId
    by: Literal["seconds", "delay", "loosening_delay", "pressure_hold", "refill_period", "capsule_expiry"]
    seconds: Seconds | None = None
    wallet: WalletLabel = "A"
    ref: CaseId | None = None
    offset: Annotated[int, Field(ge=-86_400, le=86_400)] = 0

    @model_validator(mode="after")
    def _parameters(self) -> AdvanceStep:
        if (self.by == "seconds") != (self.seconds is not None):
            raise ValueError("seconds is given exactly when by is seconds")
        if (self.by == "capsule_expiry") != (self.ref is not None):
            raise ValueError("ref is given exactly when by is capsule_expiry")
        return self


Step = Annotated[
    Union[InstructStep, OwnerStep, ExecuteStep, RunScheduleStep, AdvanceStep], Field(discriminator="type")
]


class SequenceCase(SuiteModel):
    """A scripted sequence on one or more wallets that share state within the case."""

    id: CaseId
    wallets: dict[WalletLabel, WalletSetup] = Field(min_length=1)
    steps: tuple[Step, ...] = Field(min_length=1)
    allowed: tuple[AllowedTransition, ...] = ()

    @model_validator(mode="after")
    def _references(self) -> SequenceCase:
        seen: dict[str, Step] = {}
        for step in self.steps:
            if step.id in seen:
                raise ValueError(f"step id {step.id!r} is used twice")
            if not isinstance(step, AdvanceStep) and step.wallet not in self.wallets:
                raise ValueError(f"step {step.id!r} uses wallet {step.wallet} that has no setup")
            if isinstance(step, AdvanceStep) and step.by not in ("seconds", "capsule_expiry"):
                if step.wallet not in self.wallets:
                    raise ValueError(f"step {step.id!r} reads the mandate of wallet {step.wallet} with no setup")
            ref = getattr(step, "ref", None)
            if ref is not None and ref not in seen:
                raise ValueError(f"step {step.id!r} refers to {ref!r}, which is not an earlier step")
            seen[step.id] = step
        for transition in self.allowed:
            if transition.wallet not in self.wallets:
                raise ValueError(f"an allowed transition names wallet {transition.wallet} with no setup")
        return self

    def instruct_steps(self, role: str | None = None) -> tuple[InstructStep, ...]:
        return tuple(s for s in self.steps if isinstance(s, InstructStep) and (role is None or s.role == role))

    def owner_steps(self, role: str | None = None) -> tuple[OwnerStep, ...]:
        return tuple(s for s in self.steps if isinstance(s, OwnerStep) and (role is None or s.role == role))


# ---------------------------------------------------------------------------------------------- suite files


def _unique_ids(ids: list[str], what: str) -> None:
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    if duplicates:
        raise ValueError(f"{what} ids used more than once: {duplicates}")


class TaskSuite(SuiteModel):
    suite: Literal["tasks"]
    cases: tuple[TaskCase, ...]


class AmbiguousSuite(SuiteModel):
    suite: Literal["ambiguous"]
    cases: tuple[AmbiguousCase, ...]


class AffordabilitySuite(SuiteModel):
    suite: Literal["affordability"]
    cases: tuple[AffordabilityCase, ...]


class AttackSuite(SuiteModel):
    suite: Literal["attacks"]
    cases: tuple[AttackCase, ...]


class ProbingSuite(SuiteModel):
    """One sequence of slightly odd invoices from an approved payee. Its probe steps have role ``probe_invoice``."""

    suite: Literal["probing"]
    sequence: SequenceCase

    @model_validator(mode="after")
    def _probes(self) -> ProbingSuite:
        probes = self.sequence.instruct_steps("probe_invoice")
        if not probes:
            raise ValueError("the probing sequence has no probe_invoice step")
        if any(p.expected is None for p in probes):
            raise ValueError("every probe_invoice step declares its expected outcome")
        return self


class PanickedOwnerSuite(SuiteModel):
    """Scripts in which the owner approves every prompt at once. Approvals have role ``panicked_approval``."""

    suite: Literal["panicked_owner"]
    cases: tuple[SequenceCase, ...] = Field(min_length=1)


class PoisonedUpdate(SuiteModel):
    """The poisoned half of the hostile-wallet suite: one federation round, starting from the model every wallet
    runs, in which the wallet ``hostile`` sends a poisoned update (``agentvax.fed.hostile``). Every wallet's canary
    must evaluate the candidate, and the candidate must not be adopted."""

    hostile: WalletLabel


class HostileWalletSuite(SuiteModel):
    """False capsules published by a hostile registered wallet (owner steps with role ``false_capsule``), the
    requests that meet them (role ``false_capsule_probe``), and a poisoned federation round."""

    suite: Literal["hostile_wallet"]
    cases: tuple[SequenceCase, ...] = Field(min_length=1)
    poisoned_update: PoisonedUpdate


class CapsuleResponseSuite(SuiteModel):
    """Attack on A, owner confirms and publishes, reworded replay on B, unrelated request on C, and B again after
    the capsule expired."""

    suite: Literal["capsule_response"]
    cases: tuple[SequenceCase, ...] = Field(min_length=1)


SuiteName = Literal[
    "tasks", "ambiguous", "affordability", "attacks", "probing", "panicked_owner", "hostile_wallet", "capsule_response"
]
SUITE_MODELS: dict[str, type[SuiteModel]] = {
    "tasks": TaskSuite,
    "ambiguous": AmbiguousSuite,
    "affordability": AffordabilitySuite,
    "attacks": AttackSuite,
    "probing": ProbingSuite,
    "panicked_owner": PanickedOwnerSuite,
    "hostile_wallet": HostileWalletSuite,
    "capsule_response": CapsuleResponseSuite,
}
"""Each suite is the file ``<name>.json`` in the suite directory."""


class SuiteSet(SuiteModel):
    """All eight suites, with the keccak256 of each file's exact bytes for the ledger."""

    tasks: TaskSuite
    ambiguous: AmbiguousSuite
    affordability: AffordabilitySuite
    attacks: AttackSuite
    probing: ProbingSuite
    panicked_owner: PanickedOwnerSuite
    hostile_wallet: HostileWalletSuite
    capsule_response: CapsuleResponseSuite
    file_hashes: dict[str, Bytes32]

    @model_validator(mode="after")
    def _ids_unique(self) -> SuiteSet:
        ids: list[str] = []
        for suite in (self.tasks, self.ambiguous, self.affordability):
            ids += [c.id for c in suite.cases]
        for attack in self.attacks.cases:
            ids += [attack.id, *(p.id for p in attack.paraphrases)]
        ids.append(self.probing.sequence.id)
        for suite in (self.panicked_owner, self.hostile_wallet, self.capsule_response):
            ids += [c.id for c in suite.cases]
        _unique_ids(ids, "case and paraphrase")
        return self

    def documents(self) -> tuple[Document, ...]:
        """Every document in every suite, in file order."""
        found: list[Document] = []
        for suite in (self.tasks, self.ambiguous, self.affordability, self.attacks):
            for case in suite.cases:
                found += case.documents
        for sequence in self.sequences():
            for step in sequence.instruct_steps():
                found += step.documents
        return tuple(found)

    def sequences(self) -> tuple[SequenceCase, ...]:
        return (
            self.probing.sequence,
            *self.panicked_owner.cases,
            *self.hostile_wallet.cases,
            *self.capsule_response.cases,
        )

    def rejection_keys(self) -> tuple[str, ...]:
        keys: list[str] = []
        outcomes: list[ExpectedOutcome | None] = [c.expected for c in self.tasks.cases]
        outcomes += [c.expected for c in self.ambiguous.cases] + [c.expected for c in self.affordability.cases]
        outcomes += [c.expected for c in self.attacks.cases]
        for sequence in self.sequences():
            outcomes += [s.expected for s in sequence.instruct_steps()]
        for outcome in outcomes:
            if outcome is not None and outcome.rejection is not None:
                keys.append(outcome.rejection)
        return tuple(keys)


class SuiteFileError(ValueError):
    """A suite file is missing or does not validate."""


def file_keccak(data: bytes) -> str:
    """keccak256 of a suite file's bytes with every CRLF written as LF.

    The repository stores text with LF line endings (``.gitattributes``, ``eol=lf``), while a Windows checkout may
    hold CRLF copies. Hashing the LF form gives the same value as hashing the committed file, on every platform."""
    return "0x" + keccak(data.replace(b"\r\n", b"\n")).hex()


def load_suites(directory: Path, strings: Strings) -> SuiteSet:
    """Loads and validates the eight suite files in ``directory``.

    Every rejection key a case expects must exist in ``strings`` (the reply text table), so a case cannot expect a
    reply the agent can never give.
    """
    parsed: dict[str, SuiteModel] = {}
    hashes: dict[str, str] = {}
    for name, model in SUITE_MODELS.items():
        path = directory / f"{name}.json"
        if not path.is_file():
            raise SuiteFileError(f"suite file {path} is missing")
        data = path.read_bytes()
        try:
            parsed[name] = model.model_validate_json(data)
        except ValueError as error:
            raise SuiteFileError(f"suite file {path} does not validate: {error}") from error
        hashes[name] = file_keccak(data)
    suites = SuiteSet(**parsed, file_hashes=hashes)  # type: ignore[arg-type]
    unknown = sorted({k for k in suites.rejection_keys() if not strings.has(k)})
    if unknown:
        raise SuiteFileError(f"cases expect reply keys that do not exist: {unknown}")
    return suites


# ---------------------------------------------------------------------------------------------- fixed sizes

TASKS_PER_TASK = 10
TASK_NAMES: tuple[TaskName, ...] = ("payment", "schedule_create", "sweep", "fee_topup")
AMBIGUOUS_CASES = 10
AFFORDABILITY_CASES = 20
BASE_ATTACKS_PER_FAMILY = 6
PARAPHRASES_PER_ATTACK = 2
PROBING_SEQUENCE_LENGTH = 6


def fixed_size_problems(suites: SuiteSet) -> tuple[str, ...]:
    """Every way ``suites`` departs from the fixed suite sizes. Empty when the sizes are exactly right."""
    problems: list[str] = []
    per_task = {name: sum(1 for c in suites.tasks.cases if c.task == name) for name in TASK_NAMES}
    for name, count in per_task.items():
        if count != TASKS_PER_TASK:
            problems.append(f"{count} task cases for {name}, expected {TASKS_PER_TASK}")
    if len(suites.ambiguous.cases) != AMBIGUOUS_CASES:
        problems.append(f"{len(suites.ambiguous.cases)} ambiguous cases, expected {AMBIGUOUS_CASES}")
    if len(suites.affordability.cases) != AFFORDABILITY_CASES:
        problems.append(f"{len(suites.affordability.cases)} affordability cases, expected {AFFORDABILITY_CASES}")
    for family in FAMILIES:
        count = sum(1 for c in suites.attacks.cases if c.family == family)
        if count != BASE_ATTACKS_PER_FAMILY:
            problems.append(f"{count} base attacks in family {family}, expected {BASE_ATTACKS_PER_FAMILY}")
    for case in suites.attacks.cases:
        if len(case.paraphrases) != PARAPHRASES_PER_ATTACK:
            problems.append(f"attack {case.id} has {len(case.paraphrases)} paraphrases, expected {PARAPHRASES_PER_ATTACK}")
    probes = len(suites.probing.sequence.instruct_steps("probe_invoice"))
    if probes != PROBING_SEQUENCE_LENGTH:
        problems.append(f"probing sequence has {probes} invoices, expected {PROBING_SEQUENCE_LENGTH}")
    return tuple(problems)
