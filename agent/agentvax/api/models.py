"""The JSON boundary of the interface: every request and every response is a strict pydantic model.

Requests forbid unknown fields, so a client cannot send a ``source`` (the server assigns it) or any field the
endpoint does not name. Responses carry numbers as numbers and every sentence as text rendered from
``strings.json`` on the server.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from agentvax.runtime import AgentReply
from agentvax.types import UINT64_MAX, Address

Mode = Literal["mock", "live"]
DocumentChannel = Literal["web_page", "message", "token_metadata"]
AttackChannel = Literal["owner_chat", "web_page", "message", "token_metadata"]
RequesterName = Literal["owner_myself", "someone_else", "a_message_or_page", "not_sure"]

MAX_DOCUMENT_CHARACTERS = 20_000
MAX_DOCUMENTS = 5
MAX_HOLD_EXTENSION_SECONDS = 30 * 86_400


class Request(BaseModel):
    """Base of every request body: no unknown fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class Response(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


# ---------------------------------------------------------------------------------------------- requests


class DocumentIn(Request):
    """A pasted or referenced document. It is untrusted and goes through the reader."""

    channel: DocumentChannel
    text: Annotated[str, Field(min_length=1, max_length=MAX_DOCUMENT_CHARACTERS)]


class ChatRequest(Request):
    """The owner's instruction and the documents they referenced, in separate fields."""

    instruction: Annotated[str, Field(min_length=1, max_length=2_000)]
    documents: Annotated[list[DocumentIn], Field(max_length=MAX_DOCUMENTS)] = []


class ItemRequest(Request):
    item_id: Annotated[int, Field(ge=1, le=UINT64_MAX)]


class ConfirmationIn(Request):
    """The answers of the considered confirmation."""

    typed_payee_name: Annotated[str, Field(max_length=200)]
    requester: RequesterName


class ApproveRequest(Request):
    item_id: Annotated[int, Field(ge=1, le=UINT64_MAX)]
    confirmation: ConfirmationIn | None = None


class ExtendHoldRequest(Request):
    item_id: Annotated[int, Field(ge=1, le=UINT64_MAX)]
    extra_seconds: Annotated[int, Field(ge=1, le=MAX_HOLD_EXTENSION_SECONDS)]


class ProposePayeeRequest(Request):
    name: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^\S(.*\S)?$")]
    account: Address


class ChangeRequest(Request):
    change_id: Annotated[int, Field(ge=1, le=UINT64_MAX)]


class ConfirmAttackRequest(Request):
    """The owner confirms that the request behind ``item_id`` was an attack. The flags and the task come from the
    item as the wallet stored it. Only the channel is the owner's answer."""

    item_id: Annotated[int, Field(ge=1, le=UINT64_MAX)]
    channel: AttackChannel
    publish: bool


class ExpectedIncomeRequest(Request):
    amount: Annotated[str, Field(pattern=r"^\d{1,12}(\.\d{1,6})?$")]
    expected_at: Annotated[int, Field(ge=1, le=UINT64_MAX)]


# ---------------------------------------------------------------------------------------------- responses


class MandateField(Response):
    name: str
    label: str
    value: str


class MandateView(Response):
    mission: str | None
    lines: list[str]
    fields: list[MandateField]
    mandate_hash: str


class ObligationRow(Response):
    payee_id: int
    payee: str
    amount: str
    amount_units: int
    due: int
    text: str


class IncomeRow(Response):
    amount: str
    amount_units: int
    expected_at: int
    counted: Literal[False]
    text: str


class FinancialView(Response):
    balance: str
    balance_units: int
    reserve: str
    reserve_units: int
    discretionary: str
    discretionary_units: int
    obligations: list[ObligationRow]
    expected_income: list[IncomeRow]
    lines: list[str]


class AllowanceView(Response):
    points: float
    maximum: int
    fraction: float
    text: str


class RequesterOption(Response):
    value: RequesterName
    label: str


class ConfirmationView(Response):
    payee_name: str
    lines: list[str]
    requesters: list[RequesterOption]
    hold_seconds: int


class PendingRow(Response):
    item_id: int
    status: Literal["queued", "proposed", "approved"]
    tier: int
    task: str
    payee_id: int
    payee: str
    amount: str
    amount_units: int
    text: str
    ready_at: int | None
    seconds_left: int | None
    flags: int
    flag_labels: list[str]
    held: bool
    extra_hold: int
    matching_capsules: list[int]
    can_approve: bool
    can_execute: bool
    confirmation: ConfirmationView | None


class ChangeRow(Response):
    change_id: int
    kind: str
    kind_label: str
    ready_at: int
    seconds_left: int
    name: str | None
    text: str
    can_apply: bool


class PayeeRow(Response):
    payee_id: int
    name: str
    account: str
    active: bool
    paid_count: int
    text: str


class LogRow(Response):
    tier: int
    deciding_check: str
    amount: str
    at: int
    text: str
    tx_hash: str
    link: str | None


class WalletRow(Response):
    """A wallet the page can show. ``about`` is a short description, if the wording table has one for the label."""

    label: str
    about: str | None


class StateResponse(Response):
    mode: Mode
    wallet: str
    chain_id: int
    now: int
    frozen: bool
    mandate: MandateView
    financial: FinancialView
    allowance: AllowanceView
    pending: list[PendingRow]
    changes: list[ChangeRow]
    payees: list[PayeeRow]
    log: list[LogRow]


class ChatResponse(Response):
    mode: Mode
    reply: AgentReply
    link: str | None


class ActionResult(Response):
    """The outcome of an owner action. ``ok`` is false when nothing changed, and ``text`` says why."""

    mode: Mode
    ok: bool
    text: str
    verdict: str | None = None
    tx_hash: str | None = None
    link: str | None = None
    change_id: int | None = None
    ready_at: int | None = None
    capsule_id: int | None = None
