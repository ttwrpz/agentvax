"""The quarantined reader.

The reader model sees untrusted content and has no tools. What leaves this module is a ``ReaderOutput`` made only
of enums, numbers, allowlist indices and flag bits. There is no string field, so no free text can travel on to
the planner or into memory. The destination check is plain code that compares addresses found in the content
with the allowlist, so a model cannot hide a changed account.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from enum import IntEnum
from typing import Annotated

from pydantic import Field

from agentvax.llm.base import LanguageModel, LLMError, Message, MessageRole, Role
from agentvax.llm.prompts import system_prompt
from agentvax.types import ALL_FLAGS, Address, Channel, Strict, Uint32, Uint64, Uint256

_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")

FlagBits = Annotated[int, Field(ge=0, le=int(ALL_FLAGS))]


class DocumentKind(IntEnum):
    OTHER = 0
    INVOICE = 1
    RECEIPT = 2
    NOTICE = 3


class DestinationStatus(IntEnum):
    NONE = 0
    MATCHES_ALLOWLIST = 1
    DIFFERS_FROM_ALLOWLIST = 2


class AllowlistEntry(Strict):
    """A payee the owner has added, as the reader and the validator know it."""

    name: str = Field(min_length=1, max_length=64)
    payee_id: Annotated[int, Field(ge=1, le=2**32 - 1)]
    account: Address


class UntrustedContent(Strict):
    channel: Channel
    text: str


class ReaderRequest(Strict):
    """The only thing the reader model is shown. Allowlist names are owner-set and trusted."""

    channel: Channel
    allowlist_names: tuple[str, ...]
    content: str


class ReaderReading(Strict):
    """What the reader model returns."""

    document_kind: DocumentKind
    payee_index: Annotated[int, Field(ge=0)] | None
    amount: Uint256 | None
    due: Uint64 | None
    flags: FlagBits


class ReaderOutput(Strict):
    """A typed reading of one document. Contains no string field of any kind."""

    document_kind: DocumentKind
    payee_index: Annotated[int, Field(ge=0)] | None
    payee_id: Uint32 | None
    amount: Uint256 | None
    due: Uint64 | None
    flags: FlagBits
    destination: DestinationStatus
    channel: Channel


def _destination(text: str, payee: AllowlistEntry | None, allowlist: Sequence[AllowlistEntry]) -> DestinationStatus:
    found = {a.lower() for a in _ADDRESS.findall(text)}
    if not found:
        return DestinationStatus.NONE
    known = {entry.account.lower() for entry in allowlist}
    expected = {payee.account.lower()} if payee is not None else known
    if found <= expected:
        return DestinationStatus.MATCHES_ALLOWLIST
    return DestinationStatus.DIFFERS_FROM_ALLOWLIST


def read(llm: LanguageModel, content: UntrustedContent, allowlist: Sequence[AllowlistEntry]) -> ReaderOutput:
    """Read one document. Raises ``LLMError`` if the reply is not a valid reading."""
    request = ReaderRequest(
        channel=content.channel,
        allowlist_names=tuple(entry.name for entry in allowlist),
        content=content.text,
    )
    messages = [
        Message(role=MessageRole.SYSTEM, content=system_prompt(Role.READER)),
        Message(role=MessageRole.USER, content=request.model_dump_json()),
    ]
    reading = llm.complete(Role.READER, messages, ReaderReading)
    payee = None
    if reading.payee_index is not None:
        if reading.payee_index >= len(allowlist):
            raise LLMError("the reader named a payee outside the allowlist")
        payee = allowlist[reading.payee_index]
    return ReaderOutput(
        document_kind=reading.document_kind,
        payee_index=reading.payee_index,
        payee_id=payee.payee_id if payee else None,
        amount=reading.amount,
        due=reading.due,
        flags=reading.flags,
        destination=_destination(content.text, payee, allowlist),
        channel=content.channel,
    )


