"""The guardian's line protocol, version 1.

One JSON request per line in, one JSON reply per line out. Replies carry only fixed error codes, so nothing
untrusted travels back in an error. These models hold no key.
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal

from pydantic import Field

from agentvax.types import Address, Attestation, Bytes32, Channel, Intent, Strict

PROTOCOL_VERSION = 1
MAX_CONTENT_ITEMS = 16
"""Most untrusted content items one request may carry."""
MAX_CONTENT_CHARS = 65_536
"""Longest single content item, in characters."""
MAX_LINE_BYTES = 8 * MAX_CONTENT_ITEMS * MAX_CONTENT_CHARS
"""Longest request line the guardian reads, allowing for JSON escapes of six bytes per character. Longer lines
are refused unread."""

SIGNATURE_PATTERN = r"^0x[0-9a-fA-F]{130}$"

RPC_URL_VARIABLE = "AGENTVAX_GUARDIAN_RPC_URL"
"""Environment variable through which the parent gives the guardian process its RPC endpoint. A provider URL can
embed an API key, and a command line is visible in the local process list, so the URL is never an argument."""


class ErrorCode(str, Enum):
    UNSUPPORTED_PROTOCOL = "unsupported_protocol"
    BAD_REQUEST = "bad_request"
    REQUEST_TOO_LARGE = "request_too_large"
    WRONG_WALLET = "wrong_wallet"
    WRONG_CHAIN = "wrong_chain"
    NOT_WALLET_GUARDIAN = "not_wallet_guardian"
    DOMAIN_MISMATCH = "domain_mismatch"
    CHAIN_UNAVAILABLE = "chain_unavailable"
    UNSUPPORTED_CHAIN = "unsupported_chain"
    MODEL_REJECTED = "model_rejected"
    KEY_UNAVAILABLE = "key_unavailable"


class ContentItem(Strict):
    """One piece of raw untrusted content and the channel it arrived on. Only the guardian and the reader see it."""

    channel: Channel
    text: Annotated[str, Field(max_length=MAX_CONTENT_CHARS)]


class AttestationRequest(Strict):
    """Asks the guardian to attest ``intent`` for ``wallet`` on ``chain_id``.

    ``content`` is every piece of untrusted material the intent was derived from. The guardian scores it itself
    and derives band, source and pressure flags from it. ``caller_flags`` can only add flags.
    """

    protocol_version: Literal[1]
    request_id: Annotated[int, Field(ge=0)]
    wallet: Address
    chain_id: int
    intent: Intent
    content: Annotated[tuple[ContentItem, ...], Field(max_length=MAX_CONTENT_ITEMS)]
    caller_flags: Annotated[int, Field(ge=0, le=0xFF)]


class SignedAttestation(Strict):
    attestation: Attestation
    signature: Annotated[str, Field(pattern=SIGNATURE_PATTERN)]
    guardian: Address
    digest: Bytes32
    """EIP-712 digest of the attestation that was signed."""


class AttestationReply(Strict):
    protocol_version: Literal[1]
    request_id: int
    ok: Literal[True]
    result: SignedAttestation


class ErrorReply(Strict):
    protocol_version: Literal[1]
    request_id: int | None
    ok: Literal[False]
    error: ErrorCode


class ReadyLine(Strict):
    protocol_version: Literal[1]
    event: Literal["ready"]
    guardian: Address
    wallet: Address
    chain_id: int
    model_version: int
    model_hash: Bytes32
    attestation_lifetime: int


class FatalLine(Strict):
    protocol_version: Literal[1]
    event: Literal["fatal"]
    error: ErrorCode


class KeyCreatedLine(Strict):
    protocol_version: Literal[1]
    event: Literal["key_created"]
    guardian: Address
