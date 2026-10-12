"""The one interface through which every model call goes.

Calls are stateless. Any failure raises ``LLMError`` and there is no fallback to another model.
"""

from __future__ import annotations

from collections.abc import Sequence
from enum import StrEnum
from typing import Protocol, TypeVar

from pydantic import BaseModel

from agentvax.types import Strict

T = TypeVar("T", bound=BaseModel)


class Role(StrEnum):
    """The model roles. The reader is quarantined and has no tools, the planner is privileged. The rewriter belongs
    to the evaluation harness only: VaxLab uses it to reword attacks in live mode, and nothing in the wallet runtime
    calls it."""

    READER = "reader"
    PLANNER = "planner"
    MISSION = "mission"
    REWRITER = "rewriter"


class MessageRole(StrEnum):
    SYSTEM = "system"
    USER = "user"


class Message(Strict):
    role: MessageRole
    content: str


class LLMError(Exception):
    """A model call failed or its reply did not validate against the schema."""


class LanguageModel(Protocol):
    def complete(self, role: Role, messages: Sequence[Message], schema: type[T]) -> T:
        """Return a ``schema`` object built from ``messages``, or raise ``LLMError``."""
        ...
