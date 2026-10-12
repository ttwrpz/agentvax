"""Builders shared by the runtime tests: a wallet snapshot, an allowlist and a recording model."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from agentvax.harness.mock_llm import MockLLM
from agentvax.llm.base import Message, Role, T
from agentvax.reader import AllowlistEntry
from agentvax.config import load_profile
from agentvax.types import Mandate, ObligationView, PayeeView, WalletView

USD = 10**6
WALLET = "0x" + "11" * 20
ACME_ACCOUNT = "0x" + "a1" * 20
MAPLE_ACCOUNT = "0x" + "b2" * 20
NOW = 1_800_000_000
ALLOWLIST = (
    AllowlistEntry(name="Acme Supplies", payee_id=1, account=ACME_ACCOUNT),
    AllowlistEntry(name="Maple Properties", payee_id=2, account=MAPLE_ACCOUNT),
)


def default_mandate() -> Mandate:
    return load_profile("default").mandate.mandate(NOW)


def make_view(
    *,
    balance: int = 2000 * USD,
    discretionary: int = 1000 * USD,
    nonce: int = 7,
    frozen: bool = False,
    obligations: Sequence[ObligationView] = (),
    mandate: Mandate | None = None,
) -> WalletView:
    payees = tuple(
        PayeeView(
            payee_id=e.payee_id,
            identity_hash="0x" + f"{e.payee_id:02x}" * 32,
            account=e.account,
            active=True,
            paid_count=2,
            max_paid=400 * USD,
        )
        for e in ALLOWLIST
    )
    return WalletView(
        chain_id=31337,
        wallet=WALLET,
        block_time=NOW,
        nonce=nonce,
        token_balance=balance,
        native_balance=10**18,
        agent_native_balance=10**17,
        discretionary=discretionary,
        allowance_points=10.0,
        frozen=frozen,
        min_schedule_period=86_400,
        mandate=mandate or default_mandate(),
        mandate_hash="0x" + "00" * 32,
        payees=payees,
        obligations=tuple(obligations),
    )


class RecordingLLM:
    """Wraps a model and keeps every message it was given, by role."""

    def __init__(self, inner: MockLLM | None = None) -> None:
        self._inner = inner or MockLLM()
        self.seen: list[tuple[Role, tuple[Message, ...]]] = []

    def complete(self, role: Role, messages: Sequence[Message], schema: type[T]) -> T:
        self.seen.append((role, tuple(messages)))
        return self._inner.complete(role, messages, schema)

    def text_for(self, role: Role) -> str:
        return "\n".join(m.content for r, msgs in self.seen if r is role for m in msgs)


def leaf_types(model: type, found: set[type] | None = None) -> set[type]:
    """Every scalar type reachable from the fields of a pydantic model, following nested models and containers."""
    from typing import Annotated, get_args, get_origin

    from pydantic import BaseModel

    found = set() if found is None else found

    def visit(annotation: Any) -> None:
        origin = get_origin(annotation)
        if origin is Annotated:
            visit(get_args(annotation)[0])
        elif origin is not None:
            for arg in get_args(annotation):
                visit(arg)
        elif isinstance(annotation, type) and issubclass(annotation, BaseModel):
            for field in annotation.model_fields.values():
                visit(field.annotation)
        elif isinstance(annotation, type):
            found.add(annotation)

    visit(model)
    return found
