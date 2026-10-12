"""Considered confirmation for an L3 proposal that carries flags.

The owner sees the current and requested account, the payment history and any matching alert. They must type the
payee's name exactly and say who asked for the payment. The only effect an answer can have is to lengthen the
hold. Nothing here shortens a hold or approves anything: approval is a separate action that only the owner's
signer can take.
"""

from __future__ import annotations

from enum import IntEnum

from agentvax.amounts import format_amount
from agentvax.text import Strings, describe_duration
from agentvax.types import Address, Strict, Uint16, Uint32, Uint64, Uint256


class Requester(IntEnum):
    OWNER_MYSELF = 1
    SOMEONE_ELSE = 2
    A_MESSAGE_OR_PAGE = 3
    NOT_SURE = 4


class Verdict(IntEnum):
    NAME_MISMATCH = 1
    HOLD_EXTENDED = 2
    CONFIRMED_BY_OWNER = 3


class ConfirmationContext(Strict):
    payee_name: str
    current_account: Address
    requested_account: Address | None
    paid_count: Uint32
    max_paid: Uint256
    matching_capsules: tuple[Uint256, ...]
    flags: Uint16
    pressure_hold: Uint64


class ConfirmationAnswers(Strict):
    typed_payee_name: str
    requester: Requester


class ConfirmationOutcome(Strict):
    """``extend_hold_seconds`` is an amount to add, and by its type it cannot be negative."""

    verdict: Verdict
    extend_hold_seconds: Uint64


def evaluate(context: ConfirmationContext, answers: ConfirmationAnswers) -> ConfirmationOutcome:
    """Decide what the answers change. The name must match exactly, with no trimming and no change of case."""
    if answers.typed_payee_name != context.payee_name:
        return ConfirmationOutcome(verdict=Verdict.NAME_MISMATCH, extend_hold_seconds=0)
    if answers.requester is Requester.OWNER_MYSELF:
        return ConfirmationOutcome(verdict=Verdict.CONFIRMED_BY_OWNER, extend_hold_seconds=0)
    return ConfirmationOutcome(verdict=Verdict.HOLD_EXTENDED, extend_hold_seconds=context.pressure_hold)


def describe(strings: Strings, context: ConfirmationContext) -> tuple[str, ...]:
    """What the owner is shown before answering."""
    lines = [strings.render("confirm.current_account", account=context.current_account)]
    if context.requested_account is not None:
        lines.append(strings.render("confirm.requested_account", account=context.requested_account))
    if context.paid_count:
        lines.append(
            strings.render(
                "confirm.history", count=context.paid_count, largest=format_amount(context.max_paid)
            )
        )
    else:
        lines.append(strings.render("confirm.no_history"))
    for capsule_id in context.matching_capsules:
        lines.append(strings.render("confirm.capsule", capsule=capsule_id))
    lines.append(strings.render("confirm.type_name", payee=context.payee_name))
    lines.append(strings.render("confirm.who_asked"))
    lines.append(strings.render("confirm.hold_note", hold=describe_duration(strings, context.pressure_hold)))
    return tuple(lines)


def outcome_text(strings: Strings, outcome: ConfirmationOutcome) -> str:
    key = f"confirm.verdict.{outcome.verdict.name.lower()}"
    return strings.render(key, extra=describe_duration(strings, outcome.extend_hold_seconds))
