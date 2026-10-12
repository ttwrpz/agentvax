"""Plain explanations of wallet decisions and the financial state panel.

Everything here is built from the wallet's ``Decision`` event and on-chain reads. The model's own account of what
it did is never used. No model is called.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Literal

from agentvax.amounts import format_amount
from agentvax.text import Strings, describe_duration
from agentvax.types import DecidingCheck, DecisionEvent, Strict, Tier, Uint64, Uint256, WalletView


def _tier_suffix(tier: Tier) -> str:
    return "l2" if tier is Tier.L2 else "l3"


def _template(key: str, **params: object) -> tuple[str, dict[str, object]]:
    return key, params


def explanation(strings: Strings, event: DecisionEvent, view: WalletView, amount: int) -> tuple[str, dict[str, object]]:
    """The template key and its values for the sentence that names the deciding check, the shortfall if there is
    one, and the owner's choices."""
    mandate = view.mandate
    if event.tier is Tier.L1:
        return _template("explain.l1", amount=format_amount(amount))
    suffix = _tier_suffix(event.tier)
    delay = describe_duration(strings, mandate.delay)
    shown = format_amount(amount)
    check = event.deciding_check

    if check is DecidingCheck.ALLOWED:
        if event.tier is Tier.L3:
            return _template("explain.allowed.l3", amount=shown, limit=format_amount(mandate.c2))
        if amount > mandate.c1:
            return _template("explain.allowed.l2.payment", amount=shown, limit=format_amount(mandate.c1), delay=delay)
        return _template("explain.allowed.l2.daily", amount=shown, limit=format_amount(mandate.d1), delay=delay)

    if check is DecidingCheck.AFFORDABLE:
        if event.tier is Tier.L2:
            shortfall = max(amount - view.discretionary, 0)
            return _template(
                "explain.affordable.l2",
                amount=shown,
                discretionary=format_amount(view.discretionary),
                shortfall=format_amount(shortfall),
                delay=delay,
            )
        headroom = max(view.token_balance - mandate.reserve, 0)
        return _template(
            "explain.affordable.l3",
            amount=shown,
            reserve=format_amount(mandate.reserve),
            headroom=format_amount(headroom),
            shortfall=format_amount(max(amount - headroom, 0)),
        )

    if check is DecidingCheck.SAFE_NOW:
        family = "explain.safe_now.capsule" if event.capsule_id else "explain.safe_now"
        return _template(f"{family}.{suffix}", amount=shown, delay=delay, capsule=event.capsule_id)

    return _template(f"explain.allowance.{suffix}", amount=shown, delay=delay)


def explain(strings: Strings, event: DecisionEvent, view: WalletView, amount: int) -> str:
    """One sentence naming the deciding check, the shortfall if there is one, and the owner's choices."""
    key, params = explanation(strings, event, view, amount)
    return strings.render(key, **params)


class ObligationLine(Strict):
    payee_id: int
    amount: Uint256
    due: Uint64


class ExpectedIncomeItem(Strict):
    """Income the owner says to expect. It is shown and never counted."""

    amount: Uint256
    expected_at: Uint64


class ExpectedIncomeLine(Strict):
    amount: Uint256
    expected_at: Uint64
    counted: Literal[False] = False


class FinancialPanel(Strict):
    """B, R, obligations and D as the wallet reports them. Expected income is listed beside them and is neither
    added to B nor subtracted from or added to D."""

    balance: Uint256
    reserve: Uint256
    obligations: tuple[ObligationLine, ...]
    discretionary: Uint256
    expected_income: tuple[ExpectedIncomeLine, ...]


def build_panel(view: WalletView, expected_income: Sequence[ExpectedIncomeItem] = ()) -> FinancialPanel:
    return FinancialPanel(
        balance=view.token_balance,
        reserve=view.mandate.reserve,
        obligations=tuple(ObligationLine(payee_id=o.payee_id, amount=o.amount, due=o.due) for o in view.obligations),
        discretionary=view.discretionary,
        expected_income=tuple(ExpectedIncomeLine(amount=i.amount, expected_at=i.expected_at) for i in expected_income),
    )


def _date(timestamp: int) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d")


def panel_lines(strings: Strings, panel: FinancialPanel, payee_names: Mapping[int, str]) -> tuple[str, ...]:
    """The panel as sentences. Each expected income line says "not counted"."""
    lines = [
        strings.render("panel.balance", amount=format_amount(panel.balance)),
        strings.render("panel.reserve", amount=format_amount(panel.reserve)),
    ]
    for line in panel.obligations:
        lines.append(
            strings.render(
                "panel.obligation",
                amount=format_amount(line.amount),
                payee=payee_names.get(line.payee_id, str(line.payee_id)),
                date=_date(line.due),
            )
        )
    lines.append(strings.render("panel.discretionary", amount=format_amount(panel.discretionary)))
    for income in panel.expected_income:
        lines.append(
            strings.render(
                "panel.expected_income",
                amount=format_amount(income.amount),
                date=_date(income.expected_at),
                status=strings.render("panel.not_counted"),
            )
        )
    return tuple(lines)
