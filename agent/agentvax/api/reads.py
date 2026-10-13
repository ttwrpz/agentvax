"""Reading the wallet for the interface.

Every number comes from the chain. Every sentence is rendered from ``strings.json``, and explanations come from the
wallet's ``Decision`` events, the same way the agent's own replies do. Nothing here sends a transaction.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any

from eth_utils import to_checksum_address

from agentvax.amounts import format_amount
from agentvax.api.models import (
    AllowanceView,
    ChangeRow,
    ConfirmationView,
    FinancialView,
    IncomeRow,
    LogRow,
    MandateField,
    MandateView,
    ObligationRow,
    PayeeRow,
    PendingRow,
    RequesterOption,
    StateResponse,
)
from agentvax.api.services import Services
from agentvax.confirmation import ConfirmationContext, Requester, describe
from agentvax.explain import build_panel, explanation, panel_lines
from agentvax.mission import mandate_hash
from agentvax.text import Strings, describe_duration
from agentvax.types import (
    CapsuleAction,
    DecidingCheck,
    DecisionEvent,
    Flag,
    Mandate,
    Strict,
    Task,
    Tier,
    WalletView,
)

_ITEM_STATUS = {1: "queued", 2: "proposed", 3: "approved"}
_PENDING_STATUSES = frozenset(_ITEM_STATUS)
_CHANGE_KINDS = ("none", "add_payee", "mandate", "remove_obligation", "agent", "guardian", "unfreeze")
"""Mirrors ``ChangeKind`` in the wallet's types."""
_TOKEN_FIELDS = frozenset({"reserve", "c1", "d1", "c2"})
_DURATION_FIELDS = frozenset({"delay", "loosening_delay", "pressure_hold", "refill_period", "horizon"})
_NATIVE_FIELDS = frozenset({"fee_top_up_cap", "fee_daily_budget", "agent_balance_floor", "native_reserve"})
_CAPSULE_ACTIONS = {
    Task.PAYMENT: CapsuleAction.PAYMENT,
    Task.SCHEDULE_CREATE: CapsuleAction.SCHEDULE_CREATE,
    Task.SWEEP: CapsuleAction.SWEEP,
}
_BENIGN_FLAGS = Flag.KNOWN_PAYEE_IDENTITY


class StoredItem(Strict):
    """An item as the wallet stores it, with the fields the interface uses."""

    item_id: int
    intent_hash: str
    task: int
    flags: int
    payee_id: int
    amount: int
    tier: int
    status: int
    held: bool
    extra_hold: int


def stored_item(services: Services, item_id: int, block_number: int | None = None) -> StoredItem:
    wallet = services.chain.wallet(services.wallet)
    raw = wallet.functions.getItem(item_id).call(block_identifier=block_number or "latest")
    request = raw[1]
    return StoredItem(
        item_id=item_id,
        intent_hash="0x" + bytes(raw[0]).hex(),
        task=int(request[0]),
        flags=int(request[3]),
        payee_id=int(request[4]),
        amount=int(request[6]),
        tier=int(raw[2]),
        status=int(raw[4]),
        held=bool(raw[5]),
        extra_hold=int(raw[9]),
    )


def item_count(services: Services) -> int:
    return int(services.chain.wallet(services.wallet).functions.itemCount().call())


def chain_now(services: Services) -> int:
    """The time a transaction mined now would carry. The latest block can be old on a chain that mines only when
    asked, so the pending block's time is used when it is later."""
    web3 = services.chain.web3
    latest = int(web3.eth.get_block("latest")["timestamp"])
    try:
        pending = int(web3.eth.get_block("pending")["timestamp"])
    except (ValueError, KeyError, TypeError):
        return latest
    return max(latest, pending)


def payee_label(services: Services, payee_id: int) -> str:
    name = services.agent.payee_name(payee_id)
    return name if name is not None else services.strings.render("payee.unnamed", id=payee_id)


def needs_confirmation(flags: int, held: bool, matching: Sequence[int]) -> bool:
    """A proposal that carries a flag beyond the ordinary mark of a known payee, a pressure hold or a matching
    alert needs the considered confirmation."""
    return bool(Flag(flags) & ~_BENIGN_FLAGS) or held or bool(matching)


def matching_capsules(services: Services, item: StoredItem) -> list[int]:
    action = _CAPSULE_ACTIONS.get(Task(item.task))
    if action is None:
        return []
    wallet = services.chain.wallet(services.wallet)
    full, partial, _restriction, _fail_closed = wallet.functions.matchCapsules(int(action), item.flags).call()
    return [int(i) for i in (*full, *partial)]


def requested_account(services: Services, identity_hash: str, current: str) -> str | None:
    """The newest address that something asked to pay under this payee's identity, if it differs from the
    account on file."""
    wallet = services.chain.wallet(services.wallet)
    logs = wallet.events.PayeeChangeRequested().get_logs(from_block=services.log_from_block, to_block="latest")
    wanted = bytes.fromhex(identity_hash[2:])
    for entry in reversed(logs):
        if bytes(entry["args"]["identityHash"]) != wanted:
            continue
        account = to_checksum_address(entry["args"]["account"])
        return account if account != to_checksum_address(current) else None
    return None


def confirmation_context(
    services: Services, view: WalletView, item: StoredItem, matching: Sequence[int]
) -> ConfirmationContext | None:
    """What the considered confirmation shows for ``item``, or None when none is needed."""
    if not needs_confirmation(item.flags, item.held, matching):
        return None
    payee = view.payee(item.payee_id)
    if payee is None:
        return None
    return ConfirmationContext(
        payee_name=payee_label(services, item.payee_id),
        current_account=payee.account,
        requested_account=requested_account(services, payee.identity_hash, payee.account),
        paid_count=payee.paid_count,
        max_paid=payee.max_paid,
        matching_capsules=tuple(matching),
        flags=item.flags,
        pressure_hold=view.mandate.pressure_hold,
    )


def requester_options(strings: Strings) -> list[RequesterOption]:
    return [
        RequesterOption(value=requester.name.lower(), label=strings.render(f"confirm.requester.{requester.name.lower()}"))  # type: ignore[arg-type]
        for requester in Requester
    ]


# ---------------------------------------------------------------------------------------------- state


def _mandate_value(strings: Strings, name: str, value: int) -> str:
    if name in _TOKEN_FIELDS:
        return strings.render("value.amount", amount=format_amount(value))
    if name in _DURATION_FIELDS:
        return describe_duration(strings, value)
    if name == "expiry":
        return datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    if name in _NATIVE_FIELDS:
        return strings.render("value.native", wei=value)
    return str(value)


def mission_text(services: Services, view: WalletView) -> str | None:
    """The mission stated with the current mandate, if the wallet's record of it matches the mandate fingerprint."""
    wallet = services.chain.wallet(services.wallet)
    for entry in reversed(wallet.events.MissionStated().get_logs(from_block=services.log_from_block, to_block="latest")):
        text = str(entry["args"]["mission"])
        if mandate_hash(text, view.mandate) == view.mandate_hash:
            return text
        return None
    return None


def mandate_view(services: Services, view: WalletView) -> MandateView:
    strings = services.strings
    m: Mandate = view.mandate
    lines = [
        strings.render("mandate.reserve", amount=format_amount(m.reserve)),
        strings.render("mandate.c1", amount=format_amount(m.c1)),
        strings.render("mandate.d1", amount=format_amount(m.d1)),
        strings.render("mandate.c2", amount=format_amount(m.c2), delay=describe_duration(strings, m.delay)),
        strings.render("mandate.loosening", delay=describe_duration(strings, m.loosening_delay)),
        strings.render("mandate.pressure_hold", delay=describe_duration(strings, m.pressure_hold)),
        strings.render("mandate.hash", digest=view.mandate_hash),
    ]
    fields = [
        MandateField(
            name=name,
            label=strings.render(f"mandate.field.{name}"),
            value=_mandate_value(strings, name, int(getattr(m, name))),
        )
        for name in Mandate.model_fields
    ]
    return MandateView(mission=mission_text(services, view), lines=lines, fields=fields, mandate_hash=view.mandate_hash)


def financial_view(services: Services, view: WalletView) -> FinancialView:
    strings = services.strings
    names = {p.payee_id: payee_label(services, p.payee_id) for p in view.payees}
    panel = build_panel(view, services.income.items())
    lines = panel_lines(strings, panel, names)
    return FinancialView(
        balance=format_amount(panel.balance),
        balance_units=panel.balance,
        reserve=format_amount(panel.reserve),
        reserve_units=panel.reserve,
        discretionary=format_amount(panel.discretionary),
        discretionary_units=panel.discretionary,
        obligations=[
            ObligationRow(
                payee_id=o.payee_id,
                payee=names.get(o.payee_id, str(o.payee_id)),
                amount=format_amount(o.amount),
                amount_units=o.amount,
                due=o.due,
                text=line,
            )
            for o, line in zip(panel.obligations, lines[2 : 2 + len(panel.obligations)], strict=True)
        ],
        expected_income=[
            IncomeRow(
                amount=format_amount(i.amount),
                amount_units=i.amount,
                expected_at=i.expected_at,
                counted=i.counted,
                text=line,
            )
            for i, line in zip(panel.expected_income, lines[3 + len(panel.obligations) :], strict=True)
        ],
        lines=list(lines),
    )


def allowance_view(services: Services, view: WalletView) -> AllowanceView:
    maximum = view.mandate.allowance_max
    points = round(min(view.allowance_points, float(maximum)), 1)
    return AllowanceView(
        points=points,
        maximum=maximum,
        fraction=0.0 if maximum == 0 else min(1.0, view.allowance_points / maximum),
        text=services.strings.render("allowance.text", points=f"{points:g}", maximum=maximum),
    )


def pending_rows(services: Services, view: WalletView, now: int) -> list[PendingRow]:
    strings = services.strings
    wallet = services.chain.wallet(services.wallet)
    rows: list[PendingRow] = []
    for item_id in range(1, item_count(services) + 1):
        item = stored_item(services, item_id)
        if item.status not in _PENDING_STATUSES:
            continue
        status = _ITEM_STATUS[item.status]
        ready: int | None = None
        if status != "proposed":
            ready = int(wallet.functions.itemReadyAt(item_id).call())
        left = None if ready is None else max(ready - now, 0)
        capsules = matching_capsules(services, item)
        context = confirmation_context(services, view, item, capsules) if status == "proposed" else None
        confirmation = None
        if context is not None:
            confirmation = ConfirmationView(
                payee_name=context.payee_name,
                lines=list(describe(strings, context)),
                requesters=requester_options(strings),
                hold_seconds=context.pressure_hold,
            )
        payee = payee_label(services, item.payee_id)
        rows.append(
            PendingRow(
                item_id=item_id,
                status=status,  # type: ignore[arg-type]
                tier=item.tier,
                task=Task(item.task).name.lower(),
                payee_id=item.payee_id,
                payee=payee,
                amount=format_amount(item.amount),
                amount_units=item.amount,
                text=strings.render(f"pending.{status}", amount=format_amount(item.amount), payee=payee),
                ready_at=ready,
                seconds_left=left,
                flags=item.flags,
                flag_labels=[strings.render(f"flag.{flag.name.lower()}") for flag in Flag if flag and item.flags & flag],  # type: ignore[union-attr]
                held=item.held,
                extra_hold=item.extra_hold,
                matching_capsules=capsules,
                can_approve=status == "proposed",
                can_execute=status != "proposed" and left == 0,
                confirmation=confirmation,
            )
        )
    return rows


def change_rows(services: Services, now: int) -> list[ChangeRow]:
    strings = services.strings
    wallet = services.chain.wallet(services.wallet)
    start = services.log_from_block
    closed = {
        int(e["args"]["changeId"])
        for event in ("ChangeApplied", "ChangeCancelled")
        for e in getattr(wallet.events, event)().get_logs(from_block=start, to_block="latest")
    }
    rows: list[ChangeRow] = []
    for entry in wallet.events.ChangeProposed().get_logs(from_block=start, to_block="latest"):
        change_id = int(entry["args"]["changeId"])
        if change_id in closed:
            continue
        kind = _CHANGE_KINDS[int(entry["args"]["kind"])]
        ready = int(entry["args"]["readyAt"])
        left = max(ready - now, 0)
        rows.append(
            ChangeRow(
                change_id=change_id,
                kind=kind,
                kind_label=strings.render(f"change.kind.{kind}"),
                ready_at=ready,
                seconds_left=left,
                name=services.names.proposed.get(change_id),
                text=strings.render("change.ready" if left == 0 else "change.waiting"),
                can_apply=left == 0,
            )
        )
    return rows


def payee_rows(services: Services, view: WalletView) -> list[PayeeRow]:
    strings = services.strings
    return [
        PayeeRow(
            payee_id=p.payee_id,
            name=payee_label(services, p.payee_id),
            account=p.account,
            active=p.active,
            paid_count=p.paid_count,
            text=strings.render("payee.active" if p.active else "payee.inactive"),
        )
        for p in view.payees
    ]


def _amount_of(services: Services, receipt: Any, intent_hash: bytes, block_number: int) -> int:
    chain = services.chain
    wallet = chain.wallet(services.wallet)
    for entry in chain.events(receipt, wallet, "Executed"):
        if bytes(entry["args"]["intentHash"]) == intent_hash:
            return int(entry["args"]["amount"])
    for name in ("Queued", "Proposed"):
        for entry in chain.events(receipt, wallet, name):
            if bytes(entry["args"]["intentHash"]) == intent_hash:
                return stored_item(services, int(entry["args"]["itemId"]), block_number).amount
    for entry in chain.events(receipt, wallet, "ScheduleCreated"):
        return int(entry["args"]["amount"])
    return 0


def log_rows(services: Services) -> list[LogRow]:
    """The newest decisions of the wallet, newest first, each explained from its own ``Decision`` event and the
    wallet as it stood at that block."""
    chain = services.chain
    web3 = chain.web3
    wallet = chain.wallet(services.wallet)
    entries = wallet.events.Decision().get_logs(from_block=services.log_from_block, to_block="latest")
    views: dict[int, WalletView] = {}
    rows: list[LogRow] = []
    for entry in reversed(entries[-services.log_limit :]):
        block_number = int(entry["blockNumber"])
        tx_hash = "0x" + bytes(entry["transactionHash"]).hex()
        receipt = web3.eth.get_transaction_receipt(entry["transactionHash"])
        event = DecisionEvent(
            intent_hash="0x" + bytes(entry["args"]["intentHash"]).hex(),
            tier=Tier(int(entry["args"]["tier"])),
            deciding_check=DecidingCheck(int(entry["args"]["decidingCheck"])),
            capsule_id=int(entry["args"]["capsuleId"]),
        )
        amount = _amount_of(services, receipt, bytes(entry["args"]["intentHash"]), block_number)
        if block_number not in views:
            views[block_number] = chain.wallet_view(services.wallet, block_number)
        key, params = explanation(services.strings, event, views[block_number], amount)
        rows.append(
            LogRow(
                tier=int(event.tier),
                deciding_check=event.deciding_check.name.lower(),
                amount=format_amount(amount),
                at=int(web3.eth.get_block(block_number)["timestamp"]),
                text=services.strings.render(key, **params),
                tx_hash=tx_hash,
                link=services.transaction_link(tx_hash),
            )
        )
    return rows


def build_state(services: Services) -> StateResponse:
    view = services.chain.wallet_view(services.wallet)
    now = chain_now(services)
    return StateResponse(
        mode=services.mode,
        wallet=services.wallet,
        chain_id=services.chain.chain_id,
        now=now,
        frozen=view.frozen,
        mandate=mandate_view(services, view),
        financial=financial_view(services, view),
        allowance=allowance_view(services, view),
        pending=pending_rows(services, view, now),
        changes=change_rows(services, now),
        payees=payee_rows(services, view),
        log=log_rows(services),
    )
