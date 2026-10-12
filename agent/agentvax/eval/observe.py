"""Reads what the judge needs from the chain: wallet projections, decoded events and transactions of a range.

Projections are taken at one block. Each wallet ``Executed`` event carries an ``ExecutionContext`` so the judge
can check the L1 envelope without reading the chain.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Literal

from eth_utils import keccak, to_checksum_address
from hexbytes import HexBytes
from pydantic import JsonValue
from web3.contract import Contract

from agentvax.chain.client import SAVINGS_VAULT, ChainClient
from agentvax.chain.deploy import Deployment
from agentvax.eval.judge import (
    ChangeState,
    DecodedEvent,
    ExecutionContext,
    ItemState,
    ScheduleState,
    StateProjection,
    WalletState,
)
from agentvax.types import Mandate, ObligationView, PayeeView, Strict

Source = Literal["wallet", "token", "vault", "bulletin"]


class TxRecord(Strict):
    """One mined transaction in an observed range."""

    tx_hash: str
    block_number: int
    sender: str
    """The role of the sender, for example ``agent:A``, ``owner:B`` or ``keeper``, and ``unknown`` otherwise."""
    target: str
    """``wallet:A``, ``token``, ``vault``, ``bulletin`` or ``other``."""
    entry_point: str
    """The function called, by name: plain for a wallet function (``submit``), prefixed with the contract for the
    others (``bulletin.attest``). ``0x`` and the selector if the target's ABI has no such function."""
    gas_used: int
    status: int


def _hex(value: bytes) -> str:
    return "0x" + bytes(value).hex()


def _json(value: Any) -> JsonValue:
    if isinstance(value, (bytes, bytearray, HexBytes)):
        return _hex(value)
    if isinstance(value, Mapping):
        return {str(k): _json(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json(v) for v in value]
    if isinstance(value, bool) or value is None or isinstance(value, (int, str)):
        return value
    raise TypeError(f"cannot record a value of type {type(value).__name__}")


def _abi_type(param: Mapping[str, Any]) -> str:
    if str(param["type"]).startswith("tuple"):
        inner = ",".join(_abi_type(c) for c in param["components"])
        return f"({inner}){str(param['type'])[len('tuple'):]}"
    return str(param["type"])


def _mandate(values: Sequence[Any]) -> Mandate:
    return Mandate(**{name: int(v) for name, v in zip(Mandate.model_fields, values, strict=True)})


class Observer:
    """Reads one deployment's contracts. Holds no key."""

    def __init__(self, client: ChainClient, deployment: Deployment, roles: Mapping[str, str]) -> None:
        """``roles`` maps a sender address to a role label for the transaction records."""
        self._client = client
        self._w3 = client.web3
        self._deployment = deployment
        self._roles = {k.lower(): v for k, v in roles.items()}
        self._wallets: dict[str, Contract] = {w.label: client.wallet(w.address) for w in deployment.wallets}
        self._token = client.token(deployment.mock_usd.address)
        self._vault = client.contract(SAVINGS_VAULT, deployment.savings_vault.address)
        self._bulletin = client.bulletin(deployment.threat_bulletin.address)
        self._by_address: dict[str, tuple[Source, str | None, Contract]] = {
            deployment.mock_usd.address.lower(): ("token", None, self._token),
            deployment.savings_vault.address.lower(): ("vault", None, self._vault),
            deployment.threat_bulletin.address.lower(): ("bulletin", None, self._bulletin),
        }
        for label, contract in self._wallets.items():
            self._by_address[contract.address.lower()] = ("wallet", label, contract)
        self._topics: dict[str, dict[bytes, str]] = {}
        self._selectors: dict[str, dict[bytes, str]] = {}
        for address, (_, _, contract) in self._by_address.items():
            topics: dict[bytes, str] = {}
            selectors: dict[bytes, str] = {}
            for item in contract.abi:
                signature = f"{item.get('name')}({','.join(_abi_type(i) for i in item.get('inputs', []))})"
                if item.get("type") == "event":
                    topics[keccak(text=signature)] = str(item["name"])
                elif item.get("type") == "function":
                    selectors[keccak(text=signature)[:4]] = str(item["name"])
            self._topics[address] = topics
            self._selectors[address] = selectors

    # ------------------------------------------------------------------------------------ blocks

    def latest_block(self) -> int:
        return int(self._w3.eth.block_number)

    def block_time(self, number: int) -> int:
        """The timestamp of block ``number`` as the chain holds it now. Never cached across calls: after
        ``evm_revert`` the same block number is mined again with another time, so a cache keyed by number would
        give a later case the times of an earlier one."""
        return int(self._w3.eth.get_block(number)["timestamp"])

    # ------------------------------------------------------------------------------------ projection

    def projection(self, labels: Sequence[str], block: int | None = None) -> StateProjection:
        """The state of the wallets ``labels`` at ``block`` (the latest block if None)."""
        at = self.latest_block() if block is None else block
        capsule_count = int(self._bulletin.functions.capsuleCount().call(block_identifier=at))
        return StateProjection(
            block_number=at,
            block_time=self.block_time(at),
            token=self._deployment.mock_usd.address,
            vault=self._deployment.savings_vault.address,
            bulletin=self._deployment.threat_bulletin.address,
            capsule_count=capsule_count,
            wallets=tuple(self._wallet_state(label, at, capsule_count) for label in labels),
        )

    def _wallet_state(self, label: str, at: int, capsule_count: int) -> WalletState:
        w = self._wallets[label]

        def read(name: str, *args: Any) -> Any:
            return getattr(w.functions, name)(*args).call(block_identifier=at)

        address = w.address
        payees = []
        for payee_id in range(1, int(read("payeeCount")) + 1):
            identity, account, active, paid_count, max_paid = read("getPayee", payee_id)
            payees.append(
                PayeeView(
                    payee_id=payee_id,
                    identity_hash=_hex(identity),
                    account=to_checksum_address(account),
                    active=bool(active),
                    paid_count=int(paid_count),
                    max_paid=int(max_paid),
                )
            )
        obligations = []
        for obligation_id in read("openObligationIds"):
            payee_id, due, schedule_id, _open, by_agent, amount = read("getObligation", obligation_id)
            obligations.append(
                ObligationView(
                    obligation_id=int(obligation_id),
                    payee_id=int(payee_id),
                    amount=int(amount),
                    due=int(due),
                    schedule_id=int(schedule_id),
                    by_agent=bool(by_agent),
                )
            )
        created, _active = read("scheduleCounts")
        schedules = []
        for schedule_id in range(1, int(created) + 1):
            payee_id, active, runs_done, next_due, obligation_id, terms, amount = read("getSchedule", schedule_id)
            schedules.append(
                ScheduleState(
                    schedule_id=schedule_id,
                    payee_id=int(payee_id),
                    active=bool(active),
                    runs_done=int(runs_done),
                    next_due=int(next_due),
                    obligation_id=int(obligation_id),
                    period=int(terms[0]),
                    first_due=int(terms[1]),
                    max_runs=int(terms[2]),
                    amount=int(amount),
                )
            )
        items = []
        for item_id in range(1, int(read("itemCount")) + 1):
            (intent, req, tier, approved_afford, status, hold, queued_at, approved_at, lock, extra, terms) = read(
                "getItem", item_id
            )
            task, band, source, flags, payee_id, obligation_ref, amount = req
            items.append(
                ItemState(
                    item_id=item_id,
                    intent_hash=_hex(intent),
                    task=int(task),
                    band=int(band),
                    source=int(source),
                    flags=int(flags),
                    payee_id=int(payee_id),
                    obligation_ref=int(obligation_ref),
                    amount=int(amount),
                    tier=int(tier),
                    approved_afford=int(approved_afford),
                    status=int(status),
                    hold=bool(hold),
                    queued_at=int(queued_at),
                    approved_at=int(approved_at),
                    lock_snapshot=int(lock),
                    extra_hold=int(extra),
                    period=int(terms[0]),
                    first_due=int(terms[1]),
                    max_runs=int(terms[2]),
                )
            )
        changes = []
        for change_id in range(1, int(read("changeCount")) + 1):
            change, _proposed = read("getChange", change_id)
            kind, status, proposed_at, ready_at, account, obligation_id, epoch, key, base = change
            changes.append(
                ChangeState(
                    change_id=change_id,
                    kind=int(kind),
                    status=int(status),
                    proposed_at=int(proposed_at),
                    ready_at=int(ready_at),
                    account=to_checksum_address(account),
                    obligation_id=int(obligation_id),
                    epoch=int(epoch),
                    key=_hex(key),
                    base_mandate_hash=_hex(base),
                )
            )
        mission_hash, mandate_hash = read("mandateHashes")
        dismissed = tuple(i for i in range(1, capsule_count + 1) if read("capsuleDismissed", i))
        return WalletState(
            label=label,  # type: ignore[arg-type]
            address=to_checksum_address(address),
            owner=to_checksum_address(read("owner")),
            agent=to_checksum_address(read("agent")),
            guardian=to_checksum_address(read("guardian")),
            token_balance=int(self._token.functions.balanceOf(address).call(block_identifier=at)),
            native_balance=int(self._w3.eth.get_balance(address, block_identifier=at)),
            vault_balance=int(self._vault.functions.balanceOf(address).call(block_identifier=at)),
            mandate=_mandate(read("mandate")),
            mission_hash=_hex(mission_hash),
            mandate_hash=_hex(mandate_hash),
            frozen=bool(read("frozen")),
            allowance_units=int(read("allowance")),
            allowance_unit=int(read("ALLOWANCE_UNIT")),
            nonce=int(read("nonce")),
            payees=tuple(payees),
            obligations=tuple(obligations),
            schedules=tuple(schedules),
            items=tuple(items),
            changes=tuple(changes),
            capsule_cursor=int(read("capsuleCursor")),
            tracked_capsules=tuple(int(i) for i in read("trackedCapsules")),
            dismissed_capsules=dismissed,
        )

    # ------------------------------------------------------------------------------------ events

    def events(self, first_block: int, last_block: int) -> tuple[DecodedEvent, ...]:
        """Every log of the deployment's contracts in ``[first_block, last_block]``, decoded. A log whose topic is
        not in the emitting contract's ABI is a harness error."""
        if last_block < first_block:
            return ()
        logs = self._w3.eth.get_logs(
            {
                "fromBlock": first_block,
                "toBlock": last_block,
                "address": [to_checksum_address(a) for a in self._by_address],
            }
        )
        decoded = []
        times: dict[int, int] = {}
        for log in logs:
            address = str(log["address"]).lower()
            source, label, contract = self._by_address[address]
            topic = bytes(log["topics"][0])
            name = self._topics[address].get(topic)
            if name is None:
                raise ValueError(f"log with unknown topic {_hex(topic)} at {address}")
            data = getattr(contract.events, name)().process_log(log)
            args = {str(k): _json(v) for k, v in data["args"].items()}
            block = int(log["blockNumber"])
            if block not in times:
                times[block] = self.block_time(block)
            event = DecodedEvent(
                block_number=block,
                block_time=times[block],
                tx_hash=_hex(log["transactionHash"]),
                log_index=int(log["logIndex"]),
                source=source,
                wallet=label,  # type: ignore[arg-type]
                address=to_checksum_address(address),
                name=name,
                args=args,
            )
            if source == "wallet" and name == "Executed" and label is not None:
                event = event.model_copy(update={"context": self._context(label, event)})
            decoded.append(event)
        return tuple(decoded)

    def _context(self, label: str, event: DecodedEvent) -> ExecutionContext:
        w = self._wallets[label]
        at = event.block_number
        previous = at - 1
        mandate = _mandate(w.functions.mandate().call(block_identifier=at))
        agent = to_checksum_address(w.functions.agent().call(block_identifier=at))
        task = int(event.args["task"])  # type: ignore[arg-type]
        active: bool | None = None
        discretionary: int | None = None
        if task == 1:
            to = str(event.args["to"]).lower()
            active = False
            for payee_id in range(1, int(w.functions.payeeCount().call(block_identifier=previous)) + 1):
                _identity, account, is_active, _count, _max = w.functions.getPayee(payee_id).call(
                    block_identifier=previous
                )
                if str(account).lower() == to and bool(is_active):
                    active = True
                    break
        elif task == 3:
            discretionary = int(w.functions.discretionary(0).call(block_identifier=previous))
        return ExecutionContext(
            mandate=mandate, agent=agent, payee_active_before=active, discretionary_before=discretionary
        )

    # ------------------------------------------------------------------------------------ transactions

    def transactions(self, first_block: int, last_block: int) -> tuple[TxRecord, ...]:
        records = []
        for number in range(first_block, last_block + 1):
            block = self._w3.eth.get_block(number, full_transactions=True)
            for tx in block["transactions"]:
                receipt = self._w3.eth.get_transaction_receipt(tx["hash"])
                to = str(tx.get("to") or "").lower()
                known = self._by_address.get(to)
                if known is None:
                    target = "other"
                else:
                    target = f"wallet:{known[1]}" if known[0] == "wallet" else known[0]
                data = bytes(tx.get("input") or b"")
                selector = data[:4]
                name = self._selectors.get(to, {}).get(selector) if len(selector) == 4 else None
                if name is None:
                    name = _hex(selector) if selector else "transfer_of_native"
                entry = name if target.startswith("wallet:") else f"{target}.{name}"
                records.append(
                    TxRecord(
                        tx_hash=_hex(tx["hash"]),
                        block_number=number,
                        sender=self._roles.get(str(tx["from"]).lower(), "unknown"),
                        target=target,
                        entry_point=entry,
                        gas_used=int(receipt["gasUsed"]),
                        status=int(receipt["status"]),
                    )
                )
        return tuple(records)
