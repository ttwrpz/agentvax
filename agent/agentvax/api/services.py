"""What the interface is built from.

``Services`` holds the agent (which has only the agent session key), the chain client, the wallet, the owner
actions, the wording and the explorer address. The owner key lives only inside ``OwnerActions``. The agent never
receives it, and no endpoint that reads the wallet or talks to the agent can reach it.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from eth_utils import to_checksum_address
from web3.types import TxReceipt

from agentvax.api.models import Mode
from agentvax.capsules import AttackConfirmation, ConfirmedAttack, confirm_attack
from agentvax.chain import agent as keeper_actions
from agentvax.chain import owner as owner_actions
from agentvax.chain.client import ChainClient, Signer
from agentvax.chain.owner import ProposedChange
from agentvax.explain import ExpectedIncomeItem
from agentvax.memory import MemoryStore
from agentvax.names import identity_hash
from agentvax.owner_tools import PayeeAddition, apply_payee_addition
from agentvax.runtime import Agent
from agentvax.text import Strings
from agentvax.types import Strict


class PayeeNameFile(Strict):
    """The saved form of ``PayeeNames``."""

    names: dict[int, str]
    proposed: dict[int, str]


class PayeeNames:
    """The names the owner gave payees. They live off chain, so the interface keeps them, in a file if it
    is given one. A name is only a label for the reader and the validator. The chain decides who may be paid."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = path
        self.names: dict[int, str] = {}
        self.proposed: dict[int, str] = {}
        if path is not None and path.is_file():
            saved = PayeeNameFile.model_validate_json(path.read_text(encoding="utf-8"))
            self.names = dict(saved.names)
            self.proposed = dict(saved.proposed)

    def save(self) -> None:
        if self._path is None:
            return
        body = PayeeNameFile(names=self.names, proposed=self.proposed).model_dump_json(indent=2)
        temporary = self._path.with_suffix(self._path.suffix + ".tmp")
        temporary.write_text(body, encoding="utf-8")
        temporary.replace(self._path)


class ExpectedIncomeBook:
    """Income the owner says to expect. It is shown beside the wallet's numbers and is never counted."""

    def __init__(self) -> None:
        self._items: list[ExpectedIncomeItem] = []
        self._lock = threading.Lock()

    def add(self, item: ExpectedIncomeItem) -> None:
        with self._lock:
            self._items.append(item)

    def items(self) -> tuple[ExpectedIncomeItem, ...]:
        with self._lock:
            return tuple(self._items)


class OwnerActions:
    """The owner's hands. It holds the owner signer and nothing else holds it."""

    def __init__(
        self,
        *,
        client: ChainClient,
        signer: Signer,
        wallet: str,
        agent: Agent,
        memory: MemoryStore,
        names: PayeeNames,
        guard_version: int,
    ) -> None:
        self._client = client
        self._signer = signer
        self._wallet = to_checksum_address(wallet)
        self._agent = agent
        self._memory = memory
        self._names = names
        self._guard_version = guard_version

    @property
    def address(self) -> str:
        return to_checksum_address(self._signer.address)

    @staticmethod
    def _hash(receipt: TxReceipt) -> str:
        return "0x" + bytes(receipt["transactionHash"]).hex()

    def approve(self, item_id: int) -> str:
        return self._hash(owner_actions.approve(self._client, self._signer, self._wallet, item_id))

    def cancel(self, item_id: int) -> str:
        return self._hash(owner_actions.cancel(self._client, self._signer, self._wallet, item_id))

    def extend_hold(self, item_id: int, extra_seconds: int) -> str:
        return self._hash(owner_actions.extend_hold(self._client, self._signer, self._wallet, item_id, extra_seconds))

    def execute(self, item_id: int) -> str:
        """Anyone may execute a pending item once it is ready. The wallet checks every condition again."""
        return self._hash(keeper_actions.execute_pending(self._client, self._signer, self._wallet, item_id))

    def freeze(self) -> str:
        return self._hash(owner_actions.freeze(self._client, self._signer, self._wallet))

    def propose_payee(self, name: str, account: str) -> ProposedChange:
        proposed = owner_actions.propose_add_payee(
            self._client, self._signer, self._wallet, identity_hash(name), to_checksum_address(account)
        )
        self._names.proposed[proposed.change_id] = name
        self._names.save()
        return proposed

    def apply_payee(self, change_id: int) -> PayeeAddition:
        added = apply_payee_addition(self._client, self._signer, self._wallet, change_id, self._memory)
        name = self._names.proposed.pop(change_id, None)
        if name is not None:
            self._names.names[added.payee_id] = name
            self._agent.name_payee(added.payee_id, name)
        self._names.save()
        return added

    def cancel_change(self, change_id: int) -> str:
        receipt = owner_actions.cancel_change(self._client, self._signer, self._wallet, change_id)
        if self._names.proposed.pop(change_id, None) is not None:
            self._names.save()
        return self._hash(receipt)

    def confirm_attack(self, attack: ConfirmedAttack, publish: bool) -> AttackConfirmation:
        return confirm_attack(
            self._client, self._signer, self._wallet, self._memory, attack, self._guard_version, publish
        )


@dataclass(frozen=True)
class Services:
    """Everything the endpoints use. ``allowed_origins`` are the origins the page is served from, such as
    ``http://127.0.0.1:8765``. ``log_from_block`` is where the action log starts reading events."""

    agent: Agent
    chain: ChainClient
    wallet: str
    owner: OwnerActions
    strings: Strings
    explorer_url: str | None
    allowed_origins: tuple[str, ...]
    mode: Mode
    names: PayeeNames
    income: ExpectedIncomeBook = field(default_factory=ExpectedIncomeBook)
    log_from_block: int = 0
    log_limit: int = 30
    chain_lock: threading.Lock = field(default_factory=threading.Lock)
    """Serialises the requests that send transactions, so two nonces are never raced."""

    def __post_init__(self) -> None:
        if not self.allowed_origins:
            raise ValueError("at least one allowed origin is needed")
        for origin in self.allowed_origins:
            parts = urlsplit(origin)
            if parts.scheme not in ("http", "https") or not parts.netloc or parts.path not in ("", "/"):
                raise ValueError(f"{origin!r} is not an origin")
        if self.explorer_url is not None and urlsplit(self.explorer_url).scheme not in ("http", "https"):
            raise ValueError("the explorer address must start with http or https")

    @property
    def allowed_hosts(self) -> frozenset[str]:
        return frozenset(urlsplit(origin).netloc for origin in self.allowed_origins)

    def transaction_link(self, tx_hash: str | None) -> str | None:
        if self.explorer_url is None or tx_hash is None:
            return None
        return f"{self.explorer_url.rstrip('/')}/tx/{tx_hash}"

