"""Web3 client for the AgentVax contracts.

Refuses any chain id outside ``ALLOWED_CHAIN_IDS``, re-reading ``eth_chainId`` before each build and before
signing. Holds no key: every transaction is signed by a signer passed in by the caller.
"""

from __future__ import annotations

from typing import Any, Protocol

from eth_abi import decode as abi_decode
from eth_account.datastructures import SignedTransaction
from eth_utils import keccak, to_checksum_address
from web3 import Web3
from web3.contract import Contract
from web3.contract.contract import ContractFunction
from web3.exceptions import ContractLogicError, TimeExhausted
from web3.logs import DISCARD
from web3.types import EventData, TxReceipt

from agentvax.chain.artifacts import ArtifactStore
from agentvax.config import ChainTuning, RuntimeConfig
from agentvax.types import (
    ALLOWED_CHAIN_IDS,
    DecidingCheck,
    DecisionEvent,
    Mandate,
    ObligationView,
    PayeeView,
    Tier,
    WalletView,
)

POLICY_WALLET = "src/PolicyWallet.sol:PolicyWallet"
MOCK_USD = "src/MockUSD.sol:MockUSD"
SAVINGS_VAULT = "src/SavingsVault.sol:SavingsVault"
THREAT_BULLETIN = "src/ThreatBulletin.sol:ThreatBulletin"


class Signer(Protocol):
    """Anything that signs transactions locally, such as ``eth_account`` ``LocalAccount``."""

    @property
    def address(self) -> str: ...

    def sign_transaction(self, transaction_dict: dict[str, Any]) -> SignedTransaction: ...


class UnsupportedChain(RuntimeError):
    """The node reports a chain id that is not an allowed test network, or not the one expected."""

    def __init__(self, chain_id: int, expected: int | None = None) -> None:
        self.chain_id = chain_id
        self.expected = expected
        if expected is not None and chain_id in ALLOWED_CHAIN_IDS:
            message = f"node reports chain id {chain_id}, expected {expected}"
        else:
            message = f"chain id {chain_id} is not an allowed test network {sorted(ALLOWED_CHAIN_IDS)}"
        super().__init__(message)


class TransactionFailed(RuntimeError):
    """A transaction was mined with status 0, or did not get a receipt in time."""

    def __init__(self, tx_hash: str, reason: str) -> None:
        self.tx_hash = tx_hash
        super().__init__(f"transaction {tx_hash} failed: {reason}")


class TransactionReverted(RuntimeError):
    """Gas estimation showed the transaction would revert. Nothing was signed or sent."""

    def __init__(self, error_name: str, args: tuple[Any, ...], data: str) -> None:
        self.error_name = error_name
        self.args_decoded = args
        self.data = data
        super().__init__(f"would revert with {error_name}{args}")


def decode_revert(abi: tuple[dict[str, Any], ...] | list[dict[str, Any]], data: str) -> tuple[str, tuple[Any, ...]]:
    """Name and arguments of the custom error in ``data``, looked up in ``abi``. Unknown errors are named by
    their selector."""
    raw = bytes.fromhex(data[2:] if data.startswith("0x") else data)
    if len(raw) < 4:
        return ("EmptyRevert", ())
    selector, body = raw[:4], raw[4:]
    for item in abi:
        if item.get("type") != "error":
            continue
        types = [_abi_type(i) for i in item.get("inputs", [])]
        signature = f"{item['name']}({','.join(types)})"
        if keccak(text=signature)[:4] == selector:
            return (item["name"], tuple(abi_decode(types, body)) if types else ())
    if selector == bytes.fromhex("08c379a0"):
        return ("Error", tuple(abi_decode(["string"], body)))
    if selector == bytes.fromhex("4e487b71"):
        return ("Panic", tuple(abi_decode(["uint256"], body)))
    return ("0x" + selector.hex(), ())


def _abi_type(param: dict[str, Any]) -> str:
    if param["type"].startswith("tuple"):
        inner = ",".join(_abi_type(c) for c in param["components"])
        return f"({inner}){param['type'][len('tuple') :]}"
    return str(param["type"])


def _hex32(value: bytes) -> str:
    return "0x" + bytes(value).hex()


class ChainClient:
    """Reads and writes the AgentVax contracts on one allowed test network."""

    def __init__(
        self,
        rpc_url: str,
        artifacts: ArtifactStore,
        tuning: ChainTuning,
        expected_chain_id: int | None = None,
    ) -> None:
        self._w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": tuning.rpc_timeout_seconds}))
        self._expected = expected_chain_id
        self._artifacts = artifacts
        self._tuning = tuning
        self._chain_id = self._read_allowed_chain_id()

    @classmethod
    def from_config(cls, config: RuntimeConfig) -> ChainClient:
        store = ArtifactStore(config.contracts_dir, config.artifacts_dir, config.forge_executable)
        return cls(config.network.rpc_url, store, config.tuning, expected_chain_id=config.network.chain_id)

    # ------------------------------------------------------------------------------------ basics

    @property
    def chain_id(self) -> int:
        return self._chain_id

    @property
    def web3(self) -> Web3:
        """The underlying connection, for reads."""
        return self._w3

    @property
    def artifacts(self) -> ArtifactStore:
        return self._artifacts

    def _read_allowed_chain_id(self) -> int:
        chain_id = int(self._w3.eth.chain_id)
        if chain_id not in ALLOWED_CHAIN_IDS:
            raise UnsupportedChain(chain_id)
        if self._expected is not None and chain_id != self._expected:
            raise UnsupportedChain(chain_id, self._expected)
        return chain_id

    def contract(self, fqn: str, address: str) -> Contract:
        return self._w3.eth.contract(address=to_checksum_address(address), abi=list(self._artifacts.load(fqn).abi))

    def wallet(self, address: str) -> Contract:
        return self.contract(POLICY_WALLET, address)

    def bulletin(self, address: str) -> Contract:
        return self.contract(THREAT_BULLETIN, address)

    def token(self, address: str) -> Contract:
        return self.contract(MOCK_USD, address)

    def latest_timestamp(self) -> int:
        return int(self._w3.eth.get_block("latest")["timestamp"])

    def code_at(self, address: str) -> bytes:
        return bytes(self._w3.eth.get_code(to_checksum_address(address)))

    # ------------------------------------------------------------------------------------ sending

    def send(self, signer: Signer, call: ContractFunction, value: int = 0) -> TxReceipt:
        """Signs ``call`` with ``signer``, sends it and waits for a successful receipt.

        Raises ``TransactionReverted`` (nothing sent) if gas estimation shows a revert, ``TransactionFailed`` if
        the transaction was mined with status 0 or no receipt arrived in time.
        """
        self._read_allowed_chain_id()
        tx: dict[str, Any] = {"from": to_checksum_address(signer.address), "value": value}
        try:
            built = call.build_transaction(tx)
        except ContractLogicError as exc:
            raise self._reverted(call.contract_abi, exc) from exc
        return self._sign_and_send(signer, dict(built))

    def deploy(
        self, signer: Signer, abi: tuple[dict[str, Any], ...], bytecode: str, args: tuple[Any, ...]
    ) -> TxReceipt:
        """Deploys linked ``bytecode`` with constructor ``args``. The receipt carries ``contractAddress``."""
        self._read_allowed_chain_id()
        factory = self._w3.eth.contract(abi=list(abi), bytecode=bytecode)
        try:
            built = factory.constructor(*args).build_transaction({"from": to_checksum_address(signer.address)})
        except ContractLogicError as exc:
            raise self._reverted(abi, exc) from exc
        return self._sign_and_send(signer, dict(built))

    def send_value(self, signer: Signer, to: str, value: int) -> TxReceipt:
        """Sends ``value`` wei of native token to ``to``."""
        self._read_allowed_chain_id()
        tx: dict[str, Any] = {
            "from": to_checksum_address(signer.address),
            "to": to_checksum_address(to),
            "value": value,
        }
        tx["gas"] = self._w3.eth.estimate_gas(tx)  # type: ignore[arg-type]
        return self._sign_and_send(signer, tx)

    @staticmethod
    def _reverted(abi: Any, exc: ContractLogicError) -> TransactionReverted:
        data = exc.data if isinstance(exc.data, str) and exc.data.startswith("0x") else "0x"
        name, args = decode_revert(list(abi or []), data)
        return TransactionReverted(name, args, data)

    def _sign_and_send(self, signer: Signer, tx: dict[str, Any]) -> TxReceipt:
        chain_id = self._read_allowed_chain_id()
        sender = to_checksum_address(signer.address)
        tx["chainId"] = chain_id
        tx["nonce"] = self._w3.eth.get_transaction_count(sender, "pending")
        estimated = int(tx.get("gas") or self._w3.eth.estimate_gas(tx))  # type: ignore[arg-type]
        tx["gas"] = estimated + estimated * self._tuning.gas_margin_percent // 100
        tx.pop("gasPrice", None)
        tx.pop("maxFeePerGas", None)
        tx.pop("maxPriorityFeePerGas", None)
        base_fee = self._w3.eth.get_block("latest").get("baseFeePerGas")
        if base_fee is None:
            tx["gasPrice"] = self._w3.eth.gas_price
        else:
            priority = int(self._w3.eth.max_priority_fee)
            tx["maxPriorityFeePerGas"] = priority
            tx["maxFeePerGas"] = self._tuning.max_fee_base_multiplier * int(base_fee) + priority
        signed = signer.sign_transaction(tx)
        tx_hash = self._w3.eth.send_raw_transaction(signed.raw_transaction)
        hex_hash = "0x" + bytes(tx_hash).hex()
        try:
            receipt = self._w3.eth.wait_for_transaction_receipt(
                tx_hash,
                timeout=self._tuning.receipt_timeout_seconds,
                poll_latency=self._tuning.receipt_poll_seconds,
            )
        except TimeExhausted as exc:
            raise TransactionFailed(hex_hash, "no receipt before the timeout") from exc
        if int(receipt["status"]) != 1:
            raise TransactionFailed(hex_hash, "status 0")
        return receipt

    # ------------------------------------------------------------------------------------ events

    def events(self, receipt: TxReceipt, contract: Contract, event_name: str) -> list[EventData]:
        """Events ``event_name`` logged by ``contract`` in ``receipt``."""
        event = getattr(contract.events, event_name)()
        address = to_checksum_address(contract.address)
        return [
            e for e in event.process_receipt(receipt, errors=DISCARD) if to_checksum_address(e["address"]) == address
        ]

    def decisions(self, receipt: TxReceipt, wallet: str) -> list[DecisionEvent]:
        """Every ``Decision`` the wallet emitted in ``receipt``, in log order."""
        return [
            DecisionEvent(
                intent_hash=_hex32(e["args"]["intentHash"]),
                tier=Tier(int(e["args"]["tier"])),
                deciding_check=DecidingCheck(int(e["args"]["decidingCheck"])),
                capsule_id=int(e["args"]["capsuleId"]),
            )
            for e in self.events(receipt, self.wallet(wallet), "Decision")
        ]

    # ------------------------------------------------------------------------------------ reads

    def wallet_view(self, wallet_address: str, block_number: int | None = None) -> WalletView:
        """A snapshot of the wallet, every value read at the same block: ``block_number``, or the latest block."""
        w = self.wallet(wallet_address)
        block = self._w3.eth.get_block("latest" if block_number is None else block_number)
        at = int(block["number"])

        def read(fn: ContractFunction) -> Any:
            return fn.call(block_identifier=at)

        agent = read(w.functions.agent())
        token = self.token(read(w.functions.token()))
        mandate_values = read(w.functions.mandate())
        mandate = Mandate(**{name: int(v) for name, v in zip(Mandate.model_fields, mandate_values, strict=True)})
        _, mandate_hash = read(w.functions.mandateHashes())
        unit = int(read(w.functions.ALLOWANCE_UNIT()))

        payees = []
        for payee_id in range(1, int(read(w.functions.payeeCount())) + 1):
            identity, account, active, paid_count, max_paid = read(w.functions.getPayee(payee_id))
            payees.append(
                PayeeView(
                    payee_id=payee_id,
                    identity_hash=_hex32(identity),
                    account=to_checksum_address(account),
                    active=bool(active),
                    paid_count=int(paid_count),
                    max_paid=int(max_paid),
                )
            )
        obligations = []
        for obligation_id in read(w.functions.openObligationIds()):
            payee_id, due, schedule_id, _open, by_agent, amount = read(w.functions.getObligation(obligation_id))
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
        checksum = to_checksum_address(wallet_address)
        return WalletView(
            chain_id=self._chain_id,
            wallet=checksum,
            block_time=int(block["timestamp"]),
            nonce=int(read(w.functions.nonce())),
            token_balance=int(token.functions.balanceOf(checksum).call(block_identifier=at)),
            native_balance=int(self._w3.eth.get_balance(checksum, block_identifier=at)),
            agent_native_balance=int(self._w3.eth.get_balance(agent, block_identifier=at)),
            discretionary=int(read(w.functions.discretionary(0))),
            allowance_points=int(read(w.functions.allowance())) / unit,
            frozen=bool(read(w.functions.frozen())),
            min_schedule_period=int(read(w.functions.MIN_SCHEDULE_PERIOD())),
            mandate=mandate,
            mandate_hash=_hex32(mandate_hash),
            payees=tuple(payees),
            obligations=tuple(obligations),
        )
