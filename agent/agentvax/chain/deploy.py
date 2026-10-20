"""The deployer of the AgentVax contracts.

Deploys and links the libraries from the artifact's link references, then the token, vault, bulletin and wallets,
registers the wallets and checks every receipt and the code at every new address.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Sequence
from typing import Annotated, Any

from eth_utils import keccak, to_checksum_address
from pydantic import Field
from web3.types import TxReceipt

from agentvax.chain.artifacts import Artifact, LinkReference
from agentvax.chain.client import (
    MOCK_USD,
    POLICY_WALLET,
    SAVINGS_VAULT,
    THREAT_BULLETIN,
    ChainClient,
    Signer,
    UnsupportedChain,
)
from agentvax.config import load_profile
from agentvax.types import ALLOWED_CHAIN_IDS, Address, Bytes32, Strict

WALLET_LABEL_PATTERN = r"^[A-Z][A-Za-z0-9]{0,15}$"
_HEX = re.compile(r"^[0-9a-fA-F]*$")


class LinkError(RuntimeError):
    """Bytecode could not be linked exactly as the compiler's link references describe."""


class DeploymentError(RuntimeError):
    """A deployment transaction did not produce the expected code."""


class ContractRecord(Strict):
    address: Address
    tx_hash: Bytes32
    block_number: int


class WalletSpec(Strict):
    """Keys of one wallet to deploy. Only addresses: the deployer never sees the owner, agent or guardian key."""

    label: Annotated[str, Field(pattern=WALLET_LABEL_PATTERN)]
    owner: Address
    agent: Address
    guardian: Address


class WalletRecord(Strict):
    label: Annotated[str, Field(pattern=WALLET_LABEL_PATTERN)]
    address: Address
    tx_hash: Bytes32
    block_number: int
    owner: Address
    agent: Address
    guardian: Address
    registration_tx_hash: Bytes32


class Deployment(Strict):
    """Everything one deployment created. Recorded with the profile it was made for."""

    chain_id: int
    profile: str
    deployer: Address
    registrar: Address
    aggregator: Address
    libraries: dict[str, ContractRecord]
    """Keyed by fully qualified name, in deployment order."""
    mock_usd: ContractRecord
    savings_vault: ContractRecord
    threat_bulletin: ContractRecord
    wallets: tuple[WalletRecord, ...]

    def wallet(self, label: str) -> WalletRecord:
        for record in self.wallets:
            if record.label == label:
                return record
        raise KeyError(f"no wallet labelled {label!r}")

    def library_addresses(self) -> dict[str, str]:
        return {fqn: record.address for fqn, record in self.libraries.items()}

    def transaction_hashes(self) -> list[str]:
        """Every transaction of the deployment in the order sent: libraries, token, vault, bulletin, then each
        wallet followed by its registration."""
        hashes = [r.tx_hash for r in self.libraries.values()]
        hashes += [self.mock_usd.tx_hash, self.savings_vault.tx_hash, self.threat_bulletin.tx_hash]
        for w in self.wallets:
            hashes += [w.tx_hash, w.registration_tx_hash]
        return hashes

    def to_file_dict(self) -> dict[str, Any]:
        """The ``deployments/*.json`` format, with the full record under ``record``."""
        contracts = {
            "MockUSD": self.mock_usd.address,
            "SavingsVault": self.savings_vault.address,
            "ThreatBulletin": self.threat_bulletin.address,
        }
        contracts.update({f"PolicyWallet{w.label}": w.address for w in self.wallets})
        return {
            "chainId": self.chain_id,
            "profile": self.profile,
            "contracts": contracts,
            "record": self.model_dump(mode="json"),
        }

    @classmethod
    def from_file_dict(cls, data: dict[str, Any]) -> Deployment:
        deployment = cls.model_validate_json(json.dumps(data["record"]))
        if data.get("chainId") != deployment.chain_id or data.get("profile") != deployment.profile:
            raise ValueError("deployment file header does not match its record")
        return deployment


# ---------------------------------------------------------------------------------------------- linking


def placeholder(fqn: str) -> str:
    """The 40-character placeholder solc writes for library ``fqn``: ``__$`` + 34 hex of keccak(fqn) + ``$__``."""
    return "__$" + keccak(text=fqn).hex()[:34] + "$__"


def link_bytecode(bytecode: str, references: dict[str, tuple[LinkReference, ...]], addresses: dict[str, str]) -> str:
    """Writes each library address at the byte offsets in ``references``.

    Every reference must hold exactly that library's placeholder before it is replaced, and the result must be
    plain hexadecimal with no placeholder left. Raises ``LinkError`` otherwise.
    """
    code = bytecode[2:] if bytecode.startswith("0x") else bytecode
    for fqn, refs in references.items():
        if fqn not in addresses:
            raise LinkError(f"no address for library {fqn}")
        address = to_checksum_address(addresses[fqn])[2:].lower()
        expected = placeholder(fqn)
        for ref in refs:
            if ref.length != 20:
                raise LinkError(f"link reference for {fqn} has length {ref.length}, expected 20")
            start, end = 2 * ref.start, 2 * (ref.start + ref.length)
            if code[start:end] != expected:
                raise LinkError(f"no placeholder for {fqn} at byte {ref.start}")
            code = code[:start] + address + code[end:]
    if "__$" in code or "$__" in code or not _HEX.match(code):
        raise LinkError("unresolved library placeholder left in bytecode")
    return "0x" + code


def _mask(code: bytes, ranges: Sequence[tuple[int, int]]) -> bytes:
    out = bytearray(code)
    for start, length in ranges:
        out[start : start + length] = bytes(length)
    return bytes(out)


def _check_runtime_code(
    client: ChainClient, address: str, artifact: Artifact, addresses: dict[str, str], library: bool
) -> None:
    """The code at ``address`` must equal the artifact's linked runtime code, apart from immutable values and,
    for a library, its own address in the call guard."""
    expected_hex = link_bytecode(artifact.deployed_bytecode, artifact.deployed_link_references, addresses)
    expected = bytes.fromhex(expected_hex[2:])
    actual = client.code_at(address)
    # Public RPC backends may expose the receipt before their latest state reader
    # sees the new contract. Retry only absent code; never accept differing code.
    for _ in range(10):
        if actual:
            break
        time.sleep(1)
        actual = client.code_at(address)
    ranges = [(r.start, r.length) for r in artifact.immutable_references]
    if library:
        ranges.append((1, 20))
    if len(actual) != len(expected) or _mask(actual, ranges) != _mask(expected, ranges):
        raise DeploymentError(
            f"code at {address} does not match {artifact.fqn} "
            f"(received {len(actual)} bytes, expected {len(expected)})"
        )


# ---------------------------------------------------------------------------------------------- deploying


def _tx_hash(receipt: TxReceipt) -> str:
    return "0x" + bytes(receipt["transactionHash"]).hex()


def _deploy(
    client: ChainClient,
    signer: Signer,
    fqn: str,
    args: tuple[Any, ...],
    addresses: dict[str, str],
    library: bool = False,
) -> ContractRecord:
    artifact = client.artifacts.load(fqn)
    bytecode = link_bytecode(artifact.bytecode, artifact.link_references, addresses)
    receipt = client.deploy(signer, artifact.abi, bytecode, args)
    address = receipt.get("contractAddress")
    if not address:
        raise DeploymentError(f"deployment of {fqn} returned no contract address")
    _check_runtime_code(client, address, artifact, addresses, library)
    return ContractRecord(
        address=to_checksum_address(address), tx_hash=_tx_hash(receipt), block_number=int(receipt["blockNumber"])
    )


def _deploy_libraries(client: ChainClient, signer: Signer, root: str) -> dict[str, ContractRecord]:
    """Deploys every library ``root`` links to, each after the libraries it links to itself."""
    records: dict[str, ContractRecord] = {}
    visiting: set[str] = set()

    def visit(fqn: str) -> None:
        if fqn in records:
            return
        if fqn in visiting:
            raise LinkError(f"library link cycle through {fqn}")
        visiting.add(fqn)
        for dependency in client.artifacts.load(fqn).link_references:
            visit(dependency)
        addresses = {k: r.address for k, r in records.items()}
        records[fqn] = _deploy(client, signer, fqn, (), addresses, library=True)
        visiting.discard(fqn)

    for library in client.artifacts.load(root).link_references:
        visit(library)
    return records


def _require_allowed(client: ChainClient) -> None:
    if client.chain_id not in ALLOWED_CHAIN_IDS:
        raise UnsupportedChain(client.chain_id)


def deploy_wallet(
    client: ChainClient,
    deployer: Signer,
    registrar: Signer,
    shared: Deployment,
    spec: WalletSpec,
) -> WalletRecord:
    """Deploys one more ``PolicyWallet`` against the token, vault, bulletin and libraries of ``shared`` and
    registers it in the bulletin. ``registrar`` must be the bulletin's registrar."""
    _require_allowed(client)
    if client.chain_id != shared.chain_id:
        raise UnsupportedChain(client.chain_id, shared.chain_id)
    addresses = shared.library_addresses()
    record = _deploy(
        client,
        deployer,
        POLICY_WALLET,
        (
            to_checksum_address(spec.owner),
            to_checksum_address(spec.agent),
            to_checksum_address(spec.guardian),
            shared.mock_usd.address,
            shared.savings_vault.address,
            shared.threat_bulletin.address,
        ),
        addresses,
    )
    bulletin = client.bulletin(shared.threat_bulletin.address)
    registration = client.send(registrar, bulletin.functions.setRegistered(record.address, True))
    if not bulletin.functions.isRegistered(record.address).call():
        raise DeploymentError(f"wallet {record.address} is not registered after registration")
    return WalletRecord(
        label=spec.label,
        address=record.address,
        tx_hash=record.tx_hash,
        block_number=record.block_number,
        owner=to_checksum_address(spec.owner),
        agent=to_checksum_address(spec.agent),
        guardian=to_checksum_address(spec.guardian),
        registration_tx_hash=_tx_hash(registration),
    )


def _check_creation(client: ChainClient, record: ContractRecord, what: str) -> None:
    """The creation transaction of ``record`` was mined with status 1 and created exactly ``record.address``."""
    try:
        receipt = client.web3.eth.get_transaction_receipt(record.tx_hash)  # type: ignore[arg-type]
    except Exception as exc:
        raise DeploymentError(f"no receipt for the deployment of {what} ({record.tx_hash})") from exc
    if int(receipt["status"]) != 1:
        raise DeploymentError(f"the deployment of {what} ({record.tx_hash}) did not succeed")
    created = receipt.get("contractAddress")
    if not created or to_checksum_address(created) != to_checksum_address(record.address):
        raise DeploymentError(f"transaction {record.tx_hash} did not create {what} at {record.address}")


def verify_deployment(client: ChainClient, deployment: Deployment) -> None:
    """Checks a recorded deployment against the chain before it is reused.

    The chain id must match. Every library, the token, the vault, the bulletin and every wallet must have been
    created by its recorded transaction, mined with status 1, and the code at each address must equal the linked
    runtime code of its artifact (immutable values aside). Each wallet must be registered in the bulletin by a
    successful recorded registration, and must name the recorded owner, agent and guardian. Raises
    ``UnsupportedChain`` or ``DeploymentError``.
    """
    _require_allowed(client)
    if client.chain_id != deployment.chain_id:
        raise UnsupportedChain(client.chain_id, deployment.chain_id)
    addresses = deployment.library_addresses()
    for fqn, record in deployment.libraries.items():
        _check_creation(client, record, fqn)
        _check_runtime_code(client, record.address, client.artifacts.load(fqn), addresses, library=True)
    for fqn, record in (
        (MOCK_USD, deployment.mock_usd),
        (SAVINGS_VAULT, deployment.savings_vault),
        (THREAT_BULLETIN, deployment.threat_bulletin),
    ):
        _check_creation(client, record, fqn)
        _check_runtime_code(client, record.address, client.artifacts.load(fqn), addresses, library=False)
    bulletin = client.bulletin(deployment.threat_bulletin.address)
    wallet_artifact = client.artifacts.load(POLICY_WALLET)
    for wallet in deployment.wallets:
        label = f"PolicyWallet{wallet.label}"
        _check_creation(
            client,
            ContractRecord(address=wallet.address, tx_hash=wallet.tx_hash, block_number=wallet.block_number),
            label,
        )
        _check_runtime_code(client, wallet.address, wallet_artifact, addresses, library=False)
        registration = client.web3.eth.get_transaction_receipt(wallet.registration_tx_hash)  # type: ignore[arg-type]
        if int(registration["status"]) != 1 or not bulletin.functions.isRegistered(wallet.address).call():
            raise DeploymentError(f"{label} at {wallet.address} is not registered in the bulletin")
        contract = client.wallet(wallet.address)
        roles = (
            contract.functions.owner().call(),
            contract.functions.agent().call(),
            contract.functions.guardian().call(),
        )
        recorded = (wallet.owner, wallet.agent, wallet.guardian)
        if tuple(to_checksum_address(r) for r in roles) != tuple(to_checksum_address(r) for r in recorded):
            raise DeploymentError(f"{label} at {wallet.address} names other keys than the deployment record")


def deploy_stack(
    client: ChainClient,
    deployer: Signer,
    registrar: Signer,
    aggregator: str,
    wallets: Sequence[WalletSpec],
    profile: str,
) -> Deployment:
    """Deploys the libraries, ``MockUSD``, ``SavingsVault``, ``ThreatBulletin`` and one ``PolicyWallet`` per
    spec, and registers each wallet. The profile is recorded here and applied when each owner sets a mandate."""
    _require_allowed(client)
    load_profile(profile)
    labels = [w.label for w in wallets]
    if len(set(labels)) != len(labels):
        raise ValueError("wallet labels must be distinct")

    libraries = _deploy_libraries(client, deployer, POLICY_WALLET)
    mock_usd = _deploy(client, deployer, MOCK_USD, (), {})
    vault = _deploy(client, deployer, SAVINGS_VAULT, (mock_usd.address,), {})
    bulletin = _deploy(
        client,
        deployer,
        THREAT_BULLETIN,
        (to_checksum_address(registrar.address), to_checksum_address(aggregator)),
        {},
    )
    shared = Deployment(
        chain_id=client.chain_id,
        profile=profile,
        deployer=to_checksum_address(deployer.address),
        registrar=to_checksum_address(registrar.address),
        aggregator=to_checksum_address(aggregator),
        libraries=libraries,
        mock_usd=mock_usd,
        savings_vault=vault,
        threat_bulletin=bulletin,
        wallets=(),
    )
    records = tuple(deploy_wallet(client, deployer, registrar, shared, spec) for spec in wallets)
    return shared.model_copy(update={"wallets": records})
