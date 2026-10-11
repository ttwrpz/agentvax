"""The chain client and the deployer against a local Anvil."""

from __future__ import annotations

import re

import pytest
from chain_support import TUNING, AnvilNode, client_for, deploy_test_stack, funded_account
from eth_account import Account
from eth_utils import to_checksum_address
from web3 import HTTPProvider, Web3

from agentvax.chain.artifacts import ArtifactStore, LinkReference
from agentvax.chain.client import POLICY_WALLET, ChainClient, TransactionReverted, UnsupportedChain
from agentvax.chain.deploy import Deployment, LinkError, WalletSpec, deploy_stack, link_bytecode, placeholder
from agentvax.config import load_profile


def _untouched(node: AnvilNode, sender: str) -> bool:
    w3 = Web3(Web3.HTTPProvider(node.rpc_url))
    return w3.eth.block_number == 0 and w3.eth.get_transaction_count(sender) == 0


def test_chain_client_refuses_non_test_chain(start_node, artifacts: ArtifactStore) -> None:  # type: ignore[no-untyped-def]
    deployer = Account.create()
    for chain_id in (1, 4242):
        node = start_node(chain_id)
        with pytest.raises(UnsupportedChain) as refused:
            ChainClient(node.rpc_url, artifacts, TUNING)
        assert refused.value.chain_id == chain_id
        with pytest.raises(UnsupportedChain):
            ChainClient(node.rpc_url, artifacts, TUNING, expected_chain_id=chain_id)
        assert _untouched(node, deployer.address)


class _SwitchingProvider(HTTPProvider):
    """An HTTP provider that, once ``switched``, reports chain id 1 and records every other method it is asked."""

    def __init__(self, endpoint_uri: str) -> None:
        super().__init__(endpoint_uri)
        self.switched = False
        self.asked: list[str] = []

    def make_request(self, method, params):  # type: ignore[no-untyped-def]
        if self.switched:
            if method == "eth_chainId":
                return {"jsonrpc": "2.0", "id": 1, "result": "0x1"}
            self.asked.append(method)
        return super().make_request(method, params)


def test_sending_paths_refuse_a_switched_chain_before_building(anvil: AnvilNode, artifacts: ArtifactStore) -> None:
    """Invariant 9: the chain id is checked before anything about a transaction is built or estimated."""
    client = client_for(anvil, artifacts)
    sender = funded_account(anvil)
    stack = deploy_test_stack(client, anvil, Account.create().address)
    wallet = client.wallet(stack.wallet)
    artifact = artifacts.load(POLICY_WALLET)
    provider = _SwitchingProvider(anvil.rpc_url)
    client.web3.provider = provider
    block_before = client.web3.eth.block_number
    nonce_before = client.web3.eth.get_transaction_count(sender.address)
    provider.switched = True

    attempts = [
        lambda: client.send(stack.owner, wallet.functions.freeze()),
        lambda: client.send_value(sender, stack.wallet, 1),
        lambda: client.deploy(sender, artifact.abi, artifact.bytecode, ()),
    ]
    for attempt in attempts:
        with pytest.raises(UnsupportedChain):
            attempt()
    assert provider.asked == [], f"nothing may be built, estimated or sent: {provider.asked}"
    provider.switched = False
    assert client.web3.eth.block_number == block_before
    assert client.web3.eth.get_transaction_count(sender.address) == nonce_before
    assert not wallet.functions.frozen().call()


def test_chain_client_refuses_unexpected_chain(anvil: AnvilNode, artifacts: ArtifactStore) -> None:
    with pytest.raises(UnsupportedChain) as refused:
        ChainClient(anvil.rpc_url, artifacts, TUNING, expected_chain_id=84532)
    assert refused.value.expected == 84532
    assert ChainClient(anvil.rpc_url, artifacts, TUNING, expected_chain_id=31337).chain_id == 31337


def test_deployer_links_every_library_and_leaves_no_placeholder(anvil: AnvilNode, artifacts: ArtifactStore) -> None:
    client = client_for(anvil, artifacts)
    guardian = Account.create()
    stack = deploy_test_stack(client, anvil, guardian.address)
    deployment = stack.deployment

    wallet_artifact = artifacts.load(POLICY_WALLET)
    assert set(deployment.libraries) == set(wallet_artifact.link_references)
    assert len(deployment.libraries) == 6

    linked = link_bytecode(wallet_artifact.bytecode, wallet_artifact.link_references, deployment.library_addresses())
    assert "__$" not in linked and re.fullmatch(r"0x[0-9a-f]+", linked)
    code = client.code_at(stack.wallet).hex()
    for record in deployment.libraries.values():
        assert client.code_at(record.address)
        assert record.address[2:].lower() in code

    w3 = client.web3
    hashes = deployment.transaction_hashes()
    assert len(hashes) == 6 + 3 + 2 and len(set(hashes)) == len(hashes)
    for tx_hash in hashes:
        assert w3.eth.get_transaction_receipt(tx_hash)["status"] == 1

    wallet = client.wallet(stack.wallet)
    assert wallet.functions.guardian().call() == guardian.address
    assert wallet.functions.owner().call() == stack.owner.address
    assert wallet.functions.agent().call() == stack.agent.address
    assert client.bulletin(deployment.threat_bulletin.address).functions.isRegistered(stack.wallet).call()

    restored = Deployment.from_file_dict(deployment.to_file_dict())
    assert restored == deployment
    file_dict = deployment.to_file_dict()
    assert file_dict["chainId"] == 31337 and file_dict["profile"] == "demo"
    assert set(file_dict["contracts"]) == {"MockUSD", "SavingsVault", "ThreatBulletin", "PolicyWalletA"}


def test_link_bytecode_refuses_anything_but_exact_placeholders() -> None:
    fqn = "src/lib/Example.sol:Example"
    marker = placeholder(fqn)
    assert len(marker) == 40
    code = "0x6000" + marker + "6000"
    address = "0x" + "ab" * 20
    refs = {fqn: (LinkReference(start=2, length=20),)}
    assert link_bytecode(code, refs, {fqn: address}) == "0x6000" + "ab" * 20 + "6000"

    with pytest.raises(LinkError):
        link_bytecode(code, refs, {})
    with pytest.raises(LinkError):
        link_bytecode(code, {fqn: (LinkReference(start=3, length=20),)}, {fqn: address})
    with pytest.raises(LinkError):
        link_bytecode(code, {}, {fqn: address})
    other = "src/lib/Other.sol:Other"
    with pytest.raises(LinkError):
        link_bytecode(code, {other: (LinkReference(start=2, length=20),)}, {other: address})


def test_deployer_refuses_unknown_profile(anvil: AnvilNode, artifacts: ArtifactStore) -> None:
    client = client_for(anvil, artifacts)
    deployer = funded_account(anvil)
    before = client.web3.eth.get_transaction_count(deployer.address)
    spec = WalletSpec(
        label="A", owner=Account.create().address, agent=Account.create().address, guardian=Account.create().address
    )
    with pytest.raises(ValueError):
        deploy_stack(client, deployer, deployer, deployer.address, [spec], "production")
    assert client.web3.eth.get_transaction_count(deployer.address) == before


def test_wallet_view_and_reverts(anvil: AnvilNode, artifacts: ArtifactStore) -> None:
    client = client_for(anvil, artifacts)
    stack = deploy_test_stack(client, anvil, Account.create().address)
    view = client.wallet_view(stack.wallet)
    profile = load_profile("demo")
    assert view.chain_id == 31337 and view.wallet == to_checksum_address(stack.wallet)
    assert view.mandate.delay == profile.mandate.delay
    assert view.mandate.reserve == profile.mandate.reserve
    assert view.token_balance == 5_000 * 10**6
    assert view.discretionary == view.token_balance - view.mandate.reserve
    assert view.allowance_points == profile.mandate.allowance_max
    assert not view.frozen and view.payees == () and view.obligations == () and view.nonce == 0

    wallet = client.wallet(stack.wallet)
    nonce = client.web3.eth.get_transaction_count(stack.agent.address)
    with pytest.raises(TransactionReverted) as reverted:
        client.send(stack.agent, wallet.functions.freeze())
    assert reverted.value.error_name == "NotOwner"
    assert client.web3.eth.get_transaction_count(stack.agent.address) == nonce
