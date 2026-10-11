"""Helpers for tests that run against a local Anvil: starting and stopping Anvil, funding fresh keys, and
deploying a stack. Keys are generated per run with ``Account.create`` and funded through ``anvil_setBalance``;
no key is written in source.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from eth_account import Account
from eth_account.signers.local import LocalAccount
from web3 import Web3

from agentvax.chain.artifacts import ArtifactStore
from agentvax.chain.client import ChainClient
from agentvax.chain.deploy import Deployment, WalletSpec, deploy_stack
from agentvax.chain.owner import set_mandate
from agentvax.config import ChainTuning, GuardianTiming, load_profile

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACTS_DIR = REPO_ROOT / "contracts"
ARTIFACTS_DIR = CONTRACTS_DIR / "out"
ETHER = 10**18
STARTUP_SECONDS = 30.0

TUNING = ChainTuning(receipt_timeout_seconds=30.0, receipt_poll_seconds=0.05)
TIMING = GuardianTiming()


def foundry_tool(name: str) -> str:
    """Path of a Foundry executable: on PATH, or in the default Foundry install directory."""
    found = shutil.which(name)
    if found:
        return found
    for candidate in (Path.home() / ".foundry" / "bin" / f"{name}.exe", Path.home() / ".foundry" / "bin" / name):
        if candidate.is_file():
            return str(candidate)
    raise FileNotFoundError(f"{name} not found; install Foundry")


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@dataclass
class AnvilNode:
    process: subprocess.Popen[bytes]
    rpc_url: str
    chain_id: int

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)


def start_anvil(chain_id: int) -> AnvilNode:
    """Starts Anvil on a free local port and waits until it answers. The caller must call ``stop``."""
    port = free_port()
    process = subprocess.Popen(
        [foundry_tool("anvil"), "--port", str(port), "--chain-id", str(chain_id), "--host", "127.0.0.1", "--silent"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    node = AnvilNode(process=process, rpc_url=f"http://127.0.0.1:{port}", chain_id=chain_id)
    w3 = Web3(Web3.HTTPProvider(node.rpc_url, request_kwargs={"timeout": 2}))
    deadline = time.monotonic() + STARTUP_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("anvil exited during startup")
        try:
            if w3.is_connected():
                return node
        except Exception:
            pass
        time.sleep(0.1)
    node.stop()
    raise RuntimeError("anvil did not start in time")


def artifact_store() -> ArtifactStore:
    return ArtifactStore(CONTRACTS_DIR, ARTIFACTS_DIR, foundry_tool("forge"))


def client_for(node: AnvilNode, store: ArtifactStore) -> ChainClient:
    return ChainClient(node.rpc_url, store, TUNING, expected_chain_id=node.chain_id)


def funded_account(node: AnvilNode, ether: int = 100) -> LocalAccount:
    account: LocalAccount = Account.create()
    w3 = Web3(Web3.HTTPProvider(node.rpc_url))
    w3.provider.make_request("anvil_setBalance", [account.address, hex(ether * ETHER)])
    return account


def advance_time(node: AnvilNode, seconds: int) -> None:
    """Moves the chain clock forward and mines a block, so the latest block carries the new time."""
    w3 = Web3(Web3.HTTPProvider(node.rpc_url))
    w3.provider.make_request("evm_increaseTime", [seconds])
    w3.provider.make_request("evm_mine", [])


@dataclass
class LocalStack:
    """A deployed stack with one wallet whose mandate is set from a profile, and the keys that drive it."""

    deployment: Deployment
    deployer: LocalAccount
    owner: LocalAccount
    agent: LocalAccount
    aggregator: LocalAccount

    @property
    def wallet(self) -> str:
        return self.deployment.wallets[0].address


def deploy_test_stack(
    client: ChainClient, node: AnvilNode, guardian: str, profile: str = "demo", fund_tokens: int = 5_000 * 10**6
) -> LocalStack:
    """Deploys a stack with one wallet labelled A guarded by ``guardian``, sets the profile's mandate, mints
    ``fund_tokens`` to the wallet and sends it one ether for fees."""
    deployer = funded_account(node)
    owner = funded_account(node)
    agent = funded_account(node)
    aggregator = funded_account(node)
    deployment = deploy_stack(
        client,
        deployer,
        deployer,
        aggregator.address,
        [WalletSpec(label="A", owner=owner.address, agent=agent.address, guardian=guardian)],
        profile,
    )
    wallet = deployment.wallets[0].address
    mandate = load_profile(profile).mandate.mandate(client.latest_timestamp())
    set_mandate(client, owner, wallet, "Keep 600 in reserve and pay approved payees.", mandate)
    token = client.token(deployment.mock_usd.address)
    client.send(deployer, token.functions.mint(wallet, fund_tokens))
    client.send_value(deployer, wallet, ETHER)
    return LocalStack(deployment=deployment, deployer=deployer, owner=owner, agent=agent, aggregator=aggregator)
