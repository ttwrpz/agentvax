"""The evidence run in its local self-test mode on Anvil, with MockLLM (mock).

The run is driven through ``agentvax.evidence.run.main`` exactly as from the command line. Failures are injected
from outside the run, through Anvil, never through a switch in the production code: the agent key of wallet A is
emptied so that its first transaction (E06) cannot be paid for, the bulletin registration of wallet A is cleared so
that its capsule cannot be published after the attack is confirmed (E11), and a contract's code is replaced so that
reusing a deployment file must notice it.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from chain_support import REPO_ROOT, AnvilNode, client_for, start_anvil
from eth_account import Account
from web3 import Web3

from agentvax.chain.artifacts import ArtifactStore
from agentvax.chain.deploy import Deployment, DeploymentError, verify_deployment
from agentvax.evidence import run as evidence
from agentvax.evidence.clock import NetworkClock, WaitStalled
from agentvax.evidence.keys import KeyStore, KeyStoreError
from agentvax.evidence.plan import ROW_IDS, load_plan, load_text, tokens, wei
from agentvax.evidence.rows import EXECUTION_ORDER, format_native, format_tokens
from agentvax.evidence.state import STATE_FORMAT, Progress, RowFailed, RunState, StateStore, StepRecord
from agentvax.memory import MemoryStore
from agentvax.config import load_profile

HASH = re.compile(r"^0x[0-9a-f]{64}$")
NOT_PROSE = re.compile(r"```.*?```|`[^`\n]+`|https?://[^\s)>\]\"']+|&[A-Za-z#0-9]+;", re.S)


@dataclass
class Invocation:
    code: int
    output: str


def invoke(argv: list[str], env: dict[str, str] | None = None) -> Invocation:
    """Runs the entry point in this process and captures what it prints."""
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = evidence.main(argv, dict(os.environ) if env is None else env)
    return Invocation(code=code, output=stdout.getvalue() + stderr.getvalue())


def local_args(node: AnvilNode, out: Path, *extra: str) -> list[str]:
    return ["--local", "--rpc-url", node.rpc_url, "--out", str(out), "--repo-root", str(REPO_ROOT), *extra]


def anvil_call(node: AnvilNode, method: str, params: list[Any]) -> Any:
    reply = Web3(Web3.HTTPProvider(node.rpc_url)).provider.make_request(method, params)  # type: ignore[arg-type]
    assert "error" not in reply, reply
    return reply.get("result")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def set_bulletin_registration(node: AnvilNode, bulletin: str, wallet: str, registered: bool) -> None:
    """Writes ``isRegistered[wallet]`` (storage slot 0 of the bulletin) directly, as only a test node allows."""
    slot = Web3.keccak(bytes.fromhex(wallet[2:].lower().rjust(64, "0")) + (0).to_bytes(32, "big"))
    value = "0x" + int(registered).to_bytes(32, "big").hex()
    anvil_call(node, "anvil_setStorageAt", [bulletin, "0x" + bytes(slot).hex(), value])


def event_count(node: AnvilNode, address: str, signature: str) -> int:
    w3 = Web3(Web3.HTTPProvider(node.rpc_url))
    query = {
        "address": Web3.to_checksum_address(address),
        "fromBlock": 0,
        "toBlock": "latest",
        "topics": [Web3.keccak(text=signature)],
    }
    return len(w3.eth.get_logs(query))  # type: ignore[arg-type]


# ---------------------------------------------------------------------------------------------- one full run


@dataclass
class FullRun:
    node: AnvilNode
    out: Path
    first: Invocation
    failed: Invocation
    failed_state: dict[str, Any]
    files_after_failure: list[str]
    deployment_after_first: dict[str, Any]
    until_e10: Invocation
    publish_failed: Invocation
    publish_failed_state: dict[str, Any]
    completed: Invocation


@pytest.fixture(scope="module")
def full_run(tmp_path_factory: pytest.TempPathFactory) -> Iterator[FullRun]:
    """Up to E02, then a run in which E06 cannot be paid for, then up to E10 after the agent is funded again, then a
    run in which the E11 capsule cannot be published after the attack is confirmed, then the rest."""
    node = start_anvil(31337)
    try:
        out = tmp_path_factory.mktemp("evidence-local")
        first = invoke(local_args(node, out, "--until", "E02"))
        assert first.code == 0, first.output
        deployment_file = read_json(out / "deployments" / "local.json")
        agent_a = deployment_file["record"]["wallets"][0]["agent"]
        assert deployment_file["record"]["wallets"][0]["label"] == "A"

        anvil_call(node, "anvil_setBalance", [agent_a, "0x0"])
        failed = invoke(local_args(node, out))
        failed_state = read_json(out / "work" / "state.json")
        files = sorted(str(p.relative_to(out)) for p in out.rglob("*") if p.is_file())

        before_top_up = wei(load_plan().funding_for(31337).agent_before_top_up)
        anvil_call(node, "anvil_setBalance", [agent_a, hex(before_top_up)])
        until_e10 = invoke(local_args(node, out, "--until", "E10"))

        bulletin = Deployment.from_file_dict(deployment_file).threat_bulletin.address
        wallet_a = deployment_file["record"]["wallets"][0]["address"]
        set_bulletin_registration(node, bulletin, wallet_a, registered=False)
        publish_failed = invoke(local_args(node, out))
        publish_failed_state = read_json(out / "work" / "state.json")
        set_bulletin_registration(node, bulletin, wallet_a, registered=True)
        completed = invoke(local_args(node, out))
        yield FullRun(
            node=node,
            out=out,
            first=first,
            failed=failed,
            failed_state=failed_state,
            files_after_failure=files,
            deployment_after_first=deployment_file,
            until_e10=until_e10,
            publish_failed=publish_failed,
            publish_failed_state=publish_failed_state,
            completed=completed,
        )
    finally:
        node.stop()


def test_evidence_run_never_fabricates_hashes(full_run: FullRun) -> None:
    # The injected failure: the run fails, names the row, records nothing for it and writes no completed evidence.
    assert full_run.failed.code == 1
    assert "EVIDENCE FAILED at E06" in full_run.failed.output
    assert "E06" not in full_run.failed_state["rows"]
    assert not [key for key in full_run.failed_state["steps"] if key.startswith("E06")]
    assert set(full_run.failed_state["rows"]) == {"E01", "E14", "E02"}
    assert "evidence/hashes.json" not in [f.replace("\\", "/") for f in full_run.files_after_failure]
    assert "EVIDENCE.md" not in full_run.files_after_failure

    # The resumed run completes without repeating a mined row.
    assert full_run.completed.code == 0, full_run.completed.output
    hashes = read_json(full_run.out / "evidence" / "hashes.json")
    assert list(hashes) == list(ROW_IDS)
    state = read_json(full_run.out / "work" / "state.json")
    for row in ("E01", "E14", "E02"):
        assert hashes[row] == full_run.failed_state["rows"][row]["hashes"], f"{row} was repeated"
    assert read_json(full_run.out / "deployments" / "local.json") == full_run.deployment_after_first

    # Every hash written is a mined transaction with status 1 on this chain, and appears in the document.
    w3 = Web3(Web3.HTTPProvider(full_run.node.rpc_url))
    document = (full_run.out / "EVIDENCE.md").read_text(encoding="utf-8")
    every = [h for row in ROW_IDS for h in hashes[row]]
    assert all(hashes[row] for row in ROW_IDS)
    for tx_hash in every:
        assert HASH.match(tx_hash), tx_hash
        assert int(w3.eth.get_transaction_receipt(tx_hash)["status"]) == 1
        assert tx_hash in document
    assert len(set(every)) == len(every)
    for record in state["steps"].values():
        for tx_hash in record["hashes"]:
            assert int(w3.eth.get_transaction_receipt(tx_hash)["status"]) == 1


def test_evidence_resume_never_repeats_a_mined_attack_confirmation(full_run: FullRun) -> None:
    # The injected failure: confirmAttack is mined, then publishCapsule cannot go through. Only the mined
    # confirmation is recorded, as its own step, and the row is not.
    assert full_run.until_e10.code == 0, full_run.until_e10.output
    assert full_run.publish_failed.code == 1
    assert "EVIDENCE FAILED at E11" in full_run.publish_failed.output
    not_registered = "0x" + bytes(Web3.keccak(text="NotRegistered(address)")[:4]).hex()
    assert not_registered in full_run.publish_failed.output, "the failure is the injected one"
    failed_steps = full_run.publish_failed_state["steps"]
    assert "E11" not in full_run.publish_failed_state["rows"]
    assert "E11/publish" not in failed_steps
    mined_confirmation = failed_steps["E11/confirm"]["hashes"]
    assert len(mined_confirmation) == 1
    w3 = Web3(Web3.HTTPProvider(full_run.node.rpc_url))
    assert int(w3.eth.get_transaction_receipt(mined_confirmation[0])["status"]) == 1

    # The resumed run completes and does not send confirmAttack again.
    assert full_run.completed.code == 0, full_run.completed.output
    state = read_json(full_run.out / "work" / "state.json")
    assert state["steps"]["E11/confirm"] == failed_steps["E11/confirm"]
    assert mined_confirmation[0] in state["rows"]["E11"]["hashes"]
    assert state["steps"]["E11/publish"]["hashes"][0] in state["rows"]["E11"]["hashes"]
    wallet_a = full_run.deployment_after_first["record"]["wallets"][0]["address"]
    assert event_count(full_run.node, wallet_a, "AttackConfirmed()") == 1, "confirmAttack was sent again"
    bulletin = Deployment.from_file_dict(full_run.deployment_after_first).threat_bulletin.address
    published = "CapsulePublished(uint256,address,uint8,uint8,uint16,uint8,uint8,uint64,uint32)"
    assert event_count(full_run.node, bulletin, published) == 1

    # The threat is remembered once, with the published capsule and the time of the mined confirmation.
    capsule_id = int(state["steps"]["E11/publish"]["values"]["capsule_id"])
    memory = MemoryStore(full_run.out / "work" / "memory_A.sqlite")
    try:
        threats = memory.threats()
    finally:
        memory.close()
    assert [t.capsule_id for t in threats] == [capsule_id]
    assert threats[0].observed_at == int(failed_steps["E11/confirm"]["values"]["confirmed_at"])


def test_evidence_rows_show_what_they_evidence(full_run: FullRun) -> None:
    state = read_json(full_run.out / "work" / "state.json")
    steps = state["steps"]
    plan = load_plan()
    profile = load_profile(plan.profile)
    assert state["agent_model"] == "mock"
    details = {row: record["details"] for row, record in state["rows"].items()}
    assert details["E03"]["amount"] == "120"
    assert details["E07"]["amount"] == "700"
    assert details["E08"]["amount"] == "600"
    assert details["E09"]["amount"] == "2100"
    assert details["E10"] == {
        "balance": "1850",
        "reserve": "600",
        "obligations": "800, 150 and 120",
        "discretionary": "180",
        "amount": "300",
    }
    assert details["E11"]["tier"] in ("2", "3")
    assert int(steps["E11/publish"]["values"]["capsule_id"]) >= 1
    assert details["E11"]["capsule_id"] == str(steps["E11/publish"]["values"]["capsule_id"])
    assert details["E14"]["model_hash"].startswith("0x")
    assert profile.mandate.pressure_hold > 0

    w3 = Web3(Web3.HTTPProvider(full_run.node.rpc_url))

    def block_time(tx_hash: str) -> int:
        return int(w3.eth.get_block(w3.eth.get_transaction_receipt(tx_hash)["blockNumber"])["timestamp"])

    # E07 executed only after the L2 delay, E09 only after the pressure hold, E13 cancelled before Λ.
    queued_at = block_time(steps["E07/queue"]["hashes"][0])
    assert block_time(steps["E07/execute"]["hashes"][0]) >= queued_at + profile.mandate.delay
    assert block_time(steps["E09/execute"]["hashes"][0]) >= (
        block_time(steps["E09/approve"]["hashes"][0]) + profile.mandate.pressure_hold
    )
    assert block_time(steps["E13/cancel"]["hashes"][0]) < int(steps["E13/propose"]["values"]["ready_at"])
    document = (full_run.out / "EVIDENCE.md").read_text(encoding="utf-8")
    assert "mock" in document and "no value" in document and "chain id 31337" in document
    assert "demo profile" in document


def test_evidence_outputs_and_logs_hold_no_key(full_run: FullRun) -> None:
    key_files = sorted((full_run.out / "work" / "keys").glob("*.key"))
    assert len(key_files) >= 10, "control: helper and guardian keys exist"
    secrets = set()
    for key_file in key_files:
        raw = key_file.read_text(encoding="ascii").strip().lower().removeprefix("0x")
        assert re.fullmatch(r"[0-9a-f]{64}", raw)
        secrets.add(raw)
    outputs = [p for p in full_run.out.rglob("*") if p.is_file() and p.suffix != ".key" and p.suffix != ".sqlite"]
    assert any(p.name == "state.json" for p in outputs) and any(p.name == "EVIDENCE.md" for p in outputs)
    texts = [p.read_text(encoding="utf-8").lower() for p in outputs]
    texts += [
        run.output.lower()
        for run in (full_run.first, full_run.failed, full_run.until_e10, full_run.publish_failed, full_run.completed)
    ]
    texts += [b.decode("latin-1").lower() for b in (p.read_bytes() for p in full_run.out.rglob("*.sqlite"))]
    for secret in secrets:
        for text in texts:
            assert secret not in text


def test_evidence_document_wording(full_run: FullRun) -> None:
    prose = NOT_PROSE.sub(" ", (full_run.out / "EVIDENCE.md").read_text(encoding="utf-8"))
    for mark in ("—", "–", ";"):
        assert mark not in prose, f"EVIDENCE.md prose contains {mark!r}"


# ---------------------------------------------------------------------------------------------- refusals


def _testnet_env(node: AnvilNode, chain_id: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("TESTNET_", "OWNER_", "LLM_", "EXPLORER_"))}
    env.update(
        {"TESTNET_RPC_URL": node.rpc_url, "TESTNET_CHAIN_ID": chain_id, "OWNER_PRIVATE_KEY": Account.create().key.hex()}
    )
    return env


@pytest.mark.parametrize("configured", ["1", "31337", "84532"])
def test_evidence_testnet_refuses_mainnet_anvil_and_a_mismatched_node(
    configured: str, start_node, tmp_path: Path  # type: ignore[no-untyped-def]
) -> None:
    node: AnvilNode = start_node(31337)
    w3 = Web3(Web3.HTTPProvider(node.rpc_url))
    block_before = w3.eth.block_number
    env = _testnet_env(node, configured)
    owner = Account.from_key(env["OWNER_PRIVATE_KEY"]).address
    secrets_dir = REPO_ROOT / "secrets" / "evidence"
    existed = {p.name for p in secrets_dir.iterdir()} if secrets_dir.is_dir() else set()

    result = invoke(
        ["--network", "testnet", "--env-file", str(tmp_path / "absent.env"), "--repo-root", str(REPO_ROOT)], env
    )

    assert result.code == 2
    assert "EVIDENCE NOT STARTED" in result.output
    assert configured in result.output or "31337" in result.output
    assert w3.eth.block_number == block_before
    assert w3.eth.get_transaction_count(owner) == 0
    assert ({p.name for p in secrets_dir.iterdir()} if secrets_dir.is_dir() else set()) == existed
    assert env["OWNER_PRIVATE_KEY"].lower().removeprefix("0x") not in result.output.lower()


def test_evidence_testnet_without_settings_is_not_started(tmp_path: Path) -> None:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("TESTNET_", "OWNER_"))}
    argv = ["--network", "testnet", "--env-file", str(tmp_path / "absent.env"), "--repo-root", str(REPO_ROOT)]
    result = invoke(argv, env)
    assert result.code == 2
    assert "OWNER_PRIVATE_KEY" in result.output


def test_evidence_local_refuses_a_node_that_is_not_anvil(
    start_node, tmp_path: Path  # type: ignore[no-untyped-def]
) -> None:
    node: AnvilNode = start_node(84532)
    result = invoke(local_args(node, tmp_path / "out"))
    assert result.code == 2
    assert "31337" in result.output
    assert not (tmp_path / "out" / "deployments").exists()


# ---------------------------------------------------------------------------------------------- reuse


def test_evidence_reuse_of_a_deployment_file_verifies_code(tmp_path: Path) -> None:
    node = start_anvil(31337)
    try:
        out = tmp_path / "reuse"
        first = invoke(local_args(node, out, "--until", "E01"))
        assert first.code == 0, first.output
        recorded = read_json(out / "deployments" / "local.json")
        vault = recorded["contracts"]["SavingsVault"]
        (out / "work" / "state.json").unlink()

        original = anvil_call(node, "eth_getCode", [vault, "latest"])
        anvil_call(node, "anvil_setCode", [vault, "0x00"])
        tampered = invoke(local_args(node, out, "--until", "E01"))
        assert tampered.code == 1
        assert "EVIDENCE FAILED at E01" in tampered.output and vault in tampered.output
        assert not (out / "work" / "state.json").exists() or "E01" not in read_json(out / "work" / "state.json")["rows"]

        anvil_call(node, "anvil_setCode", [vault, original])
        reused = invoke(local_args(node, out, "--until", "E01"))
        assert reused.code == 0, reused.output
        assert "reusing the deployment" in reused.output
        state = read_json(out / "work" / "state.json")
        deployment = Deployment.from_file_dict(recorded)
        assert state["rows"]["E01"]["hashes"] == deployment.transaction_hashes()
        assert read_json(out / "deployments" / "local.json") == recorded
    finally:
        node.stop()


def test_verify_deployment_checks_every_address(artifacts: ArtifactStore, tmp_path: Path) -> None:
    node = start_anvil(31337)
    try:
        out = tmp_path / "every"
        assert invoke(local_args(node, out, "--until", "E01")).code == 0
        deployment = Deployment.from_file_dict(read_json(out / "deployments" / "local.json"))
        client = client_for(node, artifacts)
        verify_deployment(client, deployment)
        addresses = [r.address for r in deployment.libraries.values()]
        addresses += [deployment.mock_usd.address, deployment.savings_vault.address, deployment.threat_bulletin.address]
        addresses += [w.address for w in deployment.wallets]
        assert len(addresses) == len(deployment.libraries) + 6
        for address in addresses:
            original = anvil_call(node, "eth_getCode", [address, "latest"])
            altered = original[:-2] + ("00" if original[-2:] != "00" else "01")
            anvil_call(node, "anvil_setCode", [address, altered])
            with pytest.raises(DeploymentError, match=address):
                verify_deployment(client, deployment)
            anvil_call(node, "anvil_setCode", [address, original])
        verify_deployment(client, deployment)
    finally:
        node.stop()


# ---------------------------------------------------------------------------------------------- units


def test_plan_funds_the_agent_below_the_floor_on_every_network() -> None:
    plan = load_plan()
    floor = load_profile(plan.profile).mandate.agent_balance_floor
    for chain_id in ("84532", "11155111", "31337"):
        funding = plan.funding_for(int(chain_id))
        assert wei(funding.agent_before_top_up) < floor
    assert tokens(plan.wallets["C"].tokens) == tokens(plan.rows.E10.balance)
    assert set(load_text().rows) == set(ROW_IDS)
    assert sorted(p for p in EXECUTION_ORDER if p in ROW_IDS) == list(ROW_IDS)
    with pytest.raises(ValueError):
        plan.funding_for(1)


def test_amount_formatting() -> None:
    assert format_tokens(1_850_000_000) == "1850"
    assert format_tokens(120_500_000) == "120.5"
    assert format_tokens(0) == "0"
    assert format_native(1_000_000_000_000_000) == "0.001"
    assert format_native(10**18) == "1"


def test_progress_records_nothing_that_is_not_verified(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.json")
    state = RunState(format=STATE_FORMAT, chain_id=31337, profile="demo", agent_model="mock")
    accepted: set[str] = {"0x" + "11" * 32}

    def verify(hashes: Any) -> None:
        for h in hashes:
            if h not in accepted:
                raise RuntimeError(f"{h} is not on chain")

    progress = Progress(store, state, verify)
    progress.step("E03/pay", lambda: StepRecord(hashes=("0x" + "11" * 32,), values={}))
    with pytest.raises(RuntimeError):
        progress.step("E07/queue", lambda: StepRecord(hashes=("0x" + "22" * 32,), values={}))
    with pytest.raises(RuntimeError):
        progress.complete_row("E07", ["0x" + "22" * 32], {})
    with pytest.raises(RowFailed):
        progress.complete_row("E08", [], {})
    saved = store.load()
    assert set(saved.steps) == {"E03/pay"} and not saved.rows

    calls: list[str] = []
    again = progress.step("E03/pay", lambda: calls.append("ran") or StepRecord(hashes=(), values={}))
    assert again.hashes == ("0x" + "11" * 32,) and not calls


class _FakeClient:
    def __init__(self, times: list[int]) -> None:
        self._times = times

    def latest_timestamp(self) -> int:
        return self._times.pop(0) if len(self._times) > 1 else self._times[0]


def test_network_clock_waits_for_chain_time_and_reports_a_stall() -> None:
    timing = load_plan().timing
    messages: list[str] = []
    client = _FakeClient([100, 100, 130, 161, 170])
    clock = NetworkClock(client, timing, messages.append, sleep=lambda _: None)  # type: ignore[arg-type]
    clock.wait_until(160, "the delay")
    assert messages[0].startswith("waiting about 60 s") and messages[-1] == "the delay has passed on chain"

    stalled = timing.model_copy(update={"stall_seconds": 0.0001})
    stuck = _FakeClient([100])
    with pytest.raises(WaitStalled):
        pausing = NetworkClock(stuck, stalled, messages.append, sleep=lambda _: time.sleep(0.001))  # type: ignore[arg-type]
        pausing.wait_until(160, "the delay")


def test_key_store_keeps_helpers_and_never_reads_a_guardian_key(tmp_path: Path) -> None:
    keys = KeyStore(tmp_path / "keys")
    first = keys.helper("agent_a")
    assert keys.helper("agent_a").address == first.address, "a helper key is read back, not replaced"
    with pytest.raises(ValueError):
        keys.helper("../escape")
    assert keys.guardian_address("A") is None
    keys.guardian_key_file("A").write_text("not read by this process", encoding="ascii")
    with pytest.raises(KeyStoreError):
        keys.guardian_address("A")


def test_amounts_with_too_many_decimals_are_refused() -> None:
    assert tokens("0.000001") == 1
    with pytest.raises(ValueError):
        tokens("0.0000001")
    with pytest.raises(ValueError):
        tokens("-1")
    with pytest.raises(ValueError):
        wei("one")
