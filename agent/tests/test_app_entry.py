"""The hosted entry point ``python -m agentvax.api.app`` (``make ui``): where it finds its deployment, keys and model,
and that its guardian runs only the detector model anchored in the deployment's ThreatBulletin.

The adoption path is exercised on Anvil against a deployment made by the evidence run in its local mode (MockLLM,
so `mock`). The app itself is given a hosted-model configuration that points at an unused local address. It never
calls it: these tests only start the app's services and look at what they adopted.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
from collections.abc import Iterator
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path

import pytest
from chain_support import REPO_ROOT, AnvilNode, start_anvil

from agentvax.api import app as hosted
from agentvax.chain.artifacts import ArtifactStore
from agentvax.chain.client import ChainClient
from agentvax.chain.deploy import Deployment
from agentvax.config import ChainTuning
from agentvax.detector.model import load_model, model_hash, save_model
from agentvax.detector.train import seed_model_path
from agentvax.evidence import run as evidence
from agentvax.evidence.keys import KeyStore
from agentvax.evidence.layout import WorkLayout
from agentvax.fed.anchor import latest_anchor

UNUSED_MODEL_ENDPOINT = "http://127.0.0.1:9/v1"


def _no_reading(*_args: object, **_kwargs: object) -> None:
    raise AssertionError("the entry point read a key or the environment before it found the deployment")


# ---------------------------------------------------------------------------------------------- no evidence run yet


def test_ui_without_a_deployment_says_to_run_evidence_first(tmp_path: Path) -> None:
    """``make ui`` runs the module with no arguments. Before any evidence run it stops with one line, exit code 2."""
    done = subprocess.run(
        [sys.executable, "-m", "agentvax.api.app"],
        cwd=tmp_path,
        env=dict(os.environ),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert done.returncode == 2, done.stdout + done.stderr
    assert done.stdout == ""
    lines = done.stderr.strip().splitlines()
    assert len(lines) == 1, done.stderr
    assert lines[0].startswith("interface not started: there is no deployment at ")
    assert "Run make evidence first." in lines[0]
    assert "usage:" not in done.stderr


def test_ui_reads_no_key_and_no_environment_when_the_deployment_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(hosted, "read_environment", _no_reading)
    monkeypatch.setattr(hosted, "_key_from_file", _no_reading)
    monkeypatch.setattr(hosted.Account, "from_key", _no_reading)
    monkeypatch.setattr(KeyStore, "helper", _no_reading)
    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
        code = hosted.main([], process_env={})
    assert code == 2
    assert "Run make evidence first." in stderr.getvalue()
    assert not (tmp_path / "secrets").exists()


# ---------------------------------------------------------------------------------------------- on Anvil


@dataclass
class LocalEvidence:
    node: AnvilNode
    out: Path
    tmp: Path

    @property
    def work(self) -> WorkLayout:
        return WorkLayout(self.out / "work")

    @property
    def deployment(self) -> Path:
        return self.out / "deployments" / "local.json"

    def run_evidence(self, until: str) -> None:
        argv = ["--local", "--rpc-url", self.node.rpc_url, "--out", str(self.out), "--repo-root", str(REPO_ROOT)]
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stdout):
            code = evidence.main([*argv, "--until", until], dict(os.environ))
        assert code == 0, stdout.getvalue()

    def environment(self) -> dict[str, str]:
        """The app's environment for this local deployment. The owner of wallet A in the local mode is a helper key
        the evidence run generated in its own work directory."""
        owner_key = (self.work.keys / "owner_a.key").read_text(encoding="ascii").strip()
        return {
            **{k: v for k, v in os.environ.items() if not k.startswith(("TESTNET_", "LLM_", "OWNER_", "EXPLORER_"))},
            "TESTNET_RPC_URL": self.node.rpc_url,
            "TESTNET_CHAIN_ID": "31337",
            "OWNER_PRIVATE_KEY": owner_key,
            "LLM_PROVIDER": "openai-compatible",
            "LLM_MODEL": "unused",
            "LLM_BASE_URL": UNUSED_MODEL_ENDPOINT,
            "LLM_API_KEY": "unused",
        }

    def args(self, *extra: str) -> list[str]:
        return [
            "--repo-root",
            str(REPO_ROOT),
            "--deployment",
            str(self.deployment),
            "--env-file",
            str(self.tmp / "absent.env"),
            "--memory",
            str(self.tmp / "memory.sqlite"),
            "--payees",
            str(self.tmp / "payees.json"),
            *extra,
        ]

    def refusal(self, *extra: str) -> str:
        """The message with which the app refuses to start."""
        with ExitStack() as stack, pytest.raises(hosted.StartupError) as refused:
            hosted.build_services(hosted.parser().parse_args(self.args(*extra)), stack, self.environment())
        return str(refused.value)

    def client(self) -> ChainClient:
        store = ArtifactStore(REPO_ROOT / "contracts", REPO_ROOT / "contracts" / "out", "forge")
        return ChainClient(self.node.rpc_url, store, ChainTuning(), expected_chain_id=31337)


@pytest.fixture(scope="module")
def local_evidence(tmp_path_factory: pytest.TempPathFactory) -> Iterator[LocalEvidence]:
    node = start_anvil(31337)
    try:
        yield LocalEvidence(node=node, out=tmp_path_factory.mktemp("app-evidence"), tmp=tmp_path_factory.mktemp("app"))
    finally:
        node.stop()


def test_ui_adopts_only_the_anchored_model(local_evidence: LocalEvidence) -> None:
    ev = local_evidence
    work = ["--evidence-dir", str(ev.work.directory)]

    ev.run_evidence("E01")
    empty = ev.tmp / "no-evidence"
    empty.mkdir()
    missing_keys = ev.refusal("--evidence-dir", str(empty))
    assert "key file" in missing_keys and "Run make evidence first." in missing_keys

    nothing_anchored = ev.refusal(*work, "--model", str(seed_model_path()))
    assert "holds no anchored detector model" in nothing_anchored

    ev.run_evidence("E14")
    version, anchored = latest_anchor(ev.client(), _bulletin(ev))
    assert model_hash(load_model(ev.work.model)) == anchored

    seed = ev.refusal(*work, "--model", str(seed_model_path()))
    assert "is not the anchored one" in seed

    tampered_path = ev.tmp / "tampered.json"
    original = load_model(ev.work.model)
    save_model(original.model_copy(update={"bias": original.bias + 0.5}), tampered_path)
    assert model_hash(load_model(tampered_path)) != anchored
    assert "is not the anchored one" in ev.refusal(*work, "--model", str(tampered_path))

    absent = ev.refusal(*work, "--model", str(ev.tmp / "absent_model.json"))
    assert f"version {version}" in absent and "is not at" in absent

    with ExitStack() as stack:
        services = hosted.build_services(hosted.parser().parse_args(ev.args(*work)), stack, ev.environment())
        guardian = vars(services.agent)["_guardian"]
        assert guardian.ready.model_hash == anchored
        assert guardian.ready.model_version == version
        assert "--model-hash" in guardian.argv
        assert guardian.argv[guardian.argv.index("--model-hash") + 1] == anchored
        assert guardian.argv[guardian.argv.index("--model") + 1] == str(ev.work.model)
        assert str(seed_model_path()) not in guardian.argv
        assert vars(services.owner)["_guard_version"] == version
        assert services.mode == "live"
    assert not guardian.running


def _bulletin(ev: LocalEvidence) -> str:
    return Deployment.from_file_dict(json.loads(ev.deployment.read_text(encoding="utf-8"))).threat_bulletin.address
