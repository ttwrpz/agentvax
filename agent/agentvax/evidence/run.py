"""The evidence run.

    python -m agentvax.evidence.run --network testnet [--model mock|hosted] [--until EXX] [--redeploy]
    python -m agentvax.evidence.run --local [--out DIR] [--rpc-url URL] [--until EXX]

``--network testnet`` reads its settings from ``.env``, refuses chain ids other than 84532 and 11155111, and
writes the deployment, hashes and evidence files. ``--local`` runs against Anvil (chain id 31337) and writes only
under ``--out``. The mock model is labelled mock and the hosted model live.

Exit codes: 0 done, 1 a row failed, 2 the run could not start.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from eth_account import Account
from eth_account.signers.local import LocalAccount
from eth_utils import to_checksum_address

from agentvax.chain.anvil import LOCAL_CHAIN_ID, LocalNode, LocalNodeError, foundry_executable
from agentvax.chain.artifacts import ArtifactStore
from agentvax.chain.client import ChainClient, UnsupportedChain
from agentvax.chain.deploy import Deployment, DeploymentError, verify_deployment
from agentvax.config import (
    ChainTuning,
    EnvironmentSettings,
    GuardianTiming,
    Profile,
    load_profile,
    read_environment,
    settings_from_environment,
)
from agentvax.evidence.clock import ChainClock, LocalClock, NetworkClock
from agentvax.evidence.keys import KeyStore, KeyStoreError
from agentvax.evidence.layout import WorkLayout, testnet_deployment_file, testnet_work_directory
from agentvax.evidence.outputs import EvidenceUnverified, OutputPaths, verify_hashes, write_deployment, write_evidence
from agentvax.evidence.plan import ROW_IDS, WALLET_LABELS, EvidencePlan, load_plan, load_text, wei
from agentvax.evidence.rows import EvidenceRun, GuardianLaunch, Roles
from agentvax.evidence.state import STATE_FORMAT, Progress, RowFailed, RunState, StateStore
from agentvax.guardian.client import child_environment
from agentvax.llm.base import LanguageModel
from agentvax.text import Strings

TESTNET_CHAIN_IDS: frozenset[int] = frozenset({84532, 11155111})
"""The public test networks the evidence run accepts. Anvil (31337) is accepted only by ``--local``."""

MOCK_MODEL_LABEL = "mock"


class StartupRefused(RuntimeError):
    """The run cannot start: settings are missing, the chain is refused, or the owner key lacks funds."""


@dataclass
class Session:
    run: EvidenceRun
    client: ChainClient
    paths: OutputPaths
    explorer: str | None
    plan: EvidencePlan
    profile: Profile
    node: LocalNode | None

    def close(self) -> None:
        self.run.close()
        if self.node is not None:
            self.node.stop()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Produce the AgentVax execution evidence (rows E01 to E14).")
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--network", choices=["testnet"], help="the public test network configured in .env")
    target.add_argument("--local", action="store_true", help="self-test on a local Anvil with chain id 31337")
    parser.add_argument("--model", choices=["mock", "hosted"], default="mock", help="what drives the agent")
    parser.add_argument("--until", choices=list(ROW_IDS), help="stop after this row")
    parser.add_argument("--redeploy", action="store_true", help="set the recorded run aside and deploy again")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd(), help="repository root with contracts/")
    parser.add_argument("--env-file", type=Path, help="environment file (default: <repo-root>/.env)")
    parser.add_argument("--out", type=Path, help="output directory of --local (default: results/evidence-local)")
    parser.add_argument("--rpc-url", help="with --local: an Anvil already running, instead of starting one")
    return parser


def _report(message: str) -> None:
    print(f"evidence: {message}", flush=True)


# ---------------------------------------------------------------------------------------------- settings


def _testnet_settings(env: Mapping[str, str]) -> EnvironmentSettings:
    """The settings for ``--network testnet``. Refuses a chain id that is not a public test network."""
    try:
        settings = settings_from_environment(env)
    except ValueError as exc:
        raise StartupRefused(f"the test network settings in .env are refused: {exc}") from None
    if settings.testnet is None or settings.secrets.owner_private_key is None:
        raise StartupRefused("TESTNET_RPC_URL, TESTNET_CHAIN_ID and OWNER_PRIVATE_KEY must be set in .env")
    if settings.testnet.chain_id not in TESTNET_CHAIN_IDS:
        raise StartupRefused(
            f"chain id {settings.testnet.chain_id} is not a public test network the evidence run accepts "
            f"{sorted(TESTNET_CHAIN_IDS)}"
        )
    return settings


def _owner_from(settings: EnvironmentSettings) -> LocalAccount:
    secret = settings.secrets.owner_private_key
    if secret is None:
        raise StartupRefused("OWNER_PRIVATE_KEY must be set in .env")
    try:
        account: LocalAccount = Account.from_key(secret.get_secret_value())
    except Exception:
        raise StartupRefused("OWNER_PRIVATE_KEY is not a valid private key") from None
    return account


def _model(choice: str, settings: EnvironmentSettings | None) -> tuple[LanguageModel, str]:
    if choice == "mock":
        from agentvax.harness.mock_llm import MockLLM

        return MockLLM(), MOCK_MODEL_LABEL
    from agentvax.llm.factory import build

    if settings is None or settings.llm is None or settings.secrets.llm_api_key is None:
        raise StartupRefused("--model hosted needs LLM_PROVIDER, LLM_MODEL and LLM_API_KEY in .env")
    return build(settings.llm, settings.secrets.llm_api_key), f"live:{settings.llm.provider}/{settings.llm.model}"


# ---------------------------------------------------------------------------------------------- roles


_HELPERS = ("owner_b", "owner_c", "agent_a", "agent_b", "agent_c", "registrar", "aggregator")


def _roles(keys: KeyStore, owner: LocalAccount, env: Mapping[str, str], timing: GuardianTiming) -> Roles:
    return Roles(
        owners={"A": owner, "B": keys.helper("owner_b"), "C": keys.helper("owner_c")},
        agents={label: keys.agent(label) for label in WALLET_LABELS},
        registrar=keys.helper("registrar"),
        aggregator=keys.helper("aggregator"),
        guardians={label: keys.create_guardian(label, env, timing) for label in WALLET_LABELS},
    )


def _check_roles_match(deployment: Deployment, roles: Roles) -> None:
    if to_checksum_address(deployment.registrar) != roles.registrar.address:
        raise DeploymentError("the deployment's registrar is not the registrar key of this run")
    if to_checksum_address(deployment.aggregator) != roles.aggregator.address:
        raise DeploymentError("the deployment's aggregator is not the aggregator key of this run")
    for label in WALLET_LABELS:
        record = deployment.wallet(label)
        mine = (roles.owners[label].address, roles.agents[label].address, roles.guardians[label])
        recorded = tuple(to_checksum_address(a) for a in (record.owner, record.agent, record.guardian))
        if recorded != tuple(to_checksum_address(a) for a in mine):
            raise DeploymentError(f"wallet {label} of the deployment names other keys than this run holds")


def _owner_needs(client: ChainClient, roles: Roles, plan: EvidencePlan) -> int:
    """Native the owner key must hold before deployment: what the helpers and wallet A's fee reserve still lack,
    the agent of wallet A's working balance and the plan's spare for the owner's own transactions."""
    funding = plan.funding_for(client.chain_id)

    def lack(address: str, target: int) -> int:
        return max(0, target - int(client.web3.eth.get_balance(to_checksum_address(address))))

    needs = lack(roles.registrar.address, wei(funding.registrar))
    needs += lack(roles.aggregator.address, wei(funding.aggregator))
    for label in ("B", "C"):
        needs += lack(roles.owners[label].address, wei(funding.peer_owner))
        needs += lack(roles.agents[label].address, wei(funding.agent_working))
    needs += wei(funding.agent_working) + wei(funding.wallet_fee_reserve) + wei(funding.owner_spare)
    return needs


# ---------------------------------------------------------------------------------------------- preparation


def _artifacts(repo_root: Path) -> ArtifactStore:
    if not (repo_root / "contracts" / "foundry.toml").is_file():
        raise StartupRefused(
            f"{repo_root} has no contracts/foundry.toml. Run from the repository root or pass --repo-root."
        )
    return ArtifactStore(repo_root / "contracts", repo_root / "contracts" / "out", foundry_executable("forge"))


@dataclass(frozen=True)
class StartingPoint:
    """Where the run starts: the state to continue, a deployment file to reuse, and what must be set aside first."""

    state: RunState
    reused: Deployment | None
    archive_state: bool
    """The recorded run is set aside because ``--redeploy`` asked for a new deployment."""
    remove_evidence: bool
    """A new deployment starts, so a hashes file and evidence document from an earlier one no longer hold."""


def _starting_point(
    store: StateStore,
    paths: OutputPaths,
    client: ChainClient,
    plan: EvidencePlan,
    keys: KeyStore,
    agent_model: str,
    fresh: bool,
) -> StartingPoint:
    """Decides where the run starts without changing any file. The caller sets old files aside only after every
    check has passed."""
    if store.exists() and not fresh:
        state = store.load()
        if (state.chain_id, state.profile, state.agent_model) != (client.chain_id, plan.profile, agent_model):
            raise StartupRefused(
                f"the recorded run in {store.path} was made on chain {state.chain_id} with profile {state.profile} and "
                f"model {state.agent_model}. Use the same settings, or --redeploy to start again."
            )
        return StartingPoint(state=state, reused=None, archive_state=False, remove_evidence=False)
    state = RunState(format=STATE_FORMAT, chain_id=client.chain_id, profile=plan.profile, agent_model=agent_model)
    archive = fresh and store.exists()
    if not fresh and paths.deployment.is_file():
        data: dict[str, Any] = json.loads(paths.deployment.read_text(encoding="utf-8"))
        deployment = Deployment.from_file_dict(data)
        if deployment.chain_id != client.chain_id or deployment.profile != plan.profile:
            raise StartupRefused(f"{paths.deployment} is for another chain or profile. Use --redeploy.")
        missing = [name for name in _HELPERS if not keys.has_helper(name)]
        missing += [f"guardian_{label}" for label in WALLET_LABELS if keys.guardian_address(label) is None]
        if missing:
            raise StartupRefused(
                f"{paths.deployment} cannot be reused because the keys of its roles are not in {keys.directory} "
                f"({', '.join(missing)}). Use --redeploy."
            )
        return StartingPoint(state=state, reused=deployment, archive_state=archive, remove_evidence=False)
    return StartingPoint(state=state, reused=None, archive_state=archive, remove_evidence=True)


def _set_aside(store: StateStore) -> None:
    taken = {p.name for p in store.path.parent.glob("state.*.json")}
    number = 1
    while f"state.{number}.json" in taken:
        number += 1
    archived = store.path.with_name(f"state.{number}.json")
    store.path.replace(archived)
    _report(f"the recorded run was set aside as {archived.name}")


def prepare(args: argparse.Namespace, process_env: Mapping[str, str]) -> Session:
    """Everything the run needs, checked before the first transaction. A local node started here is stopped again
    if preparation fails."""
    plan = load_plan()
    repo_root: Path = args.repo_root.resolve()
    store_artifacts = _artifacts(repo_root)
    node: LocalNode | None = None
    if args.local and not args.rpc_url:
        anvil = foundry_executable("anvil")
        node = LocalNode.start(anvil, plan.anvil_startup_seconds, ChainTuning().rpc_timeout_seconds)
    try:
        return _prepare(args, process_env, plan, repo_root, store_artifacts, node)
    except BaseException:
        if node is not None:
            node.stop()
        raise


def _prepare(
    args: argparse.Namespace,
    process_env: Mapping[str, str],
    plan: EvidencePlan,
    repo_root: Path,
    store_artifacts: ArtifactStore,
    started: LocalNode | None,
) -> Session:
    profile = load_profile(plan.profile)
    tuning = ChainTuning()
    timing = GuardianTiming()
    child_env = child_environment(process_env)
    settings: EnvironmentSettings | None = None
    fresh = bool(args.redeploy) or started is not None
    node = started

    if args.local:
        out: Path = (args.out or repo_root / "results" / "evidence-local").resolve()
        if node is None:
            node = LocalNode.attach(args.rpc_url, tuning.rpc_timeout_seconds)
        client = ChainClient(node.rpc_url, store_artifacts, tuning, expected_chain_id=LOCAL_CHAIN_ID)
        work_dir = out / "work"
        keys = KeyStore(WorkLayout(work_dir).keys)
        owner = keys.helper("owner_a")
        native = wei(plan.local_owner_native)
        if int(client.web3.eth.get_balance(owner.address)) < native:
            node.set_balance(owner.address, native)
        paths = OutputPaths(out / "deployments" / "local.json", out / "evidence" / "hashes.json", out / "EVIDENCE.md")
        clock: ChainClock = LocalClock(node, _report)
        explorer = None
        rpc_url = node.rpc_url
        llm, agent_model = _model(args.model, None)
    else:
        env = read_environment(args.env_file or repo_root / ".env", process_env)
        settings = _testnet_settings(env)
        network = settings.testnet
        if network is None:
            raise StartupRefused("TESTNET_RPC_URL and TESTNET_CHAIN_ID must be set in .env")
        try:
            client = ChainClient(network.rpc_url, store_artifacts, tuning, expected_chain_id=network.chain_id)
        except UnsupportedChain as exc:
            raise StartupRefused(f"the node at TESTNET_RPC_URL is refused: {exc}") from None
        if client.chain_id not in TESTNET_CHAIN_IDS:
            raise StartupRefused(f"chain id {client.chain_id} is not a public test network")
        owner = _owner_from(settings)
        work_dir = testnet_work_directory(repo_root, client.chain_id)
        keys = KeyStore(WorkLayout(work_dir).keys)
        paths = OutputPaths(
            testnet_deployment_file(repo_root),
            repo_root / "evidence" / "hashes.json",
            repo_root / "docs" / "EVIDENCE.md",
        )
        clock = NetworkClock(client, plan.timing, _report)
        explorer = plan.explorer_for(client.chain_id, network.explorer_url)
        rpc_url = network.rpc_url
        llm, agent_model = _model(args.model, settings)

    funding = plan.funding_for(client.chain_id)
    if wei(funding.agent_before_top_up) >= profile.mandate.agent_balance_floor:
        raise StartupRefused("the plan funds the agent of wallet A at or above the floor, so E06 could not run")

    store = StateStore(WorkLayout(work_dir).state)
    start = _starting_point(store, paths, client, plan, keys, agent_model, fresh)
    state = start.state
    roles = _roles(keys, owner, child_env, timing)
    if start.reused is not None:
        try:
            _check_roles_match(start.reused, roles)
            verify_deployment(client, start.reused)
        except DeploymentError as exc:
            raise RowFailed("E01", f"{paths.deployment} cannot be reused: {exc}") from None
        _report(f"reusing the deployment in {paths.deployment}: every address holds the expected code")
    try:
        verify_hashes(client, [h for record in state.steps.values() for h in record.hashes])
        verify_hashes(client, [h for record in state.rows.values() for h in record.hashes])
    except EvidenceUnverified as exc:
        raise StartupRefused(f"the recorded run does not match the chain ({exc}). Use --redeploy.") from None
    if state.deployment is None and start.reused is None:
        needs = _owner_needs(client, roles, plan)
        holds = int(client.web3.eth.get_balance(owner.address))
        if holds < needs:
            raise StartupRefused(
                f"the owner key {owner.address} holds {holds / 10**18:.6f} native, the run needs about "
                f"{needs / 10**18:.6f}. Fund it from a faucet and run again."
            )

    if start.archive_state:
        _set_aside(store)
    if start.remove_evidence:
        paths.remove_evidence()
    progress = Progress(store, state, lambda hashes: verify_hashes(client, hashes))
    if start.reused is not None:
        progress.set_deployment(start.reused)

    def on_deployment(deployment: Deployment) -> None:
        write_deployment(
            paths.deployment,
            deployment,
            {
                "agentModel": agent_model,
                "delays": {
                    "delay": profile.mandate.delay,
                    "pressureHold": profile.mandate.pressure_hold,
                    "looseningDelay": profile.mandate.loosening_delay,
                },
            },
        )

    run = EvidenceRun(
        client=client,
        clock=clock,
        progress=progress,
        plan=plan,
        profile=profile,
        roles=roles,
        llm=llm,
        strings=Strings.load(),
        work_dir=work_dir,
        guardian_launch=GuardianLaunch(
            rpc_url=rpc_url,
            env=child_env,
            timing=timing,
            key_files={label: keys.guardian_key_file(label) for label in WALLET_LABELS},
        ),
        report=_report,
        on_deployment=on_deployment,
    )
    return Session(run=run, client=client, paths=paths, explorer=explorer, plan=plan, profile=profile, node=node)


# ---------------------------------------------------------------------------------------------- finishing


def finish(session: Session) -> None:
    """Writes the evidence document and the hashes file once every row is done."""
    state = session.run.progress.state
    text = load_text()
    model = state.agent_model
    if model == MOCK_MODEL_LABEL:
        model_sentence = text.model_mock
    else:
        provider, _, name = model.removeprefix("live:").partition("/")
        model_sentence = text.model_live.format(provider=provider, model_name=name)
    write_evidence(
        session.paths,
        session.client,
        state,
        text,
        {
            "network": session.plan.network_name(state.chain_id),
            "chain_id": state.chain_id,
            "profile": state.profile,
            "delay": session.profile.mandate.delay,
            "hold": session.profile.mandate.pressure_hold,
            "loosening": session.profile.mandate.loosening_delay,
            "model": model_sentence,
        },
        session.explorer,
        session.run.setup_hashes(),
    )


def main(argv: list[str] | None = None, process_env: Mapping[str, str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if not args.local and (args.out is not None or args.rpc_url is not None):
        parser.error("--out and --rpc-url belong to --local")
    environment = os.environ if process_env is None else process_env
    try:
        session = prepare(args, environment)
    except (StartupRefused, LocalNodeError, KeyStoreError) as exc:
        print(f"EVIDENCE NOT STARTED: {exc}", file=sys.stderr, flush=True)
        return 2
    except RowFailed as exc:
        print(f"EVIDENCE FAILED at {exc.row}: {exc.reason}", file=sys.stderr, flush=True)
        return 1
    try:
        session.run.run(until=args.until)
        state = session.run.progress.state
        if all(row in state.rows for row in ROW_IDS):
            finish(session)
            _report(
                "every row E01 to E14 is done and checked on chain. "
                f"Wrote {session.paths.hashes} and {session.paths.document}"
            )
        else:
            _report(f"stopped after {args.until} as asked. Run again without --until to continue.")
        return 0
    except RowFailed as exc:
        print(f"EVIDENCE FAILED at {exc.row}: {exc.reason}", file=sys.stderr, flush=True)
        return 1
    except EvidenceUnverified as exc:
        print(f"EVIDENCE FAILED: {exc}", file=sys.stderr, flush=True)
        return 1
    finally:
        session.close()


if __name__ == "__main__":
    raise SystemExit(main())
