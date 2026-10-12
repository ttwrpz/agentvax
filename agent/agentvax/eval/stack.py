"""One local AgentVax stack on its own Anvil, shared by the evaluation runner and the mock demonstration.

``local_stack`` creates keys, deploys the contracts, runs and anchors the federation and starts each guardian on
the adopted model. It is a context manager that always cleans up the chain and the guardian processes.
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator, Mapping, Sequence
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path

from eth_account import Account

from agentvax.chain.artifacts import ArtifactStore
from agentvax.chain.client import ChainClient
from agentvax.chain.deploy import Deployment, WalletSpec, deploy_stack
from agentvax.config import GuardianTiming, Profile, load_profile
from agentvax.detector.model import Detector, load_model, model_hash
from agentvax.eval.environment import AnvilChain, RunnerConfig, find_executable
from agentvax.eval.executor import Executor, Signers, anchor_detector
from agentvax.eval.suites_schema import NATIVE_DECIMALS, to_units
from agentvax.fed.anchor import AnchorRecord, adopt
from agentvax.fed.run import build_detector_release
from agentvax.guardian.client import GuardianClient, child_environment
from agentvax.llm.base import LanguageModel
from agentvax.text import Strings


@dataclass(frozen=True)
class LocalStack:
    """A running local stack. Valid only inside the ``local_stack`` block that produced it."""

    chain: AnvilChain
    client: ChainClient
    profile: Profile
    deployment: Deployment
    signers: Signers
    guardians: Mapping[str, GuardianClient]
    detector: Detector
    """The adopted federated detector every guardian runs."""
    model_path: Path
    anchor: AnchorRecord

    @property
    def detector_hash(self) -> str:
        return model_hash(self.detector.model)

    def executor(self, config: RunnerConfig, llm: LanguageModel, strings: Strings) -> Executor:
        """The executor that holds this stack's signers."""
        return Executor(
            chain=self.chain,
            client=self.client,
            deployment=self.deployment,
            profile=self.profile,
            config=config,
            strings=strings,
            llm=llm,
            guardians=self.guardians,
            signers=self.signers,
            guard_version=self.detector.model.version,
        )


@contextmanager
def local_stack(
    *, config: RunnerConfig, profile: str, labels: Sequence[str], repo_root: Path
) -> Iterator[LocalStack]:
    """A deployed stack with one wallet per label in ``labels``, each with its own owner, agent and guardian."""
    deployed_profile = load_profile(profile)
    timing = GuardianTiming()
    child_env = child_environment(os.environ)
    with tempfile.TemporaryDirectory(prefix="agentvax-stack-") as work, ExitStack() as cleanup:
        work_dir = Path(work)
        chain = AnvilChain.start(config)
        cleanup.callback(chain.stop)
        store = ArtifactStore(
            repo_root / "contracts", repo_root / "contracts" / "out", find_executable(config.forge_executable)
        )
        client = ChainClient(chain.rpc_url, store, config.tuning(), expected_chain_id=config.chain_id)

        service = to_units(config.service_native, NATIVE_DECIMALS)
        deployer, aggregator, keeper = Account.create(), Account.create(), Account.create()
        owners = {label: Account.create() for label in labels}
        agents = {label: Account.create() for label in labels}
        for account in (deployer, aggregator, keeper, *owners.values(), *agents.values()):
            chain.set_balance(account.address, service)
        signers = Signers(deployer=deployer, aggregator=aggregator, keeper=keeper, owners=owners, agents=agents)

        key_files = {label: work_dir / f"guardian_{label}.key" for label in labels}
        guardian_addresses = {
            label: GuardianClient.create_key_file(path, child_env, timing) for label, path in key_files.items()
        }
        deployment = deploy_stack(
            client,
            deployer,
            deployer,
            aggregator.address,
            [
                WalletSpec(
                    label=label,
                    owner=owners[label].address,
                    agent=agents[label].address,
                    guardian=guardian_addresses[label],
                )
                for label in labels
            ],
            deployed_profile.name,
        )
        bulletin = deployment.threat_bulletin.address
        model_path = build_detector_release(work_dir / "federation")
        anchored = anchor_detector(client, signers, bulletin, load_model(model_path))
        detector = adopt(model_path, client, bulletin)
        guardians: dict[str, GuardianClient] = {}
        for label in labels:
            guardian = GuardianClient.start(
                wallet=deployment.wallet(label).address,
                chain_id=client.chain_id,
                rpc_url=chain.rpc_url,
                model_path=model_path,
                profile=deployed_profile.name,
                env=child_env,
                timing=timing,
                key_file=key_files[label],
                model_hash=model_hash(detector.model),
            )
            cleanup.callback(guardian.close)
            guardians[label] = guardian
        yield LocalStack(
            chain=chain,
            client=client,
            profile=deployed_profile,
            deployment=deployment,
            signers=signers,
            guardians=guardians,
            detector=detector,
            model_path=model_path,
            anchor=anchored,
        )
