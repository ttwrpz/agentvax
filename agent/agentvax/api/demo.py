"""``python -m agentvax.api.demo``: the interface on a local Anvil with the mock language model.

This is the only entry point of the interface that builds ``MockLLM``. It starts the same local stack as the
evaluation runner (``agentvax.eval.stack.local_stack``: its own Anvil, fresh keys, the federated detector anchored
and adopted, one guardian process per wallet) with the ``demo`` profile (short delays, so a wait can be watched), sets
up the three wallets of the demonstration scenario through the evaluation executor, and serves the same app
as ``agentvax.api.app``. Wallet A is the worked example, B is a healthy wallet and C does not accept the
channel the scenario's attack arrives on. Their data is ``api/data/demo_wallets.json``. The page and every response
are labelled ``mock``. Nothing it shows says anything about model quality: it shows that the plumbing and the
contracts work. Anvil and the guardians are stopped when the server stops.
"""

from __future__ import annotations

import argparse
import sys
import threading
from collections.abc import Sequence
from contextlib import ExitStack
from decimal import Decimal
from pathlib import Path

import uvicorn

from agentvax import resources
from agentvax.api.app import LOOPBACK, create_app
from agentvax.api.services import ExpectedIncomeBook, OwnerActions, PayeeNames, Services
from agentvax.eval.environment import ChainError, RunnerConfig
from agentvax.eval.run import RUNNER_CONFIG
from agentvax.eval.stack import local_stack
from agentvax.eval.suites_schema import WalletSetup
from agentvax.explain import ExpectedIncomeItem
from agentvax.fed.run import FederationFailed
from agentvax.guardian.client import GuardianUnavailable
from agentvax.harness.mock_llm import MockLLM
from agentvax.memory import MemoryStore
from agentvax.runtime import Agent
from agentvax.text import Strings
from agentvax.types import TOKEN_UNIT, Strict

PROFILE = "demo"
PLAN_PATH = "api/data/demo_wallets.json"


class ExpectedIncomeSetup(Strict):
    """Income the owner expects, ``due_in`` seconds after the setup ends. The page shows it and never counts it."""

    amount: str
    due_in: int


class DemoWallet(Strict):
    """One wallet of the demonstration and the state it starts in."""

    label: str
    setup: WalletSetup
    expected_income: tuple[ExpectedIncomeSetup, ...] = ()


class DemoPlan(Strict):
    """The wallets of the demonstration. The first one is shown when the page opens."""

    wallets: tuple[DemoWallet, ...]


def load_plan() -> DemoPlan:
    return resources.load_model(DemoPlan, PLAN_PATH)


def build_services(root: Path, port: int, stack: ExitStack) -> dict[str, Services]:
    """The interface's services, one per wallet of the plan, on a fresh local stack (``agentvax.eval.stack``) with the
    ``demo`` profile. The stack is entered into ``stack``, so Anvil and the guardians stop when it closes. Setting a
    wallet up moves the chain clock forward, so the wallets are set up last to first and the first wallet's bills
    count their days from the end of all the setups. After that the chain follows the wall clock, so the demo
    profile's short delays can be watched."""
    plan = load_plan()
    labels = tuple(wallet.label for wallet in plan.wallets)
    config = resources.load_model(RunnerConfig, RUNNER_CONFIG)
    local = stack.enter_context(local_stack(config=config, profile=PROFILE, labels=labels, repo_root=root))
    strings = Strings.load()
    executor = local.executor(config, MockLLM(), strings)
    contexts = {wallet.label: executor.set_up(wallet.label, wallet.setup) for wallet in reversed(plan.wallets)}
    local.chain.use_wall_clock()
    ended = local.client.latest_timestamp()

    origins = (f"http://{LOOPBACK}:{port}", f"http://localhost:{port}")
    services: dict[str, Services] = {}
    chain_lock = threading.Lock()
    for wallet in plan.wallets:
        context = contexts[wallet.label]
        memory = MemoryStore(":memory:", shared_between_threads=True)
        stack.callback(memory.close)
        agent = Agent(
            llm=executor.llm,
            chain=local.client,
            wallet=context.address,
            agent_signer=local.signers.agents[wallet.label],
            guardian=local.guardians[wallet.label],
            memory=memory,
            strings=strings,
            payee_names=context.payee_names,
        )
        names = PayeeNames()
        names.names.update(context.payee_names)
        income = ExpectedIncomeBook()
        for item in wallet.expected_income:
            income.add(ExpectedIncomeItem(amount=int(Decimal(item.amount) * TOKEN_UNIT), expected_at=ended + item.due_in))
        services[wallet.label] = Services(
            agent=agent,
            chain=local.client,
            wallet=context.address,
            owner=OwnerActions(
                client=local.client,
                signer=local.signers.owners[wallet.label],
                wallet=context.address,
                agent=agent,
                memory=memory,
                names=names,
                guard_version=local.detector.model.version,
            ),
            strings=strings,
            explorer_url=None,
            allowed_origins=origins,
            mode="mock",
            names=names,
            income=income,
            chain_lock=chain_lock,
        )
    return services


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Serve the AgentVax interface on a local chain with the mock model.")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd(), help="repository root with contracts/")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    if not (args.repo_root / "contracts" / "foundry.toml").is_file():
        print(f"demonstration not started: {args.repo_root} has no contracts/foundry.toml", file=sys.stderr)
        return 2
    with ExitStack() as stack:
        try:
            services = build_services(args.repo_root, args.port, stack)
        except (ChainError, GuardianUnavailable, FederationFailed) as error:
            print(f"demonstration not started: {error}", file=sys.stderr)
            return 2
        print(f"Mock demonstration on a local chain. Open http://{LOOPBACK}:{args.port}/", flush=True)
        uvicorn.run(create_app(services), host=LOOPBACK, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
