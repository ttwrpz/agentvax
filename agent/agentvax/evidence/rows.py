"""The evidence rows E01 to E14, and the setup they need.

Rows are driven through the agent runtime. The E04 schedule is an owner-given intent attested by the guardian,
and owner actions are signed by the owner keys. Each row checks on chain that it reached its outcome.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any

from eth_account.signers.local import LocalAccount
from eth_utils import to_checksum_address
from web3.types import TxReceipt

from agentvax import capsules
from agentvax.chain import agent as agent_actions
from agentvax.chain import owner as owner_actions
from agentvax.chain.client import ChainClient, Signer
from agentvax.chain.deploy import Deployment, WalletSpec, deploy_stack
from agentvax.config import GuardianTiming, Profile
from agentvax.detector.model import load_model, model_hash
from agentvax.evidence.clock import ChainClock
from agentvax.evidence.layout import WorkLayout
from agentvax.evidence.plan import NATIVE_DECIMALS, ROW_IDS, EvidencePlan, Funding, tokens, wei
from agentvax.evidence.state import Progress, RowFailed, StepRecord, receipt_hash
from agentvax.fed.anchor import adopt, anchor_model
from agentvax.fed.run import build_detector_release
from agentvax.guardian.client import GuardianClient
from agentvax.llm.base import LanguageModel
from agentvax.memory import MemoryStore
from agentvax.names import identity_hash
from agentvax.owner_tools import apply_payee_addition
from agentvax.planner import OwnerInstruction
from agentvax.reader import UntrustedContent
from agentvax.runtime import Agent, AgentReply, ReplyKind
from agentvax.text import Strings
from agentvax.types import (
    PRESSURE_FLAGS,
    TOKEN_DECIMALS,
    Channel,
    DecidingCheck,
    Flag,
    Intent,
    ScheduleTerms,
    Task,
    Tier,
)

EXECUTION_ORDER: tuple[str, ...] = (
    "E01",
    "E14",
    "E02",
    "setup",
    "E06",
    "agent_funding",
    "E03",
    "E04",
    "E07",
    "E08",
    "E09",
    "E05",
    "E10",
    "E11",
    "E12",
    "E13",
)
"""Rows and setup phases in the order they run. Every row id appears exactly once."""

CAPSULE_SYNC_BATCH = 8
"""Capsules a wallet syncs per call, the contract's per-call maximum."""


@dataclass(frozen=True)
class Roles:
    """The signers of the run. The owner of wallet A also deploys and mints. No guardian key is held here."""

    owners: Mapping[str, LocalAccount]
    agents: Mapping[str, LocalAccount]
    registrar: LocalAccount
    aggregator: LocalAccount
    guardians: Mapping[str, str]
    """Guardian addresses by wallet label."""

    @property
    def deployer(self) -> LocalAccount:
        return self.owners["A"]

    def wallet_specs(self) -> list[WalletSpec]:
        return [
            WalletSpec(
                label=label,
                owner=owner.address,
                agent=self.agents[label].address,
                guardian=self.guardians[label],
            )
            for label, owner in sorted(self.owners.items())
        ]


@dataclass(frozen=True)
class GuardianLaunch:
    """What starting a guardian process needs. The key stays in its file. Only the path is handed over."""

    rpc_url: str
    env: Mapping[str, str]
    timing: GuardianTiming
    key_files: Mapping[str, Path]


def format_tokens(amount: int) -> str:
    """``amount`` base units of MockUSD as a plain decimal, with no trailing zeros after the point."""
    text = format(Decimal(amount) / (Decimal(10) ** TOKEN_DECIMALS), "f")
    return text.rstrip("0").rstrip(".") if "." in text else text


def format_native(amount: int) -> str:
    """``amount`` wei as a plain decimal number of whole native units."""
    text = format(Decimal(amount) / (Decimal(10) ** NATIVE_DECIMALS), "f")
    return text.rstrip("0").rstrip(".") if "." in text else text


def _spoken_list(items: Sequence[str]) -> str:
    """``["800", "150", "120"]`` becomes ``"800, 150 and 120"``."""
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def _held(reply: AgentReply) -> bool:
    """True if the request was held for the owner (queued or proposed) with a transaction and an item id."""
    held = reply.kind in (ReplyKind.QUEUED, ReplyKind.PROPOSED)
    return held and reply.tx_hash is not None and reply.item_id is not None


def _hash_of(receipt: TxReceipt) -> str:
    return receipt_hash(receipt)


class EvidenceRun:
    """Runs every row in ``EXECUTION_ORDER`` that the state does not record as done."""

    def __init__(
        self,
        *,
        client: ChainClient,
        clock: ChainClock,
        progress: Progress,
        plan: EvidencePlan,
        profile: Profile,
        roles: Roles,
        llm: LanguageModel,
        strings: Strings,
        work_dir: Path,
        guardian_launch: GuardianLaunch,
        report: Callable[[str], None],
        on_deployment: Callable[[Deployment], None],
    ) -> None:
        self.client = client
        self.clock = clock
        self.progress = progress
        self.plan = plan
        self.profile = profile
        self.roles = roles
        self.llm = llm
        self.strings = strings
        self.work_dir = work_dir
        self.launch = guardian_launch
        self.report = report
        self.on_deployment = on_deployment
        self.funding: Funding = plan.funding_for(client.chain_id)
        self._guardians: dict[str, GuardianClient] = {}
        self._memories: dict[str, MemoryStore] = {}
        self._agents: dict[str, Agent] = {}
        self._model_path = WorkLayout(work_dir).model

    # ------------------------------------------------------------------------------------ driving

    def run(self, until: str | None = None) -> None:
        """Runs the rows in order, stopping after row ``until`` if given. Raises ``RowFailed`` naming the row."""
        if until is not None and until not in ROW_IDS:
            raise ValueError(f"unknown row {until}")
        try:
            for phase in EXECUTION_ORDER:
                if phase in ROW_IDS and self.progress.row_done(phase):
                    self.report(f"{phase} already done, its transactions were checked on chain")
                else:
                    self._run_phase(phase)
                if phase == until:
                    return
        finally:
            self.close()

    def _run_phase(self, phase: str) -> None:
        action = getattr(self, f"_phase_{phase.lower()}")
        if phase not in ROW_IDS:
            action()
            return
        self.report(f"{phase} started")
        try:
            action()
        except RowFailed:
            raise
        except Exception as exc:
            raise RowFailed(phase, f"{type(exc).__name__}: {exc}") from exc
        self.report(f"{phase} done")

    def close(self) -> None:
        for guardian in self._guardians.values():
            guardian.close()
        for memory in self._memories.values():
            memory.close()
        self._guardians.clear()
        self._memories.clear()
        self._agents.clear()

    # ------------------------------------------------------------------------------------ helpers

    @property
    def deployment(self) -> Deployment:
        deployment = self.progress.state.deployment
        if deployment is None:
            raise RuntimeError("the stack is not deployed")
        return deployment

    def wallet(self, label: str) -> str:
        return self.deployment.wallet(label).address

    def _step(self, key: str, action: Callable[[], StepRecord]) -> StepRecord:
        return self.progress.step(key, action)

    def _tx_step(self, key: str, send: Callable[[], TxReceipt], **values: int | str) -> StepRecord:
        return self._step(key, lambda: StepRecord(hashes=(_hash_of(send()),), values=dict(values)))

    def _receipt(self, tx_hash: str) -> TxReceipt:
        return self.client.web3.eth.get_transaction_receipt(tx_hash)  # type: ignore[arg-type]

    def _events(self, tx_hash: str, label: str, event: str) -> list[Any]:
        return self.client.events(self._receipt(tx_hash), self.client.wallet(self.wallet(label)), event)

    def _block_time(self, tx_hash: str) -> int:
        return int(self.client.web3.eth.get_block(self._receipt(tx_hash)["blockNumber"])["timestamp"])

    def _margin(self) -> int:
        return self.plan.timing.wait_margin_seconds

    def _fund_to(self, signer: Signer, address: str, target: int) -> list[str]:
        """Sends ``address`` what it lacks below ``target``. Nothing if it already holds that much."""
        balance = int(self.client.web3.eth.get_balance(to_checksum_address(address)))
        if balance >= target:
            return []
        return [_hash_of(self.client.send_value(signer, address, target - balance))]

    def _payee_id(self, label: str, name: str) -> int:
        index = self.plan.wallets[label].payees.index(name)
        return int(self.progress.record(f"setup/payees_applied/{label}/{index}").values["payee_id"])

    def _payee_names(self, label: str) -> dict[int, str]:
        return {self._payee_id(label, name): name for name in self.plan.wallets[label].payees}

    def memory(self, label: str) -> MemoryStore:
        if label not in self._memories:
            self._memories[label] = MemoryStore(self.work_dir / f"memory_{label}.sqlite")
        return self._memories[label]

    def guardian(self, label: str) -> GuardianClient:
        """The guardian process of wallet ``label``, running only the detector model anchored in E14."""
        if label not in self._guardians:
            detector = adopt(self._model_path, self.client, self.deployment.threat_bulletin.address)
            self._guardians[label] = GuardianClient.start(
                wallet=self.wallet(label),
                chain_id=self.client.chain_id,
                rpc_url=self.launch.rpc_url,
                model_path=self._model_path,
                profile=self.profile.name,
                env=self.launch.env,
                timing=self.launch.timing,
                key_file=self.launch.key_files[label],
                model_hash=model_hash(detector.model),
            )
        return self._guardians[label]

    def agent(self, label: str) -> Agent:
        if label not in self._agents:
            self._agents[label] = Agent(
                llm=self.llm,
                chain=self.client,
                wallet=self.wallet(label),
                agent_signer=self.roles.agents[label],
                guardian=self.guardian(label),
                memory=self.memory(label),
                strings=self.strings,
                payee_names=self._payee_names(label),
            )
        return self._agents[label]

    def ask(self, row: str, label: str, instruction: str, documents: Sequence[str] = ()) -> AgentReply:
        reply = self.agent(label).handle(
            OwnerInstruction(text=instruction),
            [UntrustedContent(channel=Channel.MESSAGE, text=d) for d in documents],
        )
        self.report(f"{row}: the agent of wallet {label} replied {reply.kind.value} ({reply.text_key})")
        return reply

    def _expect(self, row: str, reply: AgentReply, kind: ReplyKind, tier: Tier | None = None) -> str:
        """The transaction hash of ``reply``, which must be of ``kind`` (and ``tier`` if given)."""
        if reply.kind is not kind or (tier is not None and reply.tier is not tier):
            got = f"{reply.kind.value}" + (f" at L{int(reply.tier)}" if reply.tier is not None else "")
            want = f"{kind.value}" + (f" at L{int(tier)}" if tier is not None else "")
            raise RowFailed(row, f"expected {want}, the agent's request ended {got} ({reply.text_key})")
        if reply.tx_hash is None:
            raise RowFailed(row, "the agent's reply carries no transaction")
        return reply.tx_hash

    def _executed(self, row: str, label: str, tx_hash: str, task: Task, item_id: int | None = None) -> int:
        """The amount of the single ``Executed`` event of ``task`` in ``tx_hash``."""
        events = [
            e
            for e in self._events(tx_hash, label, "Executed")
            if int(e["args"]["task"]) == int(task) and (item_id is None or int(e["args"]["itemId"]) == item_id)
        ]
        if len(events) != 1:
            raise RowFailed(row, f"transaction {tx_hash} did not execute the expected {task.name}")
        return int(events[0]["args"]["amount"])

    def _wait_for_item(self, row: str, label: str, item_id: int, what: str) -> None:
        ready = int(self.client.wallet(self.wallet(label)).functions.itemReadyAt(item_id).call())
        self.clock.wait_until(ready + self._margin(), f"{what} of {row}")

    # ------------------------------------------------------------------------------------ deployment and model

    def _phase_e01(self) -> None:
        self._step("setup/fund/helpers", self._fund_helpers)
        if self.progress.state.deployment is None:
            deployment = deploy_stack(
                self.client,
                self.roles.deployer,
                self.roles.registrar,
                self.roles.aggregator.address,
                self.roles.wallet_specs(),
                self.profile.name,
            )
            self.progress.set_deployment(deployment)
        self.on_deployment(self.deployment)
        self.progress.complete_row("E01", self.deployment.transaction_hashes(), {})

    def _fund_helpers(self) -> StepRecord:
        owner = self.roles.deployer
        targets = [
            (self.roles.registrar.address, wei(self.funding.registrar)),
            (self.roles.aggregator.address, wei(self.funding.aggregator)),
            (self.roles.agents["A"].address, wei(self.funding.agent_before_top_up)),
        ]
        for label in ("B", "C"):
            targets.append((self.roles.owners[label].address, wei(self.funding.peer_owner)))
            targets.append((self.roles.agents[label].address, wei(self.funding.agent_working)))
        hashes = [h for address, target in targets for h in self._fund_to(owner, address, target)]
        return StepRecord(hashes=tuple(hashes), values={})

    def _phase_e14(self) -> None:
        def release() -> StepRecord:
            if not self._model_path.is_file():
                build_detector_release(self.work_dir)
            model = load_model(self._model_path)
            return StepRecord(hashes=(), values={"version": model.version, "model_hash": model_hash(model)})

        built = self._step("E14/model", release)
        model = load_model(self._model_path)
        if model_hash(model) != built.values["model_hash"]:
            raise RowFailed("E14", f"the model file in {self.work_dir} is not the one this run built")

        def anchor() -> StepRecord:
            record = anchor_model(self.client, self.roles.aggregator, self.deployment.threat_bulletin.address, model)
            return StepRecord(
                hashes=(record.tx_hash,), values={"version": record.version, "model_hash": record.model_hash}
            )

        anchored = self._step("E14/anchor", anchor)
        adopt(self._model_path, self.client, self.deployment.threat_bulletin.address)
        self.progress.complete_row(
            "E14",
            list(anchored.hashes),
            {"version": str(anchored.values["version"]), "model_hash": str(anchored.values["model_hash"])},
        )

    # ------------------------------------------------------------------------------------ mandates and setup

    def _set_mandate(self, row: str, label: str) -> StepRecord:
        wallet = self.wallet(label)
        contract = self.client.wallet(wallet)
        if contract.functions.mandateSet().call():
            raise RowFailed(
                row,
                f"wallet {label} already has a mandate that this run did not record. "
                "The state file of the run that set it is needed, or start again with --redeploy.",
            )
        mandate = self.profile.mandate.mandate(self.client.latest_timestamp())
        receipt = owner_actions.set_mandate(self.client, self.roles.owners[label], wallet, self.plan.mission, mandate)
        events = self.client.events(receipt, contract, "MandateSet")
        if len(events) != 1:
            raise RowFailed(row, "setting the mandate emitted no MandateSet event")
        return StepRecord(
            hashes=(_hash_of(receipt),), values={"mandate_hash": "0x" + bytes(events[0]["args"]["mandateHash"]).hex()}
        )

    def _phase_e02(self) -> None:
        record = self._step("E02/mandate", lambda: self._set_mandate("E02", "A"))
        self.progress.complete_row("E02", list(record.hashes), {"mandate_hash": str(record.values["mandate_hash"])})

    def _phase_setup(self) -> None:
        self.report("setup started: mandates of B and C, payees, test tokens and the fee reserve")
        for label in ("B", "C"):
            self._step(f"setup/mandates/{label}", lambda label=label: self._set_mandate("setup", label))

        ready_times = []
        for label in sorted(self.plan.wallets):
            for index, name in enumerate(self.plan.wallets[label].payees):
                proposed = self._step(
                    f"setup/payees_proposed/{label}/{index}",
                    lambda label=label, name=name: self._propose_payee(label, name),
                )
                ready_times.append(int(proposed.values["ready_at"]))
        pending = [
            (label, index)
            for label in sorted(self.plan.wallets)
            for index in range(len(self.plan.wallets[label].payees))
            if not self.progress.done(f"setup/payees_applied/{label}/{index}")
        ]
        if pending:
            self.clock.wait_until(max(ready_times) + self._margin(), "the loosening delay on the new payees")
        for label, index in pending:
            self._step(
                f"setup/payees_applied/{label}/{index}",
                lambda label=label, index=index: self._apply_payee(label, index),
            )

        for label in sorted(self.plan.wallets):
            self._step(f"setup/tokens/{label}", lambda label=label: self._mint_to(label))
        reserve = wei(self.funding.wallet_fee_reserve)
        self._step(
            "setup/fund/fee_reserve",
            lambda: StepRecord(hashes=tuple(self._fund_to(self.roles.deployer, self.wallet("A"), reserve)), values={}),
        )
        self.report("setup done")

    def _propose_payee(self, label: str, name: str) -> StepRecord:
        account = to_checksum_address("0x" + os.urandom(20).hex())
        change = owner_actions.propose_add_payee(
            self.client, self.roles.owners[label], self.wallet(label), identity_hash(name), account
        )
        return StepRecord(
            hashes=(change.tx_hash,),
            values={"change_id": change.change_id, "ready_at": change.ready_at, "account": account},
        )

    def _apply_payee(self, label: str, index: int) -> StepRecord:
        proposed = self.progress.record(f"setup/payees_proposed/{label}/{index}")
        added = apply_payee_addition(
            self.client,
            self.roles.owners[label],
            self.wallet(label),
            int(proposed.values["change_id"]),
            self.memory(label),
        )
        if to_checksum_address(added.account) != proposed.values["account"]:
            raise RowFailed("setup", f"wallet {label} added another account than the one proposed")
        return StepRecord(hashes=(added.tx_hash,), values={"payee_id": added.payee_id})

    def _mint_to(self, label: str) -> StepRecord:
        token = self.client.token(self.deployment.mock_usd.address)
        wallet = self.wallet(label)
        target = tokens(self.plan.wallets[label].tokens)
        balance = int(token.functions.balanceOf(wallet).call())
        if balance > target:
            raise RowFailed("setup", f"wallet {label} already holds more MockUSD than the plan gives it")
        if balance == target:
            return StepRecord(hashes=(), values={})
        receipt = self.client.send(self.roles.deployer, token.functions.mint(wallet, target - balance))
        return StepRecord(hashes=(_hash_of(receipt),), values={})

    def _phase_agent_funding(self) -> None:
        self._step(
            "setup/agent_funding/A",
            lambda: StepRecord(
                hashes=tuple(
                    self._fund_to(self.roles.deployer, self.roles.agents["A"].address, wei(self.funding.agent_working))
                ),
                values={},
            ),
        )

    # ------------------------------------------------------------------------------------ wallet A rows

    def _phase_e06(self) -> None:
        floor = self.client.wallet_view(self.wallet("A")).mandate.agent_balance_floor

        def top_up() -> StepRecord:
            balance = int(self.client.web3.eth.get_balance(self.roles.agents["A"].address))
            if balance >= floor:
                raise RowFailed("E06", f"the agent holds {balance} wei, not below the floor of {floor} wei")
            reply = self.ask("E06", "A", self.plan.rows.E06.instruction)
            tx_hash = self._expect("E06", reply, ReplyKind.EXECUTED, Tier.L1)
            amount = self._executed("E06", "A", tx_hash, Task.FEE_TOPUP)
            return StepRecord(hashes=(tx_hash,), values={"amount": amount})

        record = self._step("E06/top_up", top_up)
        self.progress.complete_row("E06", list(record.hashes), {"amount": format_native(int(record.values["amount"]))})

    def _phase_e03(self) -> None:
        def pay() -> StepRecord:
            reply = self.ask("E03", "A", self.plan.rows.E03.instruction)
            tx_hash = self._expect("E03", reply, ReplyKind.EXECUTED, Tier.L1)
            return StepRecord(hashes=(tx_hash,), values={"amount": self._executed("E03", "A", tx_hash, Task.PAYMENT)})

        record = self._step("E03/pay", pay)
        self.progress.complete_row("E03", list(record.hashes), {"amount": format_tokens(int(record.values["amount"]))})

    def _phase_e04(self) -> None:
        plan = self.plan.rows.E04
        wallet = self.wallet("A")

        def create() -> StepRecord:
            view = self.client.wallet_view(wallet)
            terms = ScheduleTerms(
                period=view.min_schedule_period,
                first_due=self.client.latest_timestamp() + plan.first_due_lead_seconds,
                max_runs=plan.max_runs,
            )
            intent = Intent(
                task=Task.SCHEDULE_CREATE,
                payee_id=self._payee_id("A", plan.payee),
                amount=tokens(plan.amount),
                schedule_id=0,
                purpose_hash=terms.purpose_hash(),
                nonce=view.nonce,
            )
            signed = self.guardian("A").attest(intent, [], Flag.KNOWN_PAYEE_IDENTITY)
            submission = agent_actions.submit_schedule(
                self.client, self.roles.agents["A"], wallet, intent, terms, signed.attestation, signed.signature
            )
            if submission.decision.tier is not Tier.L1:
                raise RowFailed("E04", f"the schedule was decided at L{int(submission.decision.tier)}, not L1")
            created = self._events(submission.tx_hash, "A", "ScheduleCreated")
            if len(created) != 1:
                raise RowFailed("E04", "the schedule submission created no schedule")
            return StepRecord(
                hashes=(submission.tx_hash,),
                values={"schedule_id": int(created[0]["args"]["scheduleId"]), "first_due": terms.first_due},
            )

        created = self._step("E04/create", create)
        schedule_id = int(created.values["schedule_id"])
        if not self.progress.done("E04/run"):
            self.clock.wait_until(int(created.values["first_due"]) + self._margin(), "the first occurrence of E04")

        def run_once() -> StepRecord:
            receipt = agent_actions.run_schedule(self.client, self.roles.agents["A"], wallet, schedule_id)
            tx_hash = _hash_of(receipt)
            ran = [e for e in self._events(tx_hash, "A", "ScheduleRan") if int(e["args"]["scheduleId"]) == schedule_id]
            if len(ran) != 1:
                raise RowFailed("E04", "the schedule was held instead of run")
            return StepRecord(hashes=(tx_hash,), values={"amount": int(ran[0]["args"]["amount"])})

        ran = self._step("E04/run", run_once)
        self.progress.complete_row(
            "E04", [*created.hashes, *ran.hashes], {"amount": format_tokens(int(ran.values["amount"]))}
        )

    def _queued(self, row: str, label: str, instruction: str, documents: Sequence[str] = ()) -> StepRecord:
        reply = self.ask(row, label, instruction, documents)
        tx_hash = self._expect(row, reply, ReplyKind.QUEUED, Tier.L2)
        if reply.item_id is None:
            raise RowFailed(row, "the queued request has no item id")
        return StepRecord(
            hashes=(tx_hash,),
            values={"item_id": reply.item_id, "deciding_check": int(reply.deciding_check or 0)},
        )

    def _phase_e07(self) -> None:
        queued = self._step("E07/queue", lambda: self._queued("E07", "A", self.plan.rows.E07.instruction))
        item_id = int(queued.values["item_id"])
        if not self.progress.done("E07/execute"):
            self._wait_for_item("E07", "A", item_id, "the L2 delay")

        def execute() -> StepRecord:
            receipt = agent_actions.execute_pending(self.client, self.roles.agents["A"], self.wallet("A"), item_id)
            tx_hash = _hash_of(receipt)
            amount = self._executed("E07", "A", tx_hash, Task.PAYMENT, item_id)
            return StepRecord(hashes=(tx_hash,), values={"amount": amount})

        executed = self._step("E07/execute", execute)
        self.progress.complete_row(
            "E07", [*queued.hashes, *executed.hashes], {"amount": format_tokens(int(executed.values["amount"]))}
        )

    def _phase_e08(self) -> None:
        queued = self._step("E08/queue", lambda: self._queued("E08", "A", self.plan.rows.E08.instruction))
        item_id = int(queued.values["item_id"])

        def cancel() -> StepRecord:
            receipt = owner_actions.cancel(self.client, self.roles.owners["A"], self.wallet("A"), item_id)
            tx_hash = _hash_of(receipt)
            if not [e for e in self._events(tx_hash, "A", "ItemCancelled") if int(e["args"]["itemId"]) == item_id]:
                raise RowFailed("E08", "the cancellation emitted no ItemCancelled event")
            return StepRecord(hashes=(tx_hash,), values={})

        cancelled = self._step("E08/cancel", cancel)
        amount = self._item_amount("E08", "A", item_id)
        self.progress.complete_row("E08", [*queued.hashes, *cancelled.hashes], {"amount": format_tokens(amount)})

    def _item_amount(self, row: str, label: str, item_id: int) -> int:
        """The amount of pending item ``item_id``, read from the wallet."""
        item = self.client.wallet(self.wallet(label)).functions.getItem(item_id).call()
        request = item[1]
        amount = int(request[6])
        if amount <= 0:
            raise RowFailed(row, f"item {item_id} holds no amount")
        return amount

    def _phase_e09(self) -> None:
        plan = self.plan.rows.E09

        def propose() -> StepRecord:
            reply = self.ask("E09", "A", plan.instruction, [plan.document])
            tx_hash = self._expect("E09", reply, ReplyKind.PROPOSED, Tier.L3)
            if reply.item_id is None or reply.flags is None or not reply.flags & PRESSURE_FLAGS:
                raise RowFailed("E09", "the L3 proposal carries no pressure flag")
            return StepRecord(hashes=(tx_hash,), values={"item_id": reply.item_id, "flags": reply.flags})

        proposed = self._step("E09/propose", propose)
        item_id = int(proposed.values["item_id"])

        def approve() -> StepRecord:
            receipt = owner_actions.approve(self.client, self.roles.owners["A"], self.wallet("A"), item_id)
            tx_hash = _hash_of(receipt)
            approved = [e for e in self._events(tx_hash, "A", "Approved") if int(e["args"]["itemId"]) == item_id]
            if len(approved) != 1:
                raise RowFailed("E09", "the approval emitted no Approved event")
            ready_at = int(approved[0]["args"]["readyAt"])
            hold = self.client.wallet_view(self.wallet("A")).mandate.pressure_hold
            if ready_at < self._block_time(tx_hash) + hold:
                raise RowFailed("E09", "the approved item is not held for the pressure hold")
            return StepRecord(hashes=(tx_hash,), values={"ready_at": ready_at})

        approved = self._step("E09/approve", approve)
        if not self.progress.done("E09/execute"):
            self._wait_for_item("E09", "A", item_id, "the pressure hold")

        def execute() -> StepRecord:
            receipt = agent_actions.execute_pending(self.client, self.roles.agents["A"], self.wallet("A"), item_id)
            tx_hash = _hash_of(receipt)
            if self._block_time(tx_hash) < int(approved.values["ready_at"]):
                raise RowFailed("E09", "the item executed before the pressure hold ended")
            amount = self._executed("E09", "A", tx_hash, Task.PAYMENT, item_id)
            return StepRecord(hashes=(tx_hash,), values={"amount": amount})

        executed = self._step("E09/execute", execute)
        self.progress.complete_row(
            "E09",
            [*proposed.hashes, *approved.hashes, *executed.hashes],
            {"amount": format_tokens(int(executed.values["amount"]))},
        )

    def _phase_e05(self) -> None:
        vault = self.client.contract("src/SavingsVault.sol:SavingsVault", self.deployment.savings_vault.address)

        def sweep() -> StepRecord:
            before = int(vault.functions.balanceOf(self.wallet("A")).call())
            reply = self.ask("E05", "A", self.plan.rows.E05.instruction)
            tx_hash = self._expect("E05", reply, ReplyKind.EXECUTED, Tier.L1)
            amount = self._executed("E05", "A", tx_hash, Task.SWEEP)
            receipt_block = int(self._receipt(tx_hash)["blockNumber"])
            after = int(vault.functions.balanceOf(self.wallet("A")).call(block_identifier=receipt_block))
            if amount <= 0 or after - before != amount:
                raise RowFailed("E05", "the vault did not receive the swept amount")
            return StepRecord(hashes=(tx_hash,), values={"amount": amount})

        record = self._step("E05/sweep", sweep)
        self.progress.complete_row("E05", list(record.hashes), {"amount": format_tokens(int(record.values["amount"]))})

    # ------------------------------------------------------------------------------------ wallet C, the worked example

    def _phase_e10(self) -> None:
        plan = self.plan.rows.E10
        wallet = self.wallet("C")
        due_base = self.client.latest_timestamp()
        hashes: list[str] = []
        for index, obligation in enumerate(plan.obligations):
            record = self._tx_step(
                f"E10/obligation/{index}",
                lambda obligation=obligation: agent_actions.add_obligation(
                    self.client,
                    self.roles.owners["C"],
                    wallet,
                    self._payee_id("C", obligation.payee),
                    tokens(obligation.amount),
                    due_base + obligation.due_in_seconds,
                ),
            )
            hashes += record.hashes

        def request() -> StepRecord:
            view = self.client.wallet_view(wallet)
            open_amounts = sorted(o.amount for o in view.obligations)
            expected = sorted(tokens(o.amount) for o in plan.obligations)
            state = (
                f"balance {format_tokens(view.token_balance)}, reserve {format_tokens(view.mandate.reserve)}, "
                f"obligations {[format_tokens(a) for a in open_amounts]}, D {format_tokens(view.discretionary)}"
            )
            if (
                view.token_balance != tokens(plan.balance)
                or view.mandate.reserve != self.profile.mandate.reserve
                or open_amounts != expected
                or view.discretionary != tokens(plan.discretionary)
            ):
                raise RowFailed("E10", f"wallet C is not in the worked example state: {state}")
            self.report(f"E10: wallet C holds the worked example state: {state}")
            reply = self.ask("E10", "C", plan.instruction)
            tx_hash = self._expect("E10", reply, ReplyKind.QUEUED, Tier.L2)
            if reply.deciding_check is not DecidingCheck.AFFORDABLE:
                raise RowFailed("E10", "the request was not decided by the affordability check")
            item_id = reply.item_id or 0
            return StepRecord(
                hashes=(tx_hash,),
                values={
                    "balance": view.token_balance,
                    "reserve": view.mandate.reserve,
                    "discretionary": view.discretionary,
                    "amount": self._item_amount("E10", "C", item_id),
                },
            )

        queued = self._step("E10/request", request)
        self.progress.complete_row(
            "E10",
            [*hashes, *queued.hashes],
            {
                "balance": format_tokens(int(queued.values["balance"])),
                "reserve": format_tokens(int(queued.values["reserve"])),
                "obligations": _spoken_list([o.amount for o in plan.obligations]),
                "discretionary": format_tokens(int(queued.values["discretionary"])),
                "amount": format_tokens(int(queued.values["amount"])),
            },
        )

    # ------------------------------------------------------------------------------------ capsules

    def _phase_e11(self) -> None:
        plan = self.plan.rows.E11

        def attack() -> StepRecord:
            reply = self.ask("E11", "A", plan.attack_instruction, [plan.attack_document])
            if not _held(reply):
                raise RowFailed("E11", f"the attack on wallet A ended {reply.kind.value}, not held for the owner")
            if reply.flags is None or not reply.flags & PRESSURE_FLAGS:
                raise RowFailed("E11", "the attack on wallet A carries no pressure flag")
            return StepRecord(hashes=(reply.tx_hash,), values={"item_id": reply.item_id, "flags": reply.flags})

        attacked = self._step("E11/attack", attack)
        cancel_a = self._tx_step(
            "E11/attack_cancel",
            lambda: owner_actions.cancel(
                self.client, self.roles.owners["A"], self.wallet("A"), int(attacked.values["item_id"])
            ),
        )

        # Each owner transaction is its own step, so a resumed run never sends a mined one again.
        attack_seen = capsules.ConfirmedAttack(
            flags=int(attacked.values["flags"]), channel=Channel.MESSAGE, task=Task.PAYMENT
        )
        draft = capsules.draft_for(attack_seen, load_model(self._model_path).version)
        if draft is None:
            raise RowFailed("E11", "the confirmed attack has no feature a capsule can match on")

        def confirm() -> StepRecord:
            confirmation = capsules.send_attack_confirmation(self.client, self.roles.owners["A"], self.wallet("A"))
            return StepRecord(hashes=(confirmation.tx_hash,), values={"confirmed_at": confirmation.confirmed_at})

        confirmed = self._step("E11/confirm", confirm)

        def publish() -> StepRecord:
            published = capsules.publish_draft(self.client, self.roles.owners["A"], self.wallet("A"), draft)
            return StepRecord(hashes=(published.tx_hash,), values={"capsule_id": published.capsule_id})

        published = self._step("E11/publish", publish)
        capsule_id = int(published.values["capsule_id"])
        memory = self.memory("A")
        if all(threat.capsule_id != capsule_id for threat in memory.threats()):
            capsules.remember_attack(memory, attack_seen, draft, capsule_id, int(confirmed.values["confirmed_at"]))

        def replay() -> StepRecord:
            reply = self.ask("E11", "B", plan.replay_instruction, [plan.replay_document])
            if not _held(reply):
                raise RowFailed("E11", f"the replay on wallet B ended {reply.kind.value}, not restricted")
            decisions = [
                d
                for d in self.client.decisions(self._receipt(reply.tx_hash), self.wallet("B"))
                if d.intent_hash == reply.intent_hash
            ]
            if len(decisions) != 1 or decisions[0].capsule_id != capsule_id or decisions[0].tier is Tier.L1:
                raise RowFailed("E11", f"the replay on wallet B was not restricted by capsule {capsule_id}")
            return StepRecord(
                hashes=(reply.tx_hash,), values={"item_id": reply.item_id, "tier": int(decisions[0].tier)}
            )

        replayed = self._step("E11/replay", replay)
        cancel_b = self._tx_step(
            "E11/replay_cancel",
            lambda: owner_actions.cancel(
                self.client, self.roles.owners["B"], self.wallet("B"), int(replayed.values["item_id"])
            ),
        )
        self.progress.complete_row(
            "E11",
            [
                *attacked.hashes,
                *cancel_a.hashes,
                *confirmed.hashes,
                *published.hashes,
                *replayed.hashes,
                *cancel_b.hashes,
            ],
            {"capsule_id": str(capsule_id), "tier": str(replayed.values["tier"])},
        )

    def _capsule_id(self) -> int:
        return int(self.progress.record("E11/publish").values["capsule_id"])

    def _phase_e12(self) -> None:
        capsule_id = self._capsule_id()
        bulletin = self.client.bulletin(self.deployment.threat_bulletin.address)

        def attest() -> StepRecord:
            receipt = owner_actions.attest_capsule(self.client, self.roles.owners["C"], self.wallet("C"), capsule_id)
            tx_hash = _hash_of(receipt)
            capsule = bulletin.functions.getCapsule(capsule_id).call(block_identifier=int(receipt["blockNumber"]))
            if int(capsule[-1]) < 2:
                raise RowFailed("E12", f"capsule {capsule_id} has fewer than two attestations after the attestation")
            return StepRecord(hashes=(tx_hash,), values={})

        record = self._step("E12/attest", attest)
        self.progress.complete_row("E12", list(record.hashes), {"capsule_id": str(capsule_id)})

    # ------------------------------------------------------------------------------------ the panicked owner

    def _phase_e13(self) -> None:
        plan = self.plan.rows.E13
        wallet = self.wallet("B")

        def request() -> StepRecord:
            account = to_checksum_address("0x" + os.urandom(20).hex())
            reply = self.ask("E13", "B", plan.instruction, [plan.document.format(account=account)])
            tx_hash = self._expect("E13", reply, ReplyKind.PAYEE_CHANGE_REQUESTED)
            requested = self._events(tx_hash, "B", "PayeeChangeRequested")
            if len(requested) != 1 or to_checksum_address(requested[0]["args"]["account"]) != account:
                raise RowFailed("E13", "the agent did not record the request for the new address")
            return StepRecord(hashes=(tx_hash,), values={"account": account})

        requested = self._step("E13/request", request)
        account = str(requested.values["account"])

        def propose() -> StepRecord:
            change = owner_actions.propose_add_payee(
                self.client, self.roles.owners["B"], wallet, identity_hash(plan.payee), account
            )
            return StepRecord(
                hashes=(change.tx_hash,), values={"change_id": change.change_id, "ready_at": change.ready_at}
            )

        proposed = self._step("E13/propose", propose)
        ready_at = int(proposed.values["ready_at"])

        def cancel() -> StepRecord:
            if self.client.latest_timestamp() >= ready_at:
                raise RowFailed("E13", "the loosening delay ended before the owner could cancel")
            change_id = int(proposed.values["change_id"])
            receipt = owner_actions.cancel_change(self.client, self.roles.owners["B"], wallet, change_id)
            tx_hash = _hash_of(receipt)
            if self._block_time(tx_hash) >= ready_at or not self._events(tx_hash, "B", "ChangeCancelled"):
                raise RowFailed("E13", "the proposal was not cancelled before the loosening delay ended")
            accounts = {p.account for p in self.client.wallet_view(wallet).payees}
            if account in accounts:
                raise RowFailed("E13", "the new address became a payee")
            return StepRecord(hashes=(tx_hash,), values={})

        cancelled = self._step("E13/cancel", cancel)
        self.progress.complete_row("E13", [*requested.hashes, *proposed.hashes, *cancelled.hashes], {})

    # ------------------------------------------------------------------------------------ summaries

    def setup_hashes(self) -> dict[str, list[str]]:
        """Hashes of the setup steps, grouped by kind for the evidence document."""
        groups: dict[str, list[str]] = {}
        for key, record in self.progress.state.steps.items():
            parts = key.split("/")
            if parts[0] != "setup" or not record.hashes:
                continue
            groups.setdefault(parts[1], []).extend(record.hashes)
        return groups
