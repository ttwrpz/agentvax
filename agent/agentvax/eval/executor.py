"""The evaluation executor: the only part of the harness that holds keys.

It holds the deployer, aggregator, keeper, owner and agent keys, builds each case's starting state with real
transactions, builds a fresh agent, and performs owner and keeper actions. Guardian keys stay in their processes.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from eth_account.signers.local import LocalAccount
from eth_utils import to_checksum_address

from agentvax.capsules import ConfirmedAttack, confirm_attack
from agentvax.chain import agent as agent_actions
from agentvax.chain import owner as owner_actions
from agentvax.chain.agent import Outcome
from agentvax.chain.client import ChainClient, TransactionFailed, TransactionReverted
from agentvax.chain.deploy import Deployment
from agentvax.config import Profile
from agentvax.detector.model import DetectorModel
from agentvax.eval.environment import AnvilChain, RunnerConfig
from agentvax.eval.suites_schema import (
    NATIVE_DECIMALS,
    TOKEN_DECIMALS,
    CapsuleSpec,
    MandateOverrides,
    WalletSetup,
    to_units,
)
from agentvax.fed.anchor import AnchorRecord, anchor_model
from agentvax.guardian.client import GuardianClient
from agentvax.llm.base import LanguageModel
from agentvax.memory import MemoryStore
from agentvax.names import identity_hash
from agentvax.planner import OwnerInstruction
from agentvax.reader import UntrustedContent
from agentvax.runtime import Agent, AgentReply
from agentvax.text import Strings
from agentvax.types import (
    ZERO_BYTES32,
    Capsule,
    CapsuleAction,
    Channel,
    DecisionEvent,
    Family,
    Flag,
    Intent,
    Mandate,
    Strict,
    Task,
)
from agentvax.vaxlab.inputs import payee_account

DAY = 86_400
_FLAG_BITS = {name.lower(): int(member) for name, member in Flag.__members__.items() if member}


class HarnessError(RuntimeError):
    """The harness could not perform a step as the case describes it. Fails the run."""


@dataclass(frozen=True)
class Signers:
    """Every key the harness holds. Guardian keys are not here: each lives in its guardian process."""

    deployer: LocalAccount
    """Deploys, registers wallets in the bulletin and mints MockUSD."""
    aggregator: LocalAccount
    """Anchors the detector model."""
    keeper: LocalAccount
    """Holds no role. Executes pending items and runs schedules, which anyone may do."""
    owners: Mapping[str, LocalAccount]
    agents: Mapping[str, LocalAccount]

    def roles(self) -> dict[str, str]:
        roles = {
            self.deployer.address: "deployer",
            self.aggregator.address: "aggregator",
            self.keeper.address: "keeper",
        }
        roles.update({a.address: f"owner:{label}" for label, a in self.owners.items()})
        roles.update({a.address: f"agent:{label}" for label, a in self.agents.items()})
        return roles


class WalletContext(Strict):
    """A wallet after its setup for one case."""

    label: str
    address: str
    payee_ids: dict[str, int]
    """Case-folded payee name to on-chain payee id."""
    payee_names: dict[int, str]
    """Payee id to the name the owner gave it, as the agent is told."""
    accounts: dict[str, str]
    """Case-folded payee name to its account."""

    def payee_id(self, name: str) -> int:
        try:
            return self.payee_ids[name.casefold()]
        except KeyError:
            raise HarnessError(f"wallet {self.label} has no payee named {name!r}") from None

    def account(self, name: str) -> str:
        try:
            return self.accounts[name.casefold()]
        except KeyError:
            raise HarnessError(f"wallet {self.label} has no payee named {name!r}") from None


class InstructResult(Strict):
    """What an instruction produced, read from the reply and its receipt."""

    reply: AgentReply
    decision: DecisionEvent | None
    task: int | None
    schedule_id: int | None
    payee_change: tuple[str, str] | None
    """``(identity hash, account)`` of a recorded payee change request."""
    payee_change_flags: int | None
    """The flags recorded with the payee change request."""
    block_number: int | None
    """Block of the reply's transaction, if one was sent."""


class OwnerResult(Strict):
    outcome: str
    """``ok`` or ``reverted``."""
    revert_error: str | None = None
    tx_hashes: tuple[str, ...] = ()
    capsule_id: int | None = None
    effective_restriction: int | None = None
    change_id: int | None = None


def anchor_detector(client: ChainClient, signers: Signers, bulletin: str, model: DetectorModel) -> AnchorRecord:
    """Anchors the federated detector model's version and hash in the bulletin with the aggregator key, through the
    federation's one anchoring path."""
    return anchor_model(client, signers.aggregator, bulletin, model)


def _hash(receipt: Any) -> str:
    return "0x" + bytes(receipt["transactionHash"]).hex()


def mandate_for(template_mandate: Mandate, overrides: MandateOverrides) -> Mandate:
    """The profile's mandate with the case's overrides applied, apart from ``expiry_after``, which needs the time
    the mandate is set and is applied by ``Executor.set_up``."""
    fields = template_mandate.model_dump()
    token_fields = ("reserve", "c1", "d1", "c2")
    native_fields = ("fee_top_up_cap", "fee_daily_budget", "agent_balance_floor", "native_reserve")
    plain_fields = (
        "delay",
        "loosening_delay",
        "pressure_hold",
        "refill_period",
        "horizon",
        "allowance_max",
        "charge_external",
        "charge_over_half_d",
        "charge_anomaly",
        "charge_first_payment",
        "charge_partial_capsule",
    )
    for name in token_fields:
        value = getattr(overrides, name)
        if value is not None:
            fields[name] = to_units(value, TOKEN_DECIMALS)
    for name in native_fields:
        value = getattr(overrides, name)
        if value is not None:
            fields[name] = to_units(value, NATIVE_DECIMALS)
    for name in plain_fields:
        value = getattr(overrides, name)
        if value is not None:
            fields[name] = value
    if overrides.channels is not None:
        fields["channel_profile"] = sum(1 << int(Channel[c.upper()]) for c in overrides.channels)
    return Mandate(**fields)


class Executor:
    """Performs every transaction of the harness."""

    def __init__(
        self,
        *,
        chain: AnvilChain,
        client: ChainClient,
        deployment: Deployment,
        profile: Profile,
        config: RunnerConfig,
        strings: Strings,
        llm: LanguageModel,
        guardians: Mapping[str, GuardianClient],
        signers: Signers,
        guard_version: int,
    ) -> None:
        self.chain = chain
        self.client = client
        self.deployment = deployment
        self.profile = profile
        self.config = config
        self.strings = strings
        self.llm = llm
        self.guardians = dict(guardians)
        self.signers = signers
        self.guard_version = guard_version
        self._token = client.token(deployment.mock_usd.address)
        self._bulletin = client.bulletin(deployment.threat_bulletin.address)

    # ------------------------------------------------------------------------------------ basics

    def wallet_address(self, label: str) -> str:
        return self.deployment.wallet(label).address

    def now(self) -> int:
        return self.client.latest_timestamp()

    def advance(self, seconds: int) -> None:
        self.chain.advance(max(0, seconds))

    def mandate(self, label: str) -> Mandate:
        values = self.client.wallet(self.wallet_address(label)).functions.mandate().call()
        return Mandate(**{name: int(v) for name, v in zip(Mandate.model_fields, values, strict=True)})

    def mint(self, label: str, amount: int) -> None:
        if amount:
            self.client.send(self.signers.deployer, self._token.functions.mint(self.wallet_address(label), amount))

    # ------------------------------------------------------------------------------------ setup

    def set_up(self, label: str, setup: WalletSetup) -> WalletContext:
        """Brings wallet ``label`` from its freshly deployed state to the state ``setup`` describes."""
        wallet = self.wallet_address(label)
        owner = self.signers.owners[label]
        now = self.now()
        target = mandate_for(self.profile.mandate.mandate(now), setup.mandate)
        if setup.mandate.expiry_after is not None:
            target = target.model_copy(update={"expiry": now + setup.mandate.expiry_after})
        history = [p for p in setup.payees if p.paid_before]
        first = target.model_copy(update={"reserve": 0}) if history else target
        owner_actions.set_mandate(self.client, owner, wallet, self.config.mission, first)
        wallet_native = to_units(setup.wallet_native or self.config.wallet_native, NATIVE_DECIMALS)
        self.chain.set_balance(wallet, wallet_native)

        accounts = {p.name.casefold(): payee_account(p.name, p.account) for p in setup.payees}
        proposals = [
            owner_actions.propose_add_payee(
                self.client, owner, wallet, identity_hash(p.name), accounts[p.name.casefold()]
            )
            for p in setup.payees
        ]
        payee_ids: dict[str, int] = {}
        if proposals:
            self.advance(max(c.ready_at for c in proposals) - self.now() + self.config.time_margin_seconds)
            contract = self.client.wallet(wallet)
            for payee, change in zip(setup.payees, proposals, strict=True):
                receipt = owner_actions.apply_change(self.client, owner, wallet, change.change_id)
                added = self.client.events(receipt, contract, "PayeeAdded")
                if len(added) != 1:
                    raise HarnessError(f"adding payee {payee.name!r} did not emit one PayeeAdded")
                payee_ids[payee.name.casefold()] = int(added[0]["args"]["payeeId"])

        if history:
            amounts = [to_units(p.max_paid or "0", TOKEN_DECIMALS) for p in history]
            self.mint(label, sum(amounts))
            for payee, amount in zip(history, amounts, strict=True):
                self._pay_directly(label, payee_ids[payee.name.casefold()], amount)
            owner_actions.set_mandate(self.client, owner, wallet, self.config.mission, target)
        for payee in setup.payees:
            if not payee.active:
                owner_actions.remove_payee(self.client, owner, wallet, payee_ids[payee.name.casefold()])

        self.advance(max(target.refill_period, DAY) + self.config.time_margin_seconds)
        self.mint(label, to_units(setup.balance, TOKEN_DECIMALS))
        agent_native = to_units(setup.agent_native or self.config.agent_native, NATIVE_DECIMALS)
        self.chain.set_balance(self.signers.agents[label].address, agent_native)

        if setup.allowance_points is not None and setup.allowance_points < target.allowance_max:
            owner_actions.confirm_attack(self.client, owner, wallet)
            self.advance(setup.allowance_points * target.refill_period // target.allowance_max)

        start = self.now()
        for obligation in setup.obligations:
            signer = owner if obligation.added_by == "owner" else self.signers.agents[label]
            agent_actions.add_obligation(
                self.client,
                signer,
                wallet,
                payee_ids[obligation.payee.casefold()],
                to_units(obligation.amount, TOKEN_DECIMALS),
                start + obligation.due_in,
            )
        if setup.frozen:
            owner_actions.freeze(self.client, owner, wallet)
        names = {payee_ids[p.name.casefold()]: p.name for p in setup.payees}
        return WalletContext(label=label, address=wallet, payee_ids=payee_ids, payee_names=names, accounts=accounts)

    def _pay_directly(self, label: str, payee_id: int, amount: int) -> None:
        """An earlier payment for the setup: an owner-instructed intent with no untrusted content, attested by the
        real guardian and decided by the wallet. A queued or proposed payment is carried through to execution."""
        wallet = self.wallet_address(label)
        view = self.client.wallet_view(wallet)
        intent = Intent(
            task=Task.PAYMENT, payee_id=payee_id, amount=amount, schedule_id=0, purpose_hash=ZERO_BYTES32,
            nonce=view.nonce,
        )
        signed = self.guardians[label].attest(intent, [], Flag.KNOWN_PAYEE_IDENTITY)
        submission = agent_actions.submit(
            self.client, self.signers.agents[label], wallet, intent, signed.attestation, signed.signature
        )
        if submission.outcome is Outcome.EXECUTED:
            return
        if submission.outcome is Outcome.PROPOSED:
            owner_actions.approve(self.client, self.signers.owners[label], wallet, submission.item_id)
        ready = int(self.client.wallet(wallet).functions.itemReadyAt(submission.item_id).call())
        self.advance(ready - self.now() + self.config.time_margin_seconds)
        agent_actions.execute_pending(self.client, self.signers.keeper, wallet, submission.item_id)

    # ------------------------------------------------------------------------------------ the agent

    def new_agent(self, context: WalletContext) -> tuple[Agent, MemoryStore]:
        """A fresh agent with fresh memory for ``context``'s wallet. The caller closes the memory."""
        memory = MemoryStore(":memory:")
        agent = Agent(
            llm=self.llm,
            chain=self.client,
            wallet=context.address,
            agent_signer=self.signers.agents[context.label],
            guardian=self.guardians[context.label],
            memory=memory,
            strings=self.strings,
            payee_names=context.payee_names,
        )
        return agent, memory

    def instruct(self, context: WalletContext, agent: Agent, instruction: str, documents: Sequence[UntrustedContent]) -> InstructResult:
        reply = agent.handle(OwnerInstruction(text=instruction), documents)
        decision = None
        task: int | None = None
        schedule_id: int | None = None
        payee_change = None
        payee_change_flags: int | None = None
        block_number: int | None = None
        if reply.tx_hash is not None:
            receipt = self.client.web3.eth.get_transaction_receipt(reply.tx_hash)
            block_number = int(receipt["blockNumber"])
            contract = self.client.wallet(context.address)
            if reply.intent_hash is not None:
                found = [d for d in self.client.decisions(receipt, context.address) if d.intent_hash == reply.intent_hash]
                if len(found) != 1:
                    raise HarnessError("a submission did not emit exactly one Decision for its intent")
                decision = found[0]
            executed = self.client.events(receipt, contract, "Executed")
            if executed:
                task = int(executed[0]["args"]["task"])
            created = self.client.events(receipt, contract, "ScheduleCreated")
            if created:
                schedule_id = int(created[0]["args"]["scheduleId"])
            requested = self.client.events(receipt, contract, "PayeeChangeRequested")
            if requested:
                args = requested[0]["args"]
                payee_change = ("0x" + bytes(args["identityHash"]).hex(), to_checksum_address(args["account"]))
                payee_change_flags = int(args["flags"])
        if reply.item_id is not None:
            item = self.client.wallet(context.address).functions.getItem(reply.item_id).call()
            task = int(item[1][0])
        return InstructResult(
            reply=reply,
            decision=decision,
            task=task,
            schedule_id=schedule_id,
            payee_change=payee_change,
            payee_change_flags=payee_change_flags,
            block_number=block_number,
        )

    # ------------------------------------------------------------------------------------ capsules

    def capsule(self, capsule_id: int) -> Capsule:
        family, channel, features, action, restriction, expiry, version, issuer, attestations = (
            self._bulletin.functions.getCapsule(capsule_id).call()
        )
        return Capsule(
            family=Family(int(family)),
            channel=Channel(int(channel)),
            features=int(features),
            action=CapsuleAction(int(action)),
            restriction=int(restriction),
            expiry=int(expiry),
            guard_version=int(version),
            issuer=to_checksum_address(issuer),
            attestations=int(attestations),
        )

    def sync_capsules(self, label: str) -> None:
        """The keeper brings the wallet's view of the bulletin up to date, as any wallet transaction would. Anyone
        may call ``syncCapsules``, and it only adds caution."""
        wallet = self.client.wallet(self.wallet_address(label))
        chunk = int(wallet.functions.AUTO_SYNC_CHUNK().call())
        while int(wallet.functions.capsuleBacklog().call()) > 0:
            agent_actions.sync_capsules(self.client, self.signers.keeper, self.wallet_address(label), chunk)

    def full_matches(self, label: str, action: CapsuleAction, flags: int, block_number: int) -> tuple[int, ...]:
        """The capsules the wallet's ``matchCapsules`` view reports as full matches for ``action`` and ``flags`` at
        ``block_number``."""
        wallet = self.client.wallet(self.wallet_address(label))
        full, _partial, _restriction, _fail_closed = wallet.functions.matchCapsules(int(action), flags).call(
            block_identifier=block_number
        )
        return tuple(int(i) for i in full)

    def effective_restriction(self, capsule_id: int) -> int:
        return int(self._bulletin.functions.effectiveRestriction(capsule_id).call())

    def dismissed(self, label: str, capsule_id: int) -> bool:
        return bool(self.client.wallet(self.wallet_address(label)).functions.capsuleDismissed(capsule_id).call())

    # ------------------------------------------------------------------------------------ owner and keeper

    def _attempt(self, send) -> OwnerResult:  # type: ignore[no-untyped-def]
        """Runs one owner or keeper call. A refusal by the contract is an outcome. A mined failure is a harness
        error, because the client only sends calls that estimated successfully."""
        try:
            receipt = send()
        except TransactionReverted as reverted:
            return OwnerResult(outcome="reverted", revert_error=reverted.error_name)
        except TransactionFailed as failed:
            raise HarnessError(f"a transaction failed after it was sent: {failed}") from failed
        return OwnerResult(outcome="ok", tx_hashes=(_hash(receipt),))

    def approve(self, label: str, item_id: int) -> OwnerResult:
        return self._attempt(
            lambda: owner_actions.approve(self.client, self.signers.owners[label], self.wallet_address(label), item_id)
        )

    def cancel(self, label: str, item_id: int) -> OwnerResult:
        return self._attempt(
            lambda: owner_actions.cancel(self.client, self.signers.owners[label], self.wallet_address(label), item_id)
        )

    def extend_hold(self, label: str, item_id: int, seconds: int) -> OwnerResult:
        return self._attempt(
            lambda: owner_actions.extend_hold(
                self.client, self.signers.owners[label], self.wallet_address(label), item_id, seconds
            )
        )

    def execute_pending(self, label: str, item_id: int) -> OwnerResult:
        return self._attempt(
            lambda: agent_actions.execute_pending(self.client, self.signers.keeper, self.wallet_address(label), item_id)
        )

    def run_schedule(self, label: str, schedule_id: int) -> OwnerResult:
        return self._attempt(
            lambda: agent_actions.run_schedule(self.client, self.signers.keeper, self.wallet_address(label), schedule_id)
        )

    def propose_add_payee(self, label: str, identity: str, account: str) -> OwnerResult:
        owner = self.signers.owners[label]
        wallet = self.wallet_address(label)
        try:
            proposed = owner_actions.propose_add_payee(self.client, owner, wallet, identity, account)
        except TransactionReverted as reverted:
            return OwnerResult(outcome="reverted", revert_error=reverted.error_name)
        except TransactionFailed as failed:
            raise HarnessError(f"a transaction failed after it was sent: {failed}") from failed
        return OwnerResult(outcome="ok", tx_hashes=(proposed.tx_hash,), change_id=proposed.change_id)

    def propose_unfreeze(self, label: str) -> OwnerResult:
        owner = self.signers.owners[label]
        wallet = self.wallet_address(label)
        try:
            proposed = owner_actions.propose_unfreeze(self.client, owner, wallet)
        except TransactionReverted as reverted:
            return OwnerResult(outcome="reverted", revert_error=reverted.error_name)
        except TransactionFailed as failed:
            raise HarnessError(f"a transaction failed after it was sent: {failed}") from failed
        return OwnerResult(outcome="ok", tx_hashes=(proposed.tx_hash,), change_id=proposed.change_id)

    def apply_change(self, label: str, change_id: int) -> OwnerResult:
        return self._attempt(
            lambda: owner_actions.apply_change(
                self.client, self.signers.owners[label], self.wallet_address(label), change_id
            )
        )

    def cancel_change(self, label: str, change_id: int) -> OwnerResult:
        return self._attempt(
            lambda: owner_actions.cancel_change(
                self.client, self.signers.owners[label], self.wallet_address(label), change_id
            )
        )

    def freeze(self, label: str) -> OwnerResult:
        return self._attempt(
            lambda: owner_actions.freeze(self.client, self.signers.owners[label], self.wallet_address(label))
        )

    def remove_payee(self, label: str, payee_id: int) -> OwnerResult:
        return self._attempt(
            lambda: owner_actions.remove_payee(
                self.client, self.signers.owners[label], self.wallet_address(label), payee_id
            )
        )

    def confirm_attack(
        self, label: str, memory: MemoryStore, flags: int, channel: Channel, task: Task, publish: bool
    ) -> OwnerResult:
        """The owner confirms an attack with ``capsules.confirm_attack``: the allowance goes to zero and, if
        ``publish``, the capsule drafted by rule is published."""
        try:
            confirmed = confirm_attack(
                self.client,
                self.signers.owners[label],
                self.wallet_address(label),
                memory,
                ConfirmedAttack(flags=flags, channel=channel, task=task),
                self.guard_version,
                publish,
            )
        except TransactionReverted as reverted:
            return OwnerResult(outcome="reverted", revert_error=reverted.error_name)
        except TransactionFailed as failed:
            raise HarnessError(f"a transaction failed after it was sent: {failed}") from failed
        hashes = tuple(h for h in (confirmed.confirm_tx_hash, confirmed.publish_tx_hash) if h is not None)
        capsule_id = confirmed.capsule_id
        restriction = self.effective_restriction(capsule_id) if capsule_id else None
        return OwnerResult(outcome="ok", tx_hashes=hashes, capsule_id=capsule_id, effective_restriction=restriction)

    def publish_capsule(self, label: str, spec: CapsuleSpec) -> OwnerResult:
        features = 0
        for name in spec.features:
            features |= _FLAG_BITS[name]
        fields = owner_actions.CapsuleFields(
            family=Family[spec.family.upper()],
            channel=Channel[spec.channel.upper()],
            features=features,
            action=CapsuleAction[spec.action.upper()],
            restriction=spec.restriction,
            lifetime=spec.lifetime,
            guard_version=self.guard_version,
        )
        try:
            published = owner_actions.publish_capsule(
                self.client, self.signers.owners[label], self.wallet_address(label), fields
            )
        except TransactionReverted as reverted:
            return OwnerResult(outcome="reverted", revert_error=reverted.error_name)
        except TransactionFailed as failed:
            raise HarnessError(f"a transaction failed after it was sent: {failed}") from failed
        return OwnerResult(
            outcome="ok",
            tx_hashes=(published.tx_hash,),
            capsule_id=published.capsule_id,
            effective_restriction=self.effective_restriction(published.capsule_id),
        )

    def attest_capsule(self, label: str, capsule_id: int) -> OwnerResult:
        result = self._attempt(
            lambda: owner_actions.attest_capsule(
                self.client, self.signers.owners[label], self.wallet_address(label), capsule_id
            )
        )
        return result.model_copy(update={"capsule_id": capsule_id})

    def dismiss_capsule(self, label: str, capsule_id: int) -> OwnerResult:
        result = self._attempt(
            lambda: owner_actions.dismiss_capsule(
                self.client, self.signers.owners[label], self.wallet_address(label), capsule_id
            )
        )
        return result.model_copy(update={"capsule_id": capsule_id})
