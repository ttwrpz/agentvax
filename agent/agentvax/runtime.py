"""The composition root of the agent.

``Agent.handle`` takes one owner instruction and the untrusted documents the owner referenced, and runs:

1. a snapshot of the wallet, read from the chain;
2. the quarantined reader on each document, which returns typed fields only;
3. the planner on the owner's instruction, the wallet numbers, structured memory and the readings;
4. a question, if the planner asks one, rendered from ``strings.json``;
5. the deterministic validator, with ``pressure.scan`` of the raw documents added to its flags;
6. the payee change path, if a document asks to pay an address that is not the payee's account on chain: no intent
   is made, the request is recorded on chain without authority, and the owner is told that adding the address is
   a time-locked owner change;
7. the guardian attestation, in the separate guardian process, which sees the raw documents;
8. submission with the agent session key, and the wallet's ``Decision`` decoded from the receipt;
9. the explanation, built from the decision and a wallet view read at the block of the receipt;
10. memory, updated with deterministic facts about settled payments only.

Every sentence in an ``AgentReply`` comes from ``strings.json``. No model text is shown. The runtime holds the agent
session key only: it has no owner key and no guardian key, and nothing here can add a payee, change the mandate
or approve an item.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from enum import StrEnum

from eth_utils import to_checksum_address

from agentvax import pressure
from agentvax.chain.agent import Outcome, Submission, record_payee_change_request, submit, submit_schedule
from agentvax.chain.client import ChainClient, Signer, TransactionFailed, TransactionReverted
from agentvax.explain import explanation
from agentvax.guardian.client import AttestationInvalid, GuardianClient, GuardianRefused, GuardianUnavailable
from agentvax.guardian.protocol import ContentItem
from agentvax.llm.base import LanguageModel, LLMError
from agentvax.memory import MemoryStore
from agentvax.planner import IntentDraft, OwnerInstruction, Question, build_context, plan, question_text
from agentvax.reader import AllowlistEntry, ReaderOutput, UntrustedContent, read
from agentvax.text import Strings, describe_duration
from agentvax.types import (
    ZERO_BYTES32,
    Bytes32,
    DecidingCheck,
    Flag,
    Strict,
    Task,
    Tier,
    Uint16,
    WalletView,
)
from agentvax.validator import Rejected, Validated, rejection_text, validate_draft

_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")


class ReplyKind(StrEnum):
    EXECUTED = "executed"
    QUEUED = "queued"
    PROPOSED = "proposed"
    QUESTION = "question"
    REJECTED = "rejected"
    PAYEE_CHANGE_REQUESTED = "payee_change_requested"


class AgentReply(Strict):
    """What the agent tells the owner. ``text`` is rendered from the template ``text_key``; no field holds model
    text or untrusted text."""

    kind: ReplyKind
    text_key: str
    text: str
    tier: Tier | None = None
    deciding_check: DecidingCheck | None = None
    intent_hash: Bytes32 | None = None
    tx_hash: Bytes32 | None = None
    item_id: int | None = None
    flags: Uint16 | None = None


_KIND_OF_OUTCOME = {
    Outcome.EXECUTED: ReplyKind.EXECUTED,
    Outcome.QUEUED: ReplyKind.QUEUED,
    Outcome.PROPOSED: ReplyKind.PROPOSED,
}


def _snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


class Agent:
    """One wallet's agent. Built by an entry point from its parts; holds the agent session key only."""

    def __init__(
        self,
        *,
        llm: LanguageModel,
        chain: ChainClient,
        wallet: str,
        agent_signer: Signer,
        guardian: GuardianClient,
        memory: MemoryStore,
        strings: Strings,
        payee_names: Mapping[int, str],
    ) -> None:
        """``payee_names`` maps on-chain payee ids to the names the owner gave them when adding them."""
        if to_checksum_address(guardian.wallet) != to_checksum_address(wallet):
            raise ValueError("the guardian is bound to another wallet")
        if guardian.chain_id != chain.chain_id:
            raise ValueError("the guardian is bound to another chain")
        self._llm = llm
        self._chain = chain
        self._wallet = to_checksum_address(wallet)
        self._signer = agent_signer
        self._guardian = guardian
        self._memory = memory
        self._strings = strings
        self._names = dict(payee_names)

    # ------------------------------------------------------------------------------------ the loop

    def handle(self, instruction: OwnerInstruction, documents: Sequence[UntrustedContent]) -> AgentReply:
        view = self._chain.wallet_view(self._wallet)
        entries = self.allowlist(view)
        try:
            readings = [read(self._llm, document, entries) for document in documents]
            context = build_context(instruction, view, entries, self._memory.payee_facts(), readings)
            decision = plan(self._llm, context)
        except LLMError:
            return self._reply(ReplyKind.REJECTED, "agent.model_failed")

        if isinstance(decision, Question):
            return AgentReply(
                kind=ReplyKind.QUESTION,
                text_key=f"question.{decision.code.name.lower()}",
                text=question_text(self._strings, decision, context),
            )

        result = validate_draft(decision, context, view)
        if isinstance(result, Rejected):
            return AgentReply(
                kind=ReplyKind.REJECTED,
                text_key=f"rejection.{result.code.name.lower()}",
                text=rejection_text(self._strings, result),
            )

        flags = Flag(result.flags)
        for document in documents:
            flags |= pressure.scan(document.text)

        substituted = self._substituted_address(decision, view, readings, documents)
        if substituted is not None:
            return self._request_payee_change(decision, view, substituted, flags)
        return self._submit(decision, result, flags, documents)

    def payee_name(self, payee_id: int) -> str | None:
        """The name the owner gave payee ``payee_id``, or None if the owner has not named it."""
        return self._names.get(payee_id)

    def name_payee(self, payee_id: int, name: str) -> None:
        """Records the name the owner gave a payee they have just added. A name only lets the reader and the
        validator recognise the payee. It adds no authority: the payee must already be active on chain."""
        self._names[payee_id] = name

    def allowlist(self, view: WalletView) -> tuple[AllowlistEntry, ...]:
        """Active payees that the owner has named, with the account read from the chain."""
        return tuple(
            AllowlistEntry(name=self._names[p.payee_id], payee_id=p.payee_id, account=p.account)
            for p in view.payees
            if p.active and p.payee_id in self._names
        )

    # ------------------------------------------------------------------------------------ steps

    def _substituted_address(
        self,
        draft: IntentDraft,
        view: WalletView,
        readings: Sequence[ReaderOutput],
        documents: Sequence[UntrustedContent],
    ) -> str | None:
        """An address in a document about the draft's payee that is not that payee's account on chain.

        The address is matched by a fixed pattern of 40 hexadecimal digits. It is a typed value, not text, and it
        is only ever recorded as a request without authority.
        """
        if draft.task in (Task.SWEEP, Task.FEE_TOPUP):
            return None
        payee = view.payee(draft.payee_id)
        if payee is None:
            return None
        for reading, document in zip(readings, documents, strict=True):
            if reading.payee_id not in (None, draft.payee_id):
                continue
            for found in _ADDRESS.findall(document.text):
                if found.lower() != payee.account.lower():
                    return to_checksum_address(found)
        return None

    def _request_payee_change(self, draft: IntentDraft, view: WalletView, account: str, flags: Flag) -> AgentReply:
        payee = view.payee(draft.payee_id)
        identity = payee.identity_hash if payee is not None else ZERO_BYTES32
        flags |= Flag.NEW_DESTINATION
        try:
            receipt = record_payee_change_request(
                self._chain, self._signer, self._wallet, identity, account, int(flags)
            )
        except (TransactionReverted, TransactionFailed):
            return self._reply(ReplyKind.REJECTED, "agent.chain_failed")
        return AgentReply(
            kind=ReplyKind.PAYEE_CHANGE_REQUESTED,
            text_key="agent.payee_change_requested",
            text=self._strings.render(
                "agent.payee_change_requested",
                payee=self._names.get(draft.payee_id, ""),
                delay=describe_duration(self._strings, view.mandate.loosening_delay),
            ),
            tx_hash="0x" + bytes(receipt["transactionHash"]).hex(),
            flags=int(flags),
        )

    def _submit(
        self,
        draft: IntentDraft,
        validated: Validated,
        flags: Flag,
        documents: Sequence[UntrustedContent],
    ) -> AgentReply:
        content = [ContentItem(channel=d.channel, text=d.text) for d in documents]
        try:
            signed = self._guardian.attest(validated.intent, content, flags)
        except (GuardianRefused, GuardianUnavailable, AttestationInvalid):
            return self._reply(ReplyKind.REJECTED, "agent.guardian_failed")

        intent = validated.intent
        try:
            if intent.task is Task.SCHEDULE_CREATE and validated.schedule is not None:
                submission = submit_schedule(
                    self._chain,
                    self._signer,
                    self._wallet,
                    intent,
                    validated.schedule,
                    signed.attestation,
                    signed.signature,
                )
            else:
                submission = submit(
                    self._chain, self._signer, self._wallet, intent, signed.attestation, signed.signature
                )
        except TransactionReverted as reverted:
            key = f"revert.{_snake(reverted.error_name)}"
            return self._reply(ReplyKind.REJECTED, key if self._strings.has(key) else "revert.other")
        except TransactionFailed:
            return self._reply(ReplyKind.REJECTED, "agent.chain_failed")

        self._remember(draft, submission)
        explained_view = self._chain.wallet_view(self._wallet, submission.block_number)
        if intent.task is Task.PAYMENT and intent.schedule_id:
            wallet = self._chain.wallet(self._wallet)
            excluded = wallet.functions.discretionary(intent.schedule_id).call(block_identifier=submission.block_number)
            explained_view = explained_view.model_copy(update={"discretionary": int(excluded)})
        decision = submission.decision
        key, params = explanation(self._strings, decision, explained_view, intent.amount)
        return AgentReply(
            kind=_KIND_OF_OUTCOME[submission.outcome],
            text_key=key,
            text=self._strings.render(key, **params),
            tier=decision.tier,
            deciding_check=decision.deciding_check,
            intent_hash=submission.intent_hash,
            tx_hash=submission.tx_hash,
            item_id=submission.item_id or None,
            flags=signed.attestation.flags,
        )

    def _remember(self, draft: IntentDraft, submission: Submission) -> None:
        """Deterministic facts only: a payment that executed, its payee id, amount and block time."""
        if draft.task is not Task.PAYMENT or submission.outcome is not Outcome.EXECUTED:
            return
        receipt = self._chain.web3.eth.get_transaction_receipt(submission.tx_hash)
        block = self._chain.web3.eth.get_block(receipt["blockNumber"])
        self._memory.record_payment(draft.payee_id, draft.amount, int(block["timestamp"]))

    def _reply(self, kind: ReplyKind, key: str) -> AgentReply:
        return AgentReply(kind=kind, text_key=key, text=self._strings.render(key))
