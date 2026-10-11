"""Agent session actions on a PolicyWallet, signed by the agent key passed in by the caller.

The agent submits attested intents. The contract decides the tier and the ``Decision`` event is returned as the
outcome. The agent key cannot add a payee, change the mandate or approve anything.
"""

from __future__ import annotations

from enum import Enum

from web3.types import TxReceipt

from agentvax.chain.client import ChainClient, Signer
from agentvax.types import (
    Attestation,
    Bytes32,
    DecisionEvent,
    Intent,
    ScheduleTerms,
    Strict,
    Task,
    Tier,
    Uint64,
)

SIGNATURE_PATTERN = r"^0x[0-9a-fA-F]{130}$"


class Outcome(str, Enum):
    EXECUTED = "executed"
    QUEUED = "queued"
    PROPOSED = "proposed"


class Submission(Strict):
    """What the wallet decided for one submitted intent, read from the receipt."""

    tx_hash: Bytes32
    block_number: int
    intent_hash: Bytes32
    decision: DecisionEvent
    outcome: Outcome
    item_id: int
    """Queued or proposed item id, 0 when executed at L1."""
    ready_at: Uint64 | None
    """When a queued item can execute. None for an executed or proposed intent."""


def _hash(receipt: TxReceipt) -> str:
    return "0x" + bytes(receipt["transactionHash"]).hex()


def _sig(signature: str) -> bytes:
    if len(signature) != 132 or not signature.startswith("0x"):
        raise ValueError("signature must be 65 bytes of 0x-prefixed hex")
    return bytes.fromhex(signature[2:])


def _submission(client: ChainClient, wallet: str, receipt: TxReceipt, attestation: Attestation) -> Submission:
    decisions = [d for d in client.decisions(receipt, wallet) if d.intent_hash == attestation.intent_hash]
    if len(decisions) != 1:
        raise RuntimeError("expected exactly one Decision for the submitted intent")
    decision = decisions[0]
    w = client.wallet(wallet)
    if decision.tier == Tier.L1:
        return Submission(
            tx_hash=_hash(receipt),
            block_number=int(receipt["blockNumber"]),
            intent_hash=attestation.intent_hash,
            decision=decision,
            outcome=Outcome.EXECUTED,
            item_id=0,
            ready_at=None,
        )
    if decision.tier == Tier.L2:
        queued = client.events(receipt, w, "Queued")
        if len(queued) != 1:
            raise RuntimeError("expected exactly one Queued event")
        return Submission(
            tx_hash=_hash(receipt),
            block_number=int(receipt["blockNumber"]),
            intent_hash=attestation.intent_hash,
            decision=decision,
            outcome=Outcome.QUEUED,
            item_id=int(queued[0]["args"]["itemId"]),
            ready_at=int(queued[0]["args"]["readyAt"]),
        )
    proposed = client.events(receipt, w, "Proposed")
    if len(proposed) != 1:
        raise RuntimeError("expected exactly one Proposed event")
    return Submission(
        tx_hash=_hash(receipt),
        block_number=int(receipt["blockNumber"]),
        intent_hash=attestation.intent_hash,
        decision=decision,
        outcome=Outcome.PROPOSED,
        item_id=int(proposed[0]["args"]["itemId"]),
        ready_at=None,
    )


def submit(
    client: ChainClient, agent: Signer, wallet: str, intent: Intent, attestation: Attestation, signature: str
) -> Submission:
    """Submits a PAYMENT, SWEEP or FEE_TOPUP intent with its guardian attestation."""
    if intent.task == Task.SCHEDULE_CREATE:
        raise ValueError("a SCHEDULE_CREATE intent is submitted with submit_schedule")
    call = client.wallet(wallet).functions.submit(intent.as_tuple(), attestation.as_tuple(), _sig(signature))
    return _submission(client, wallet, client.send(agent, call), attestation)


def submit_schedule(
    client: ChainClient,
    agent: Signer,
    wallet: str,
    intent: Intent,
    terms: ScheduleTerms,
    attestation: Attestation,
    signature: str,
) -> Submission:
    """Submits a SCHEDULE_CREATE intent. Its ``purpose_hash`` must commit to ``terms``."""
    if intent.task != Task.SCHEDULE_CREATE:
        raise ValueError("submit_schedule takes a SCHEDULE_CREATE intent")
    if intent.purpose_hash != terms.purpose_hash():
        raise ValueError("the intent's purpose hash does not commit to these schedule terms")
    call = client.wallet(wallet).functions.submitSchedule(
        intent.as_tuple(), terms.as_tuple(), attestation.as_tuple(), _sig(signature)
    )
    return _submission(client, wallet, client.send(agent, call), attestation)


def record_payee_change_request(
    client: ChainClient, agent: Signer, wallet: str, identity_hash: str, account: str, flags: int
) -> TxReceipt:
    """Records that something asked to pay a new address. Carries no authority: only the owner can propose."""
    call = client.wallet(wallet).functions.recordPayeeChangeRequest(bytes.fromhex(identity_hash[2:]), account, flags)
    return client.send(agent, call)


def add_obligation(
    client: ChainClient,
    signer: Signer,
    wallet: str,
    payee_id: int,
    amount: int,
    due: int,
) -> TxReceipt:
    """Registers a bill, which can only lower D. ``signer`` is the agent or the owner."""
    return client.send(signer, client.wallet(wallet).functions.addObligation(payee_id, amount, due))


# ---------------------------------------------------------------------------------------------- open to anyone


def execute_pending(client: ChainClient, signer: Signer, wallet: str, item_id: int) -> TxReceipt:
    """Executes a queued item after Δ or an approved item after any hold. Re-assessed by the contract."""
    return client.send(signer, client.wallet(wallet).functions.executePending(item_id))


def run_schedule(client: ChainClient, signer: Signer, wallet: str, schedule_id: int) -> TxReceipt:
    """Pays a due schedule occurrence if it is still L1, otherwise the wallet emits ``ScheduleHeld``."""
    return client.send(signer, client.wallet(wallet).functions.runSchedule(schedule_id))


def sync_capsules(client: ChainClient, signer: Signer, wallet: str, max_count: int) -> TxReceipt:
    return client.send(signer, client.wallet(wallet).functions.syncCapsules(max_count))
