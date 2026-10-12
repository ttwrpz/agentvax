"""Python against the deployed contracts: constants copied from the contracts, capsule features as the wallet
matches them, the owner workflows that write memory, and the gas fee settings. Each test runs on the session
Anvil with a fresh stack."""

from __future__ import annotations

from typing import Any

import pytest
from agentvax import mission
from agentvax.names import identity_hash
from agentvax.capsules import ConfirmedAttack, confirm_attack, draft_capsule
from agentvax.chain.artifacts import ArtifactStore
from agentvax.chain.client import POLICY_WALLET, ChainClient, decode_revert
from agentvax.chain.deploy import WalletSpec, deploy_wallet
from agentvax.chain.owner import CapsuleFields, propose_add_payee, publish_capsule
from agentvax.config import ChainTuning, load_profile
from agentvax.eip712 import attestation_typed_data, intent_hash
from agentvax.memory import MemoryStore, account_hash
from agentvax.owner_tools import apply_payee_addition
from agentvax.types import (
    MAX_ATTESTATION_TTL,
    ZERO_BYTES32,
    Attestation,
    Band,
    CapsuleAction,
    Channel,
    Family,
    Flag,
    Intent,
    Mandate,
    Source,
    Task,
)
from chain_support import TUNING, AnvilNode, LocalStack, advance_time, client_for, deploy_test_stack, funded_account
from eth_account import Account
from web3.contract.contract import ContractFunction
from web3.exceptions import ContractLogicError


def _outcome(client: ChainClient, call: ContractFunction, sender: str) -> str:
    """``"ok"`` if ``call`` succeeds at the latest block, else the name of the custom error it reverts with."""
    try:
        call.call({"from": sender}, block_identifier="latest")
    except ContractLogicError as exc:
        return decode_revert(client.artifacts.load(POLICY_WALLET).abi, str(exc.data))[0]
    return "ok"


def _publish(client: ChainClient, stack: LocalStack, draft: Any) -> int:
    fields = CapsuleFields(**{k: getattr(draft, k) for k in CapsuleFields.model_fields})
    return publish_capsule(client, stack.owner, stack.wallet, fields).capsule_id


def _matches(client: ChainClient, stack: LocalStack, action: CapsuleAction, flags: int) -> tuple[set[int], set[int]]:
    client.send(stack.owner, client.wallet(stack.wallet).functions.syncCapsules(16))
    full, partial, _, _ = client.wallet(stack.wallet).functions.matchCapsules(int(action), flags).call()
    return set(full), set(partial)


# ---------------------------------------------------------------------------------------------- constants


def test_python_copies_of_contract_bounds_match_the_contract(anvil: AnvilNode, artifacts: ArtifactStore) -> None:
    client = client_for(anvil, artifacts)
    stack = deploy_test_stack(client, anvil, Account.create().address)
    owner = funded_account(anvil)
    fresh = deploy_wallet(
        client,
        stack.deployer,
        stack.deployer,
        stack.deployment,
        WalletSpec(label="B", owner=owner.address, agent=Account.create().address, guardian=Account.create().address),
    )
    base = load_profile("default").mandate.mandate(client.latest_timestamp())
    wallet = client.wallet(fresh.address)

    def set_mandate(m: Mandate) -> str:
        return _outcome(client, wallet.functions.setMandate("bounds", m.as_tuple()), owner.address)

    for field, bound in (
        ("delay", mission.MAX_DELAY),
        ("loosening_delay", mission.MAX_LOOSENING_DELAY),
        ("pressure_hold", mission.MAX_PRESSURE_HOLD),
    ):
        at_bound = base.model_copy(update={field: bound})
        over = base.model_copy(update={field: bound + 1})
        assert set_mandate(at_bound) == "ok", field
        assert set_mandate(over) == "InvalidMandate", field
        mission.check_bounds(at_bound)
        with pytest.raises(mission.MissionError):
            mission.check_bounds(over)

    view = client.wallet_view(stack.wallet)
    assert view.min_schedule_period == client.wallet(stack.wallet).functions.MIN_SCHEDULE_PERIOD().call()


def test_attestation_ttl_copy_matches_the_contract(anvil: AnvilNode, artifacts: ArtifactStore) -> None:
    client = client_for(anvil, artifacts)
    guardian = Account.create()
    stack = deploy_test_stack(client, anvil, guardian.address)
    wallet = client.wallet(stack.wallet)
    intent = Intent(task=Task.SWEEP, payee_id=0, amount=10**6, schedule_id=0, purpose_hash=ZERO_BYTES32, nonce=0)

    def outcome(seconds: int) -> str:
        att = Attestation(
            intent_hash=intent_hash(intent, 31337, stack.wallet),
            band=Band.LOW,
            source=Source.OWNER_INSTRUCTION,
            flags=0,
            valid_until=client.latest_timestamp() + seconds,
        )
        sig = guardian.sign_typed_data(full_message=attestation_typed_data(att, 31337, stack.wallet)).signature
        return _outcome(client, wallet.functions.submit(intent.as_tuple(), att.as_tuple(), sig), stack.agent.address)

    assert outcome(MAX_ATTESTATION_TTL) == "ok"
    assert outcome(MAX_ATTESTATION_TTL + 1) == "AttestationValidityTooLong"
    assert load_profile("default").guardian.attestation_lifetime <= MAX_ATTESTATION_TTL


def test_max_fee_follows_the_configured_multiplier(anvil: AnvilNode, artifacts: ArtifactStore) -> None:
    client = ChainClient(anvil.rpc_url, artifacts, TUNING.model_copy(update={"max_fee_base_multiplier": 3}))
    sender = funded_account(anvil)
    receipt = client.send_value(sender, Account.create().address, 1)
    tx = client.web3.eth.get_transaction(receipt["transactionHash"])
    base = client.web3.eth.get_block(receipt["blockNumber"] - 1)["baseFeePerGas"]
    assert tx["maxFeePerGas"] == 3 * base + tx["maxPriorityFeePerGas"]
    assert ChainTuning().max_fee_base_multiplier == 2


# ---------------------------------------------------------------------------------------------- capsules


def test_capsules_never_partially_match_a_clean_known_payee_payment(anvil: AnvilNode, artifacts: ArtifactStore) -> None:
    client = client_for(anvil, artifacts)
    stack = deploy_test_stack(client, anvil, Account.create().address)
    substitution = draft_capsule(
        ConfirmedAttack(
            flags=int(Flag.KNOWN_PAYEE_IDENTITY | Flag.NEW_DESTINATION | Flag.URGENCY),
            channel=Channel.MESSAGE,
            task=Task.PAYMENT,
        ),
        1,
    )
    urgent_invoice = draft_capsule(
        ConfirmedAttack(
            flags=int(Flag.KNOWN_PAYEE_IDENTITY | Flag.URGENCY | Flag.AMOUNT_ANOMALY),
            channel=Channel.WEB_PAGE,
            task=Task.PAYMENT,
        ),
        1,
    )
    assert substitution.family is Family.RECIPIENT_SUBSTITUTION
    assert substitution.features == int(Flag.NEW_DESTINATION | Flag.URGENCY)
    assert urgent_invoice.features == int(Flag.URGENCY)
    for draft in (substitution, urgent_invoice):
        assert not draft.features & (Flag.KNOWN_PAYEE_IDENTITY | Flag.AMOUNT_ANOMALY)

    sub_id = _publish(client, stack, substitution)
    urgent_id = _publish(client, stack, urgent_invoice)

    clean = int(Flag.KNOWN_PAYEE_IDENTITY)
    for action in (CapsuleAction.PAYMENT, CapsuleAction.PAYEE_OR_MANDATE_CHANGE):
        full, partial = _matches(client, stack, action, clean)
        assert not full and not partial, action

    full, _ = _matches(client, stack, CapsuleAction.PAYMENT, clean | int(Flag.URGENCY))
    assert urgent_id in full
    full, _ = _matches(
        client, stack, CapsuleAction.PAYEE_OR_MANDATE_CHANGE, clean | int(Flag.NEW_DESTINATION | Flag.URGENCY)
    )
    assert sub_id in full


# ---------------------------------------------------------------------------------------------- owner workflows


def test_confirm_attack_zeroes_allowance_records_threat_and_returns_draft(
    anvil: AnvilNode, artifacts: ArtifactStore
) -> None:
    client = client_for(anvil, artifacts)
    stack = deploy_test_stack(client, anvil, Account.create().address)
    memory = MemoryStore(":memory:")
    try:
        assert client.wallet_view(stack.wallet).allowance_points > 0
        attack = ConfirmedAttack(
            flags=int(Flag.KNOWN_PAYEE_IDENTITY | Flag.NEW_DESTINATION | Flag.SECRECY),
            channel=Channel.MESSAGE,
            task=Task.PAYMENT,
        )
        result = confirm_attack(client, stack.owner, stack.wallet, memory, attack, guard_version=1, publish=True)
        assert result.draft == draft_capsule(attack, 1)
        assert result.capsule_id == 1 and result.publish_tx_hash is not None
        receipt = client.web3.eth.get_transaction_receipt(result.confirm_tx_hash)
        assert client.events(receipt, client.wallet(stack.wallet), "AttackConfirmed")
        assert client.web3.eth.get_block(receipt["blockNumber"])["timestamp"] == memory.threats()[0].observed_at
        assert client.wallet(stack.wallet).functions.allowance().call(block_identifier=receipt["blockNumber"]) == 0
        (threat,) = memory.threats()
        assert (threat.family, threat.channel, threat.features, threat.capsule_id) == (
            Family.RECIPIENT_SUBSTITUTION,
            Channel.MESSAGE,
            result.draft.features,
            1,
        )
        bulletin = client.bulletin(stack.deployment.threat_bulletin.address)
        assert bulletin.functions.getCapsule(1).call()[2] == result.draft.features

        unpublished = confirm_attack(
            client,
            stack.owner,
            stack.wallet,
            memory,
            ConfirmedAttack(flags=int(Flag.AMOUNT_ANOMALY), channel=Channel.WEB_PAGE, task=Task.PAYMENT),
            guard_version=1,
            publish=True,
        )
        assert unpublished.draft is None and unpublished.capsule_id is None
        assert memory.threats()[1].capsule_id == 0 and memory.threats()[1].features == 0
    finally:
        memory.close()


def test_payee_addition_records_verification(anvil: AnvilNode, artifacts: ArtifactStore) -> None:
    client = client_for(anvil, artifacts)
    stack = deploy_test_stack(client, anvil, Account.create().address)
    memory = MemoryStore(":memory:")
    try:
        account = Account.create().address
        identity = identity_hash("Acme Supplies")
        change = propose_add_payee(client, stack.owner, stack.wallet, identity, account)
        assert memory.payee_facts() == ()
        advance_time(anvil, client.wallet_view(stack.wallet).mandate.loosening_delay)
        added = apply_payee_addition(client, stack.owner, stack.wallet, change.change_id, memory)
        assert added.payee_id == 1 and added.account == account and added.identity_hash == identity
        fact = memory.payee_fact(1)
        assert fact is not None and fact.account_hash == account_hash(account)
        receipt = client.web3.eth.get_transaction_receipt(added.tx_hash)
        assert fact.last_verified == client.web3.eth.get_block(receipt["blockNumber"])["timestamp"]
        assert fact.usual_amount == 0 and fact.last_paid == 0
    finally:
        memory.close()


def test_mandate_written_through_the_owner_sink_matches_the_proposal(
    anvil: AnvilNode, artifacts: ArtifactStore
) -> None:
    from agentvax.chain.owner import OwnerMandateSink
    from agentvax.harness.mock_llm import MockLLM

    client = client_for(anvil, artifacts)
    stack = deploy_test_stack(client, anvil, Account.create().address)
    owner = funded_account(anvil)
    fresh = deploy_wallet(
        client,
        stack.deployer,
        stack.deployer,
        stack.deployment,
        WalletSpec(label="C", owner=owner.address, agent=Account.create().address, guardian=Account.create().address),
    )
    proposal = mission.propose_mandate(
        MockLLM(),
        "Keep at least 700 in reserve and pay up to 400 on your own.",
        client.latest_timestamp(),
        load_profile("demo").mandate,
    )
    signed = Account.sign_message(mission.signing_message(proposal, fresh.address, 31337), owner.key)
    sink = OwnerMandateSink(client, owner, fresh.address)
    mission.MandatePublisher(sink, owner.address).publish(
        mission.OwnerSignedMandate(
            proposal=proposal,
            wallet=fresh.address,
            chain_id=31337,
            owner=owner.address,
            signature="0x" + bytes(signed.signature).hex(),
        )
    )
    _, on_chain = client.wallet(fresh.address).functions.mandateHashes().call()
    assert "0x" + bytes(on_chain).hex() == proposal.mandate_hash
    assert client.wallet_view(fresh.address).mandate == proposal.mandate
