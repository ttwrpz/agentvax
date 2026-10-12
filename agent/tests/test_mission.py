"""Mission to mandate, the hash, and the owner-signature gate."""

from __future__ import annotations

import pytest
from eth_abi import encode as abi_encode
from eth_account import Account
from eth_utils import keccak

from agentvax.config import load_profile
from agentvax.harness.mock_llm import MockLLM
from agentvax.mission import (
    MandateProposal,
    MandatePublisher,
    MissionError,
    MissionProblem,
    OwnerSignedMandate,
    check_bounds,
    problem_text,
    propose_mandate,
    show_back,
    signing_message,
)
from agentvax.text import Strings
from agentvax.types import Mandate
from runtime_support import NOW, USD, WALLET, default_mandate

TEMPLATE = load_profile("default").mandate
MISSION = "Keep at least 600 in reserve, pay up to 500 on your own, and no more than 1,000 a day."
MANDATE_TUPLE = (
    "(uint256,uint256,uint256,uint256,uint64,uint64,uint64,uint64,uint64,uint64,uint32,uint8,uint8,uint8,uint8,uint8,"
    "uint8,uint256,uint256,uint256,uint256)"
)


class RecordingSink:
    def __init__(self, wallet: str = WALLET, chain_id: int = 31337) -> None:
        self.calls: list[tuple[Mandate, str]] = []
        self.wallet = wallet
        self.chain_id = chain_id

    def set_mandate(self, mandate: Mandate, mission: str) -> None:
        self.calls.append((mandate, mission))


def _sign(proposal: MandateProposal, key: str, owner: str, chain_id: int = 31337) -> OwnerSignedMandate:
    signed = Account.sign_message(signing_message(proposal, WALLET, chain_id), key)
    return OwnerSignedMandate(
        proposal=proposal,
        wallet=WALLET,
        chain_id=chain_id,
        owner=owner,
        signature="0x" + signed.signature.hex().removeprefix("0x"),
    )


def test_mission_to_mandate_roundtrip() -> None:
    proposal = propose_mandate(MockLLM(), MISSION, NOW, TEMPLATE)
    mandate = proposal.mandate
    assert (mandate.reserve, mandate.c1, mandate.d1) == (600 * USD, 500 * USD, 1000 * USD)
    assert mandate.c2 == default_mandate().c2, "unstated fields keep the defaults"
    independent = keccak(abi_encode(["bytes32", MANDATE_TUPLE], [keccak(text=MISSION), mandate.as_tuple()]))
    assert proposal.mandate_hash == "0x" + independent.hex()
    assert MandateProposal.model_validate_json(proposal.model_dump_json()) == proposal
    lines = show_back(Strings.load(), proposal)
    assert any("600" in line for line in lines) and any("500" in line for line in lines)
    assert lines[-1].endswith(proposal.mandate_hash)


def test_a_tampered_proposal_does_not_validate() -> None:
    proposal = propose_mandate(MockLLM(), MISSION, NOW, TEMPLATE)
    looser = proposal.mandate.model_copy(update={"c1": 900 * USD})
    with pytest.raises(ValueError):
        MandateProposal(mission=MISSION, mandate=looser, mandate_hash=proposal.mandate_hash)


def test_mission_durations_are_read() -> None:
    proposal = propose_mandate(
        MockLLM(),
        "Keep at least 800 in reserve. Wait 2 hours before larger payments. Wait 3 days before loosening.",
        NOW,
        TEMPLATE,
    )
    assert proposal.mandate.reserve == 800 * USD
    assert proposal.mandate.delay == 7200
    assert proposal.mandate.loosening_delay == 3 * 86_400


def test_out_of_order_limits_are_refused() -> None:
    with pytest.raises(MissionError) as caught:
        propose_mandate(MockLLM(), "Pay up to 5,000 on your own.", NOW, TEMPLATE)
    assert caught.value.problem is MissionProblem.LIMITS_OUT_OF_ORDER
    assert "limits" in problem_text(Strings.load(), caught.value)


def test_delays_outside_the_contract_bounds_are_refused() -> None:
    base = default_mandate()
    with pytest.raises(MissionError):
        check_bounds(base.model_copy(update={"delay": 0}))
    with pytest.raises(MissionError):
        check_bounds(base.model_copy(update={"pressure_hold": 8 * 86_400}))
    with pytest.raises(MissionError):
        check_bounds(base.model_copy(update={"loosening_delay": 31 * 86_400}))


def test_mandate_not_written_without_owner_signature() -> None:
    proposal = propose_mandate(MockLLM(), MISSION, NOW, TEMPLATE)
    owner, stranger = Account.create(), Account.create()
    sink = RecordingSink()
    publisher = MandatePublisher(sink, owner.address)

    forged = _sign(proposal, stranger.key.hex(), owner.address)
    with pytest.raises(MissionError) as caught:
        publisher.publish(forged)
    assert caught.value.problem is MissionProblem.NOT_OWNER_SIGNED

    blank = forged.model_copy(update={"signature": "0x" + "00" * 65})
    with pytest.raises(MissionError):
        publisher.publish(blank)

    claims_other = _sign(proposal, owner.key.hex(), stranger.address)
    with pytest.raises(MissionError):
        publisher.publish(claims_other)

    other_mission = propose_mandate(MockLLM(), "Keep at least 700 in reserve.", NOW, TEMPLATE)
    replay = _sign(other_mission, owner.key.hex(), owner.address).model_copy(update={"proposal": proposal})
    with pytest.raises(MissionError):
        publisher.publish(replay)

    assert sink.calls == []

    publisher.publish(_sign(proposal, owner.key.hex(), owner.address))
    assert sink.calls == [(proposal.mandate, MISSION)]


def test_signed_mandate_for_another_wallet_or_chain_is_refused() -> None:
    proposal = propose_mandate(MockLLM(), MISSION, NOW, TEMPLATE)
    owner = Account.create()
    signed = _sign(proposal, owner.key.hex(), owner.address)
    for sink in (RecordingSink(wallet="0x" + "22" * 20), RecordingSink(chain_id=84532)):
        with pytest.raises(MissionError) as caught:
            MandatePublisher(sink, owner.address).publish(signed)
        assert caught.value.problem is MissionProblem.WRONG_TARGET
        assert sink.calls == []


def test_signature_for_another_network_is_refused() -> None:
    proposal = propose_mandate(MockLLM(), MISSION, NOW, TEMPLATE)
    with pytest.raises(MissionError) as caught:
        signing_message(proposal, WALLET, 1)
    assert caught.value.problem is MissionProblem.UNSUPPORTED_CHAIN
