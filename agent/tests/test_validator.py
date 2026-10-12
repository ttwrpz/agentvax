"""Provenance, state and rule-set flags in the validator."""

from __future__ import annotations

from agentvax.harness.mock_llm import MockLLM
from agentvax.memory import PayeeFact
from agentvax.planner import (
    IntentDraft,
    OwnerInstruction,
    Provenance,
    ProvenanceKind,
    build_context,
    plan,
)
from agentvax.reader import DestinationStatus, DocumentKind, ReaderOutput
from agentvax.text import Strings
from agentvax.types import ZERO_BYTES32, Channel, Flag, ObligationView, ScheduleTerms, Task
from agentvax.schedules import read_schedule
from agentvax.validator import (
    Rejected,
    RejectionCode,
    Validated,
    rejection_text,
    validate_draft,
)
from runtime_support import ALLOWLIST, NOW, USD, make_view

INSTRUCTION = Provenance(kind=ProvenanceKind.INSTRUCTION)


def _context(text: str, documents=(), memory=(), view=None):
    return build_context(OwnerInstruction(text=text), view or make_view(), ALLOWLIST, memory, documents)


def _draft(**overrides) -> IntentDraft:
    fields = dict(
        task=Task.PAYMENT,
        payee_id=1,
        payee_label="Acme Supplies",
        amount=300 * USD,
        amount_source=INSTRUCTION,
        payee_source=INSTRUCTION,
    )
    fields.update(overrides)
    return IntentDraft(**fields)


def _document(**overrides) -> ReaderOutput:
    fields = dict(
        document_kind=DocumentKind.INVOICE,
        payee_index=0,
        payee_id=1,
        amount=300 * USD,
        due=None,
        flags=0,
        destination=DestinationStatus.NONE,
        channel=Channel.MESSAGE,
    )
    fields.update(overrides)
    return ReaderOutput(**fields)


def test_valid_payment_gets_nonce_and_known_identity_flag() -> None:
    result = validate_draft(_draft(), _context("pay Acme Supplies 300 for hosting"), make_view(nonce=9))
    assert isinstance(result, Validated)
    assert result.intent.nonce == 9
    assert result.intent.amount == 300 * USD
    assert result.intent.purpose_hash == ZERO_BYTES32
    assert result.flags == int(Flag.KNOWN_PAYEE_IDENTITY)


def test_provenance_rejects_unsourced_amount() -> None:
    context = _context("pay Acme Supplies 300 for hosting")
    result = validate_draft(_draft(amount=450 * USD), context, make_view())
    assert result == Rejected(code=RejectionCode.UNSOURCED_AMOUNT)
    assert "amount" in rejection_text(Strings.load(), result)


def test_provenance_rejects_amount_claimed_from_a_document_that_does_not_say_it() -> None:
    document = _document(amount=120 * USD)
    context = _context("pay the invoice", documents=(document,))
    reader = Provenance(kind=ProvenanceKind.READER, index=0)
    claimed = _draft(amount=300 * USD, amount_source=reader, payee_source=reader)
    assert validate_draft(claimed, context, make_view()) == Rejected(code=RejectionCode.UNSOURCED_AMOUNT)


def test_provenance_rejects_unsourced_payee() -> None:
    context = _context("pay Maple Properties 300")
    result = validate_draft(_draft(), context, make_view())
    assert result == Rejected(code=RejectionCode.UNSOURCED_PAYEE)


def test_provenance_rejects_raw_address() -> None:
    draft = _draft(payee_label="0x" + "ab" * 20)
    result = validate_draft(draft, _context("pay Acme Supplies 300"), make_view())
    assert result == Rejected(code=RejectionCode.RAW_ADDRESS)


def test_validator_rejects_a_payee_that_is_not_on_the_list() -> None:
    result = validate_draft(_draft(payee_id=9, payee_label=None), _context("pay Acme Supplies 300"), make_view())
    assert result == Rejected(code=RejectionCode.UNKNOWN_PAYEE)


def test_validator_rejects_a_frozen_wallet_and_a_short_balance() -> None:
    context = _context("pay Acme Supplies 300")
    assert validate_draft(_draft(), context, make_view(frozen=True)) == Rejected(code=RejectionCode.WALLET_FROZEN)
    poor = make_view(balance=100 * USD)
    assert validate_draft(_draft(), _context("pay Acme Supplies 300", view=poor), poor) == Rejected(
        code=RejectionCode.INSUFFICIENT_BALANCE
    )


def test_validator_sets_new_destination_flag() -> None:
    document = _document(destination=DestinationStatus.DIFFERS_FROM_ALLOWLIST)
    context = _context("pay the invoice from Acme Supplies", documents=(document,))
    decision = plan(MockLLM(), context)
    assert isinstance(decision, IntentDraft)
    result = validate_draft(decision, context, make_view())
    assert isinstance(result, Validated)
    assert Flag(result.flags) & Flag.NEW_DESTINATION
    assert Flag(result.flags) & Flag.KNOWN_PAYEE_IDENTITY


def test_reader_cannot_claim_known_identity_or_memory() -> None:
    document = _document(flags=int(Flag.KNOWN_PAYEE_IDENTITY | Flag.MEMORY_SOURCED | Flag.URGENCY))
    draft = _draft(amount_source=Provenance(kind=ProvenanceKind.READER, index=0))
    context = _context("pay Acme Supplies the invoice", documents=(document,))
    result = validate_draft(draft, context, make_view())
    assert isinstance(result, Validated)
    assert Flag(result.flags) & Flag.URGENCY
    assert not Flag(result.flags) & Flag.MEMORY_SOURCED


def test_validator_sets_memory_sourced_flag() -> None:
    fact = PayeeFact(
        payee_id=1, usual_amount=300 * USD, last_paid=NOW - 100, last_verified=NOW - 50, account_hash="0x" + "01" * 32
    )
    context = _context("pay the usual 300", memory=(fact,))
    decision = plan(MockLLM(), context)
    assert isinstance(decision, IntentDraft)
    assert decision.payee_id == 1
    assert decision.payee_source.kind is ProvenanceKind.MEMORY
    assert decision.amount_source.kind is ProvenanceKind.INSTRUCTION
    result = validate_draft(decision, context, make_view())
    assert isinstance(result, Validated)
    assert Flag(result.flags) & Flag.MEMORY_SOURCED


def test_memory_is_never_the_source_of_an_amount() -> None:
    fact = PayeeFact(
        payee_id=1, usual_amount=300 * USD, last_paid=NOW - 100, last_verified=NOW - 50, account_hash="0x" + "01" * 32
    )
    context = _context("pay Acme Supplies the usual amount", memory=(fact,))
    draft = _draft(amount_source=Provenance(kind=ProvenanceKind.MEMORY))
    assert validate_draft(draft, context, make_view()) == Rejected(code=RejectionCode.UNSOURCED_AMOUNT)
    decision = plan(MockLLM(), context)
    assert not isinstance(decision, IntentDraft), "the planner asks for the amount instead of taking it from memory"


def test_memory_tag_without_a_memory_fact_is_rejected() -> None:
    draft = _draft(amount_source=Provenance(kind=ProvenanceKind.MEMORY))
    result = validate_draft(draft, _context("pay Acme Supplies the usual amount"), make_view())
    assert result == Rejected(code=RejectionCode.UNSOURCED_AMOUNT)


def test_schedule_purpose_hash_is_the_terms_hash() -> None:
    context = _context("pay rent of 1,200 to Acme Supplies on the 1st of each month for 12 months")
    terms = read_schedule(context.instruction.text, context.now).terms
    assert terms is not None and terms.max_runs == 12
    draft = _draft(task=Task.SCHEDULE_CREATE, amount=1200 * USD, schedule=terms)
    result = validate_draft(draft, context, make_view())
    assert isinstance(result, Validated)
    assert result.intent.purpose_hash == terms.purpose_hash()
    assert result.schedule == terms


def test_schedule_terms_must_be_the_ones_the_instruction_states() -> None:
    """Provenance of a schedule: period, run count and first due date come from what the owner wrote."""
    context = _context("pay Acme Supplies 1,200 every month for 6 months")
    stated = ScheduleTerms(period=2_592_000, first_due=NOW + 2_592_000, max_runs=6)
    good = _draft(task=Task.SCHEDULE_CREATE, amount=1200 * USD, schedule=stated)
    assert isinstance(validate_draft(good, context, make_view()), Validated)
    for wrong in (
        stated.model_copy(update={"max_runs": 12}),
        stated.model_copy(update={"period": 604_800}),
        stated.model_copy(update={"first_due": NOW + 86_400}),
    ):
        draft = _draft(task=Task.SCHEDULE_CREATE, amount=1200 * USD, schedule=wrong)
        assert validate_draft(draft, context, make_view()) == Rejected(code=RejectionCode.UNSOURCED_SCHEDULE)

    unstated = _context("pay Acme Supplies 1,200 every month")
    assert validate_draft(good, unstated, make_view()) == Rejected(code=RejectionCode.UNSOURCED_SCHEDULE)
    one_off = _draft(amount=1200 * USD)
    assert validate_draft(one_off, context, make_view()) == Rejected(code=RejectionCode.UNSOURCED_SCHEDULE)


def test_a_contradictory_instruction_never_validates() -> None:
    context = _context("pay Acme Supplies 300, no wait, do not send Acme Supplies anything")
    assert validate_draft(_draft(), context, make_view()) == Rejected(code=RejectionCode.CONTRADICTORY_INSTRUCTION)


def test_schedule_in_the_past_or_too_frequent_is_rejected() -> None:
    context = _context("pay rent of 1,200 to Acme Supplies every month")
    past = ScheduleTerms(period=2_592_000, first_due=NOW - 1, max_runs=3)
    fast = ScheduleTerms(period=60, first_due=NOW + 10, max_runs=3)
    for terms in (past, fast):
        draft = _draft(task=Task.SCHEDULE_CREATE, amount=1200 * USD, schedule=terms)
        assert validate_draft(draft, context, make_view()) == Rejected(code=RejectionCode.MALFORMED_SCHEDULE)


def test_sweep_amount_must_be_the_discretionary_amount_from_the_wallet() -> None:
    mandate = Provenance(kind=ProvenanceKind.MANDATE)
    view = make_view(discretionary=250 * USD)
    context = _context("save what I do not need", view=view)
    good = IntentDraft(task=Task.SWEEP, payee_id=0, amount=250 * USD, amount_source=mandate, payee_source=mandate)
    inflated = good.model_copy(update={"amount": 900 * USD})
    assert isinstance(validate_draft(good, context, view), Validated)
    assert validate_draft(inflated, context, view) == Rejected(code=RejectionCode.UNSOURCED_AMOUNT)


def test_obligation_reference_must_belong_to_the_payee() -> None:
    obligation = ObligationView(
        obligation_id=1, payee_id=2, amount=300 * USD, due=NOW + 5, schedule_id=0, by_agent=True
    )
    view = make_view(obligations=(obligation,))
    context = _context("pay Acme Supplies 300", view=view)
    result = validate_draft(_draft(obligation_ref=1), context, view)
    assert result == Rejected(code=RejectionCode.OBLIGATION_MISMATCH)
