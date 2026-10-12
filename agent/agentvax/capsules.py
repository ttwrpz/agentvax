"""Capsule drafts and the local match rules.

A draft has only fixed fields, derived by rule from the flags, channel and task of an attack the owner confirmed.
It carries no text. A capsule can raise a tier or charge the allowance. It has no path to mandate state. A single
observer's capsule asks for a delay at most, which the bulletin enforces until a second wallet attests.
"""

from __future__ import annotations

from enum import IntEnum
from typing import Annotated

from pydantic import Field

from agentvax.chain import owner as owner_actions
from agentvax.chain.client import ChainClient, Signer
from agentvax.memory import MemoryStore, ThreatRecord
from agentvax.resources import load_model
from agentvax.types import (
    PRESSURE_FLAGS,
    Capsule,
    CapsuleAction,
    Channel,
    Family,
    Flag,
    Strict,
    Task,
    Uint8,
    Uint16,
    Uint32,
    Uint64,
)

_SINGLE_OBSERVER_RESTRICTION = 2


class CapsuleError(Exception):
    """An attack cannot be turned into a capsule."""


class CapsuleRules(Strict):
    lifetime_seconds: Annotated[int, Field(gt=0)]
    excluded_features: Annotated[int, Field(ge=0, le=0xFF)]


class ConfirmedAttack(Strict):
    """What the owner confirmed: the flags the request carried, the channel it came through and the task it asked for."""

    flags: Uint16
    channel: Channel
    task: Task


class CapsuleDraft(Strict):
    family: Family
    channel: Channel
    features: Uint16
    action: CapsuleAction
    restriction: Annotated[int, Field(ge=2, le=3)]
    lifetime: Annotated[int, Field(gt=0)]
    guard_version: Uint32

    def as_capsule(self, now: int, issuer: str) -> Capsule:
        """The capsule as the bulletin would store it right after the issuer publishes it."""
        return Capsule(
            family=self.family,
            channel=self.channel,
            features=self.features,
            action=self.action,
            restriction=self.restriction,
            expiry=now + self.lifetime,
            guard_version=self.guard_version,
            issuer=issuer,
            attestations=1,
        )


def _family(attack: ConfirmedAttack) -> Family:
    flags = Flag(attack.flags)
    if Flag.NEW_DESTINATION in flags and Flag.KNOWN_PAYEE_IDENTITY in flags:
        return Family.RECIPIENT_SUBSTITUTION
    if Flag.ENCODED_CONTENT in flags:
        return Family.ENCODED
    if Flag.MEMORY_SOURCED in flags or attack.channel is Channel.MEMORY:
        return Family.MEMORY
    if attack.channel is Channel.OWNER_CHAT:
        return Family.DIRECT
    return Family.INDIRECT


_TASK_ACTIONS = {
    Task.PAYMENT: CapsuleAction.PAYMENT,
    Task.SCHEDULE_CREATE: CapsuleAction.SCHEDULE_CREATE,
    Task.SWEEP: CapsuleAction.SWEEP,
}


def draft_capsule(attack: ConfirmedAttack, guard_version: int) -> CapsuleDraft:
    """Derive the draft by rule. Two attacks worded differently but carrying the same flags give the same draft.

    KNOWN_PAYEE_IDENTITY and AMOUNT_ANOMALY are never features (``excluded_features`` in the rules file): every
    clean payment to a known payee carries the first, and the contract sets the second itself, so either would let
    a capsule partially match ordinary payments and drain the allowance. A recipient substitution matches on
    NEW_DESTINATION and the pressure flags it carried.
    """
    rules = load_model(CapsuleRules, "data/capsule_rules.json")
    family = _family(attack)
    if family is Family.RECIPIENT_SUBSTITUTION:
        features = int(Flag.NEW_DESTINATION | (Flag(attack.flags) & PRESSURE_FLAGS))
    else:
        features = attack.flags & ~rules.excluded_features
    if features == 0:
        raise CapsuleError("the attack carries no feature a capsule can match on")
    if family is Family.RECIPIENT_SUBSTITUTION:
        action = CapsuleAction.PAYEE_OR_MANDATE_CHANGE
    elif attack.task in _TASK_ACTIONS:
        action = _TASK_ACTIONS[attack.task]
    else:
        raise CapsuleError("this task has no capsule action")
    return CapsuleDraft(
        family=family,
        channel=attack.channel,
        features=features,
        action=action,
        restriction=_SINGLE_OBSERVER_RESTRICTION,
        lifetime=rules.lifetime_seconds,
        guard_version=guard_version,
    )


class MatchKind(IntEnum):
    NONE = 0
    PARTIAL = 1
    FULL = 2


class CapsuleRequest(Strict):
    """A request as the matcher sees it."""

    action: CapsuleAction
    flags: Uint16
    now: Uint64


def _bits(value: int) -> int:
    return value.bit_count()


def match_capsule(
    capsule: Capsule, request: CapsuleRequest, channel_profile: Uint8, dismissed: bool = False
) -> MatchKind:
    """Mirror of the bulletin's match rules, for display only. The wallet contract decides.

    Not expired, not dismissed by this wallet, channel in the wallet profile and the same action. A full match needs
    every feature bit present in the request flags. A partial match needs at least half of them.
    """
    if dismissed or capsule.expiry <= request.now:
        return MatchKind.NONE
    if not (channel_profile >> int(capsule.channel)) & 1 or capsule.action != request.action:
        return MatchKind.NONE
    present = _bits(capsule.features & request.flags)
    if present == _bits(capsule.features):
        return MatchKind.FULL
    if present * 2 >= _bits(capsule.features):
        return MatchKind.PARTIAL
    return MatchKind.NONE


# ---------------------------------------------------------------------------------------------- owner workflow


class AttackConfirmation(Strict):
    """The result of ``confirm_attack``. ``capsule_id`` is set only if the owner chose to publish."""

    draft: CapsuleDraft | None
    capsule_id: Annotated[int, Field(ge=1)] | None
    confirm_tx_hash: str
    publish_tx_hash: str | None


class AttackConfirmed(Strict):
    """A mined ``confirmAttack``: the caution allowance is zero from block time ``confirmed_at``."""

    tx_hash: str
    confirmed_at: Uint64


def send_attack_confirmation(client: ChainClient, owner: Signer, wallet: str) -> AttackConfirmed:
    """Sends ``confirmAttack``, which sets the allowance to zero at once (tightening is immediate)."""
    receipt = owner_actions.confirm_attack(client, owner, wallet)
    return AttackConfirmed(
        tx_hash="0x" + bytes(receipt["transactionHash"]).hex(),
        confirmed_at=int(client.web3.eth.get_block(receipt["blockNumber"])["timestamp"]),
    )


def draft_for(attack: ConfirmedAttack, guard_version: int) -> CapsuleDraft | None:
    """The draft derived by rule, or None for an attack with no feature or action a capsule can match on."""
    try:
        return draft_capsule(attack, guard_version)
    except CapsuleError:
        return None


def publish_draft(
    client: ChainClient, owner: Signer, wallet: str, draft: CapsuleDraft
) -> owner_actions.PublishedCapsule:
    """Publishes ``draft`` from ``wallet`` to the bulletin it is fixed to. One transaction."""
    return owner_actions.publish_capsule(
        client,
        owner,
        wallet,
        owner_actions.CapsuleFields(
            family=draft.family,
            channel=draft.channel,
            features=draft.features,
            action=draft.action,
            restriction=draft.restriction,
            lifetime=draft.lifetime,
            guard_version=draft.guard_version,
        ),
    )


def remember_attack(
    memory: MemoryStore,
    attack: ConfirmedAttack,
    draft: CapsuleDraft | None,
    capsule_id: int | None,
    confirmed_at: int,
) -> None:
    """Records the confirmed attack in memory as its fixed features and the capsule id (0 when nothing was
    published). No text from the attack is kept."""
    memory.record_threat(
        ThreatRecord(
            family=draft.family if draft is not None else _family(attack),
            channel=attack.channel,
            features=draft.features if draft is not None else 0,
            capsule_id=capsule_id or 0,
            observed_at=confirmed_at,
        )
    )


def confirm_attack(
    client: ChainClient,
    owner: Signer,
    wallet: str,
    memory: MemoryStore,
    attack: ConfirmedAttack,
    guard_version: int,
    publish: bool,
) -> AttackConfirmation:
    """The owner confirms an attack.

    The allowance is set to zero at once through ``confirmAttack`` (tightening is immediate). A capsule draft is
    derived by rule. If ``publish`` is true and a draft exists, the wallet publishes it to the bulletin. The threat
    is recorded in memory as its fixed features and the capsule id (0 when nothing was published). An attack with
    no feature a capsule can match on is still confirmed and recorded, with no draft.

    A caller that must resume after a failure without repeating a mined transaction, such as the evidence run,
    uses ``send_attack_confirmation``, ``draft_for``, ``publish_draft`` and ``remember_attack`` one by one and
    records each transaction as it is mined.
    """
    confirmed = send_attack_confirmation(client, owner, wallet)
    draft = draft_for(attack, guard_version)
    published = publish_draft(client, owner, wallet, draft) if publish and draft is not None else None
    capsule_id = published.capsule_id if published is not None else None
    remember_attack(memory, attack, draft, capsule_id, confirmed.confirmed_at)
    return AttackConfirmation(
        draft=draft,
        capsule_id=capsule_id,
        confirm_tx_hash=confirmed.tx_hash,
        publish_tx_hash=published.tx_hash if published is not None else None,
    )
