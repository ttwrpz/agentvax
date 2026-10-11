"""Owner actions on a PolicyWallet.

Every function takes the owner signer explicitly. Tightening and cancelling act at once. Loosening is only
proposed here and applied by ``apply_change`` after Λ, which the contract enforces.
"""

from __future__ import annotations

from typing import Annotated

from eth_utils import to_checksum_address
from pydantic import Field
from web3.types import TxReceipt

from agentvax.chain.client import ChainClient, Signer
from agentvax.types import CapsuleAction, Channel, Family, Mandate, Strict, Uint32, Uint64


class ProposedChange(Strict):
    """A loosening change waiting on Λ."""

    change_id: int
    ready_at: Uint64
    tx_hash: str


class PublishedCapsule(Strict):
    capsule_id: int
    expiry: Uint64
    tx_hash: str


class CapsuleFields(Strict):
    """The fixed fields an owner publishes for a confirmed attack. No text, no call data."""

    family: Family
    channel: Channel
    features: Annotated[int, Field(ge=1, le=0xFF)]
    action: CapsuleAction
    restriction: Annotated[int, Field(ge=2, le=3)]
    lifetime: Annotated[int, Field(ge=1, le=2**64 - 1)]
    guard_version: Uint32


def _hash(receipt: TxReceipt) -> str:
    return "0x" + bytes(receipt["transactionHash"]).hex()


def _proposed(client: ChainClient, wallet: str, receipt: TxReceipt) -> ProposedChange:
    events = client.events(receipt, client.wallet(wallet), "ChangeProposed")
    if len(events) != 1:
        raise RuntimeError("expected exactly one ChangeProposed event")
    args = events[0]["args"]
    return ProposedChange(change_id=int(args["changeId"]), ready_at=int(args["readyAt"]), tx_hash=_hash(receipt))


# ---------------------------------------------------------------------------------------------- mandate


def set_mandate(client: ChainClient, owner: Signer, wallet: str, mission: str, mandate: Mandate) -> TxReceipt:
    """Sets the first mandate, or a mandate that is equal or tighter in every field."""
    return client.send(owner, client.wallet(wallet).functions.setMandate(mission, mandate.as_tuple()))


def propose_mandate(client: ChainClient, owner: Signer, wallet: str, mission: str, mandate: Mandate) -> ProposedChange:
    """Proposes a mandate with a looser field. Applied after Λ."""
    receipt = client.send(owner, client.wallet(wallet).functions.proposeMandate(mission, mandate.as_tuple()))
    return _proposed(client, wallet, receipt)


def propose_add_payee(
    client: ChainClient, owner: Signer, wallet: str, identity_hash: str, account: str
) -> ProposedChange:
    """Proposes the payee (identity, address). Applied after Λ."""
    call = client.wallet(wallet).functions.proposeAddPayee(bytes.fromhex(identity_hash[2:]), account)
    return _proposed(client, wallet, client.send(owner, call))


def propose_unfreeze(client: ChainClient, owner: Signer, wallet: str) -> ProposedChange:
    return _proposed(client, wallet, client.send(owner, client.wallet(wallet).functions.proposeUnfreeze()))


def apply_change(client: ChainClient, owner: Signer, wallet: str, change_id: int) -> TxReceipt:
    """Applies a change once Λ has passed and the change is not stale."""
    return client.send(owner, client.wallet(wallet).functions.applyChange(change_id))


def cancel_change(client: ChainClient, owner: Signer, wallet: str, change_id: int) -> TxReceipt:
    return client.send(owner, client.wallet(wallet).functions.cancelChange(change_id))


def remove_payee(client: ChainClient, owner: Signer, wallet: str, payee_id: int) -> TxReceipt:
    return client.send(owner, client.wallet(wallet).functions.removePayee(payee_id))


def freeze(client: ChainClient, owner: Signer, wallet: str) -> TxReceipt:
    return client.send(owner, client.wallet(wallet).functions.freeze())


def confirm_attack(client: ChainClient, owner: Signer, wallet: str) -> TxReceipt:
    """Sets the caution allowance to zero."""
    return client.send(owner, client.wallet(wallet).functions.confirmAttack())


# ---------------------------------------------------------------------------------------------- items


def approve(client: ChainClient, owner: Signer, wallet: str, item_id: int) -> TxReceipt:
    return client.send(owner, client.wallet(wallet).functions.approve(item_id))


def cancel(client: ChainClient, owner: Signer, wallet: str, item_id: int) -> TxReceipt:
    return client.send(owner, client.wallet(wallet).functions.cancel(item_id))


def extend_hold(client: ChainClient, owner: Signer, wallet: str, item_id: int, extra_seconds: int) -> TxReceipt:
    """Lengthens the wait of a pending item. A wait can never be shortened."""
    if extra_seconds <= 0:
        raise ValueError("extra_seconds must be positive")
    return client.send(owner, client.wallet(wallet).functions.extendHold(item_id, extra_seconds))


# ---------------------------------------------------------------------------------------------- capsules


def publish_capsule(client: ChainClient, owner: Signer, wallet: str, fields: CapsuleFields) -> PublishedCapsule:
    """Publishes a capsule from ``wallet`` to the bulletin it is fixed to."""
    w = client.wallet(wallet)
    call = w.functions.publishCapsule(
        int(fields.family),
        int(fields.channel),
        fields.features,
        int(fields.action),
        fields.restriction,
        fields.lifetime,
        fields.guard_version,
    )
    receipt = client.send(owner, call)
    bulletin = client.bulletin(w.functions.bulletin().call())
    events = client.events(receipt, bulletin, "CapsulePublished")
    if len(events) != 1:
        raise RuntimeError("expected exactly one CapsulePublished event")
    args = events[0]["args"]
    return PublishedCapsule(capsule_id=int(args["id"]), expiry=int(args["expiry"]), tx_hash=_hash(receipt))


def attest_capsule(client: ChainClient, owner: Signer, wallet: str, capsule_id: int) -> TxReceipt:
    return client.send(owner, client.wallet(wallet).functions.attestCapsule(capsule_id))


def dismiss_capsule(client: ChainClient, owner: Signer, wallet: str, capsule_id: int) -> TxReceipt:
    """Dismisses a capsule for this wallet only. Does not touch the mandate."""
    return client.send(owner, client.wallet(wallet).functions.dismissCapsule(capsule_id))


class OwnerMandateSink:
    """Writes a mandate through ``set_mandate`` with the owner's signer. The production ``MandateSink`` of
    ``agentvax.mission.MandatePublisher``, so the owner-signature gate sits on the real write path."""

    def __init__(self, client: ChainClient, owner: Signer, wallet: str) -> None:
        self._client = client
        self._owner = owner
        self._wallet = to_checksum_address(wallet)

    @property
    def wallet(self) -> str:
        return self._wallet

    @property
    def chain_id(self) -> int:
        return self._client.chain_id

    @property
    def owner(self) -> str:
        return to_checksum_address(self._owner.address)

    def set_mandate(self, mandate: Mandate, mission: str) -> None:
        set_mandate(self._client, self._owner, self._wallet, mission, mandate)
