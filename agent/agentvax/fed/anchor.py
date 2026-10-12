"""Anchoring a federated model in the ThreatBulletin, and adopting only an anchored model.

The bulletin accepts ``anchorModel`` only from its aggregator and only for a newer version. A wallet adopts a model
file only if its keccak256 equals the anchored hash for the latest version. Signers are passed in explicitly.
"""

from __future__ import annotations

from pathlib import Path

from eth_account import Account
from eth_account.signers.local import LocalAccount
from eth_utils import to_checksum_address

from agentvax.chain.client import ChainClient, Signer
from agentvax.detector.model import (
    Detector,
    DetectorModel,
    ModelHashMismatch,
    load_if_hash_matches,
    model_hash,
)
from agentvax.types import Address, Bytes32, Strict, Uint32

ZERO_HASH = "0x" + "00" * 32


class ModelNotAnchored(LookupError):
    """The bulletin holds no model hash for the requested version."""


class NotAggregator(PermissionError):
    """The signer is not the bulletin's aggregator."""


class AnchorRecord(Strict):
    chain_id: int
    bulletin: Address
    version: Uint32
    model_hash: Bytes32
    tx_hash: Bytes32


def anchor_model(client: ChainClient, aggregator: Signer, bulletin_address: str, model: DetectorModel) -> AnchorRecord:
    """Anchors ``model``'s version and hash. Refuses before sending if ``aggregator`` is not the bulletin's
    aggregator. Checks that exactly one matching ``ModelAnchored`` event was emitted."""
    bulletin = client.bulletin(bulletin_address)
    expected = to_checksum_address(bulletin.functions.aggregator().call())
    if to_checksum_address(aggregator.address) != expected:
        raise NotAggregator(f"{aggregator.address} is not the bulletin's aggregator {expected}")
    digest = model_hash(model)
    receipt = client.send(aggregator, bulletin.functions.anchorModel(model.version, bytes.fromhex(digest[2:])))
    events = client.events(receipt, bulletin, "ModelAnchored")
    if len(events) != 1:
        raise RuntimeError("expected exactly one ModelAnchored event")
    args = events[0]["args"]
    if int(args["version"]) != model.version or "0x" + bytes(args["modelHash"]).hex() != digest:
        raise RuntimeError("ModelAnchored event does not match the model")
    return AnchorRecord(
        chain_id=client.chain_id,
        bulletin=to_checksum_address(bulletin_address),
        version=model.version,
        model_hash=digest,
        tx_hash="0x" + bytes(receipt["transactionHash"]).hex(),
    )


def anchored_hash(client: ChainClient, bulletin_address: str, version: int) -> str:
    """The hash anchored for ``version``. Raises ``ModelNotAnchored`` if there is none."""
    digest = "0x" + bytes(client.bulletin(bulletin_address).functions.modelHash(version).call()).hex()
    if digest == ZERO_HASH:
        raise ModelNotAnchored(f"no model anchored for version {version}")
    return digest


def latest_anchor(client: ChainClient, bulletin_address: str) -> tuple[int, str]:
    """``(version, hash)`` of the latest anchored model. Raises ``ModelNotAnchored`` if none is anchored."""
    version = int(client.bulletin(bulletin_address).functions.latestModelVersion().call())
    if version == 0:
        raise ModelNotAnchored("no model has been anchored")
    return version, anchored_hash(client, bulletin_address, version)


def adopt(model_path: Path, client: ChainClient, bulletin_address: str) -> Detector:
    """The detector in ``model_path``, only if the file is the latest anchored model.

    Raises ``ModelHashMismatch`` if the file's hash differs from the latest anchored hash or the file names a
    different version, ``ModelNotAnchored`` if nothing is anchored, and ``ModelFormatError`` for a malformed file.
    """
    version, digest = latest_anchor(client, bulletin_address)
    model = load_if_hash_matches(model_path, digest)
    if model.version != version:
        raise ModelHashMismatch(f"model file names version {model.version}, the anchored version is {version}")
    return Detector(model)


def aggregator_from_key_file(path: Path) -> LocalAccount:
    """The aggregator signer from a file holding its hex private key. The key is never printed or logged."""
    account: LocalAccount = Account.from_key(path.read_text(encoding="ascii").strip())
    return account
