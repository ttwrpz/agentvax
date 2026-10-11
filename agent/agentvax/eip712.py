"""EIP-712 hashing of the wallet's typed data, computed exactly as the contract computes it.

The wallet's domain is built by OpenZeppelin ``EIP712`` with name ``EIP712_NAME``, version ``EIP712_VERSION``,
the chain id and the wallet address. The intent hash is the EIP-712 digest of an ``Intent``. The guardian signs
the EIP-712 digest of an ``Attestation`` whose ``intentHash`` is that digest.

This module holds no key. It is pure computation, used by the guardian to recompute what it signs and by the
runtime and the tests to compare with the contract's ``hashIntent`` and ``hashAttestation``.
"""

from __future__ import annotations

from typing import Any

from eth_abi import encode as abi_encode
from eth_keys import keys
from eth_utils import keccak, to_checksum_address

from agentvax.types import (
    ATTESTATION_TYPE,
    EIP712_NAME,
    EIP712_VERSION,
    INTENT_TYPE,
    Attestation,
    Intent,
)

DOMAIN_TYPE = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"

INTENT_TYPEHASH = keccak(text=INTENT_TYPE)
ATTESTATION_TYPEHASH = keccak(text=ATTESTATION_TYPE)
DOMAIN_TYPEHASH = keccak(text=DOMAIN_TYPE)

_DOMAIN_FIELDS = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]
_INTENT_FIELDS = [
    {"name": "task", "type": "uint8"},
    {"name": "payeeId", "type": "uint32"},
    {"name": "amount", "type": "uint256"},
    {"name": "scheduleId", "type": "uint64"},
    {"name": "purposeHash", "type": "bytes32"},
    {"name": "nonce", "type": "uint256"},
]
_ATTESTATION_FIELDS = [
    {"name": "intentHash", "type": "bytes32"},
    {"name": "band", "type": "uint8"},
    {"name": "source", "type": "uint8"},
    {"name": "flags", "type": "uint16"},
    {"name": "validUntil", "type": "uint64"},
]


def _hex(value: bytes) -> str:
    return "0x" + value.hex()


def domain_separator(chain_id: int, wallet: str) -> bytes:
    """Domain separator of the wallet at ``wallet`` on ``chain_id``."""
    return keccak(
        abi_encode(
            ["bytes32", "bytes32", "bytes32", "uint256", "address"],
            [
                DOMAIN_TYPEHASH,
                keccak(text=EIP712_NAME),
                keccak(text=EIP712_VERSION),
                chain_id,
                to_checksum_address(wallet),
            ],
        )
    )


def _digest(separator: bytes, struct_hash: bytes) -> bytes:
    return keccak(b"\x19\x01" + separator + struct_hash)


def intent_struct_hash(intent: Intent) -> bytes:
    return keccak(
        abi_encode(
            ["bytes32", "uint8", "uint32", "uint256", "uint64", "bytes32", "uint256"],
            [INTENT_TYPEHASH, *intent.as_tuple()],
        )
    )


def attestation_struct_hash(attestation: Attestation) -> bytes:
    return keccak(
        abi_encode(
            ["bytes32", "bytes32", "uint8", "uint8", "uint16", "uint64"],
            [ATTESTATION_TYPEHASH, *attestation.as_tuple()],
        )
    )


def intent_hash(intent: Intent, chain_id: int, wallet: str) -> str:
    """The intent hash: EIP-712 digest of ``intent`` under the wallet's domain, as ``0x`` hex."""
    return _hex(_digest(domain_separator(chain_id, wallet), intent_struct_hash(intent)))


def attestation_digest(attestation: Attestation, chain_id: int, wallet: str) -> str:
    """The digest the guardian signs: EIP-712 digest of ``attestation`` under the wallet's domain."""
    return _hex(_digest(domain_separator(chain_id, wallet), attestation_struct_hash(attestation)))


def _domain(chain_id: int, wallet: str) -> dict[str, Any]:
    return {
        "name": EIP712_NAME,
        "version": EIP712_VERSION,
        "chainId": chain_id,
        "verifyingContract": to_checksum_address(wallet),
    }


def attestation_typed_data(attestation: Attestation, chain_id: int, wallet: str) -> dict[str, Any]:
    """The full EIP-712 message for ``attestation`` in the form ``eth_account`` signs."""
    return {
        "types": {"EIP712Domain": _DOMAIN_FIELDS, "Attestation": _ATTESTATION_FIELDS},
        "primaryType": "Attestation",
        "domain": _domain(chain_id, wallet),
        "message": {
            "intentHash": bytes.fromhex(attestation.intent_hash[2:]),
            "band": int(attestation.band),
            "source": int(attestation.source),
            "flags": attestation.flags,
            "validUntil": attestation.valid_until,
        },
    }


def intent_typed_data(intent: Intent, chain_id: int, wallet: str) -> dict[str, Any]:
    """The full EIP-712 message for ``intent``, for display in a signing wallet."""
    return {
        "types": {"EIP712Domain": _DOMAIN_FIELDS, "Intent": _INTENT_FIELDS},
        "primaryType": "Intent",
        "domain": _domain(chain_id, wallet),
        "message": {
            "task": int(intent.task),
            "payeeId": intent.payee_id,
            "amount": intent.amount,
            "scheduleId": intent.schedule_id,
            "purposeHash": bytes.fromhex(intent.purpose_hash[2:]),
            "nonce": intent.nonce,
        },
    }


def recover_signer(digest: str, signature: str) -> str:
    """Checksum address that produced the 65-byte ``r || s || v`` ``signature`` over ``digest``.

    ``v`` may be 27 or 28 (as ``eth_account`` and OpenZeppelin ``ECDSA`` use) or 0 or 1. A malformed signature
    raises ``ValueError``.
    """
    raw = bytes.fromhex(signature[2:] if signature.startswith("0x") else signature)
    if len(raw) != 65:
        raise ValueError("signature must be 65 bytes")
    v = raw[64] - 27 if raw[64] >= 27 else raw[64]
    if v not in (0, 1):
        raise ValueError("invalid signature recovery id")
    message = bytes.fromhex(digest[2:] if digest.startswith("0x") else digest)
    public = keys.Signature(signature_bytes=raw[:64] + bytes([v])).recover_public_key_from_msg_hash(message)
    return to_checksum_address(public.to_checksum_address())
