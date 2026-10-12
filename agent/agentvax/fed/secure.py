"""Update clipping, fixed-point encoding and pairwise additive masks (after Bonawitz et al.).

Each wallet clips its update to L2 norm C, encodes it as integers in units of ``2**-fraction_bits`` and adds one
mask per peer from an X25519 and HKDF seed. The smaller id adds and the other subtracts, so masks cancel in the sum.
``exactness_bound`` keeps every partial sum below 2**53 so the cancellation is exact in float64.
A dropped wallet abandons the round. Clipping is done by the wallet because the aggregator sees only masked updates.
"""

from __future__ import annotations

import math
from collections.abc import Mapping

import numpy as np
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

EXACT_INTEGER_LIMIT = 2**53
MASK_INFO = b"agentvax-fed-mask-v1"


class MaskingError(ValueError):
    """Masked aggregation cannot be done exactly with these parameters or these inputs."""


def l2_norm(vector: np.ndarray) -> float:
    return float(np.linalg.norm(vector))


def clip(update: np.ndarray, clip_norm: float) -> np.ndarray:
    """``update`` scaled down to L2 norm ``clip_norm`` if it is longer, otherwise unchanged."""
    if clip_norm <= 0 or not math.isfinite(clip_norm):
        raise ValueError("clip_norm must be a positive finite number")
    vector = np.asarray(update, dtype=np.float64)
    if not np.all(np.isfinite(vector)):
        raise ValueError("update has non-finite components")
    norm = l2_norm(vector)
    if norm <= clip_norm:
        return vector.copy()
    return vector * (clip_norm / norm)


class Quantiser:
    """Fixed-point encoding in units of ``2**-fraction_bits``. Encoding rounds to the nearest unit, decoding is
    exact (division by a power of two)."""

    def __init__(self, fraction_bits: int) -> None:
        self.fraction_bits = fraction_bits
        self.scale = float(2**fraction_bits)

    def encode(self, vector: np.ndarray) -> np.ndarray:
        return np.rint(np.asarray(vector, dtype=np.float64) * self.scale)

    def decode(self, vector: np.ndarray) -> np.ndarray:
        return np.asarray(vector, dtype=np.float64) / self.scale

    def max_units(self, max_abs: float) -> float:
        """Largest encoded magnitude of a component whose absolute value is at most ``max_abs``."""
        return math.floor(max_abs * self.scale + 0.5)


def exactness_bound(
    n_wallets: int, examples_per_wallet: int, max_component: float, fraction_bits: int, mask_bits: int
) -> int:
    """Largest absolute value any partial sum of FedAvg's ``sum_k n * (q_k + masks_k)`` can reach.

    ``max_component`` bounds the absolute value of one component of an update before encoding. Each wallet adds
    ``n_wallets - 1`` masks, each component below ``2**mask_bits`` in magnitude.
    """
    per_update = math.floor(max_component * 2**fraction_bits + 0.5) + (n_wallets - 1) * 2**mask_bits
    return n_wallets * examples_per_wallet * per_update


def require_exact(
    n_wallets: int, examples_per_wallet: int, max_component: float, fraction_bits: int, mask_bits: int
) -> None:
    """Raises ``MaskingError`` unless masked FedAvg sums stay exactly representable in float64."""
    bound = exactness_bound(n_wallets, examples_per_wallet, max_component, fraction_bits, mask_bits)
    if bound >= EXACT_INTEGER_LIMIT:
        raise MaskingError(
            f"masked sums can reach {bound}, beyond 2**53; lower fraction_bits, mask_bits or the clip norm"
        )


class MaskingKey:
    """One wallet's X25519 key for agreeing pairwise mask seeds. The private key never leaves this object."""

    def __init__(self, wallet_id: str, private_key: X25519PrivateKey | None = None) -> None:
        self.wallet_id = wallet_id
        self._private = private_key if private_key is not None else X25519PrivateKey.generate()

    @property
    def public_key(self) -> X25519PublicKey:
        return self._private.public_key()

    def pair_seed(self, peer_id: str, peer_public: X25519PublicKey, round_number: int) -> int:
        """The seed this wallet and ``peer_id`` both derive for ``round_number``. Symmetric in the pair."""
        if peer_id == self.wallet_id:
            raise MaskingError("a wallet has no mask with itself")
        shared = self._private.exchange(peer_public)
        low, high = sorted((self.wallet_id, peer_id))
        info = MASK_INFO + f"|round={round_number}|pair={low},{high}".encode("ascii")
        derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared)
        return int.from_bytes(derived, "big")


def pair_mask(seed: int, dimension: int, mask_bits: int) -> np.ndarray:
    """Uniform integers in ``[-2**mask_bits, 2**mask_bits)``, as float64, drawn from ``seed``."""
    rng = np.random.default_rng(seed)
    bound = 2**mask_bits
    return rng.integers(-bound, bound, size=dimension, dtype=np.int64).astype(np.float64)


class PairwiseMasker:
    """Adds this wallet's share of every pairwise mask to an encoded update."""

    def __init__(self, key: MaskingKey, peers: Mapping[str, X25519PublicKey], mask_bits: int) -> None:
        if key.wallet_id in peers:
            raise MaskingError("the peer list must not contain the wallet itself")
        if not peers:
            raise MaskingError("masking needs at least one peer")
        self._key = key
        self._peers = dict(peers)
        self.mask_bits = mask_bits

    @property
    def wallet_id(self) -> str:
        return self._key.wallet_id

    def total_mask(self, round_number: int, dimension: int) -> np.ndarray:
        """Sum of this wallet's signed pairwise masks for ``round_number``."""
        total = np.zeros(dimension, dtype=np.float64)
        for peer_id in sorted(self._peers):
            seed = self._key.pair_seed(peer_id, self._peers[peer_id], round_number)
            mask = pair_mask(seed, dimension, self.mask_bits)
            total += mask if self.wallet_id < peer_id else -mask
        return total

    def mask(self, encoded_update: np.ndarray, round_number: int) -> np.ndarray:
        """``encoded_update`` plus this wallet's masks. The input must already be integer-valued."""
        update = np.asarray(encoded_update, dtype=np.float64)
        if not np.array_equal(update, np.rint(update)):
            raise MaskingError("only fixed-point encoded updates can be masked")
        return update + self.total_mask(round_number, update.shape[0])
