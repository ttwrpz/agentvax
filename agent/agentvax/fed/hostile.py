"""A poisoning participant, for the hostile-wallet suite and its tests.

Sends the sign-flipped update scaled to ``hostile_scale`` times the clipping norm, unclipped. Masking hides
the length from the aggregator, so each wallet's canary check must reject the result. Holds no key.
"""

from __future__ import annotations

import numpy as np
from flwr.common import NDArrays

from agentvax.fed.client import WalletClient
from agentvax.fed.secure import l2_norm


def poisoned_update(honest_update: np.ndarray, target_norm: float) -> np.ndarray:
    """The sign-flipped ``honest_update`` rescaled to L2 norm ``target_norm``.

    Flipping the sign pushes the shared model away from what the wallet's data teaches, so attacks the data
    describes score lower and the model degrades for everyone.
    """
    norm = l2_norm(honest_update)
    if norm == 0.0:
        raise ValueError("cannot poison a zero update")
    return -np.asarray(honest_update, dtype=np.float64) * (target_norm / norm)


class HostileWalletClient(WalletClient):
    """A wallet that sends a poisoned, unclipped update and otherwise behaves like any other client."""

    def prepare_update(self, parameters: NDArrays, round_number: int) -> np.ndarray:
        honest = self.local_update(parameters, round_number)
        return poisoned_update(honest, self._config.hostile_scale * self._config.clip_norm)
