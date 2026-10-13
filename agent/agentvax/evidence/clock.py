"""Waiting for a delay to end, in chain time.

``NetworkClock`` polls the latest block. ``LocalClock`` moves Anvil's chain time forward. The contract always
decides with its own block time.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Protocol

from agentvax.chain.anvil import LocalNode
from agentvax.chain.client import ChainClient
from agentvax.evidence.plan import Timing


class WaitStalled(RuntimeError):
    """The chain produced no new block for longer than the plan allows."""


class ChainClock(Protocol):
    def wait_until(self, chain_time: int, what: str) -> None:
        """Returns once the latest block's timestamp is at least ``chain_time``."""
        ...


class NetworkClock:
    """Waits in real time on a public test network."""

    def __init__(
        self,
        client: ChainClient,
        timing: Timing,
        report: Callable[[str], None],
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._client = client
        self._timing = timing
        self._report = report
        self._sleep = sleep

    def wait_until(self, chain_time: int, what: str) -> None:
        latest = self._client.latest_timestamp()
        if latest >= chain_time:
            return
        self._report(f"waiting about {chain_time - latest} s for {what}")
        last_change, last_seen, last_report = time.monotonic(), latest, time.monotonic()
        while latest < chain_time:
            self._sleep(self._timing.poll_seconds)
            latest = self._client.latest_timestamp()
            now = time.monotonic()
            if latest != last_seen:
                last_seen, last_change = latest, now
            elif now - last_change > self._timing.stall_seconds:
                raise WaitStalled(f"no new block for {self._timing.stall_seconds:.0f} s while waiting for {what}")
            if latest < chain_time and now - last_report >= self._timing.progress_seconds:
                self._report(f"still waiting for {what}, about {chain_time - latest} s left")
                last_report = now
        self._report(f"{what} has passed on chain")


class LocalClock:
    """Moves a local Anvil's chain time forward."""

    def __init__(self, node: LocalNode, report: Callable[[str], None]) -> None:
        self._node = node
        self._report = report

    def wait_until(self, chain_time: int, what: str) -> None:
        self._report(f"moving local chain time forward past {what}")
        self._node.advance_to(chain_time)
