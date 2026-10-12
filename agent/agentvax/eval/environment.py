"""The local chain of an evaluation run: its own Anvil on a free port, snapshots and chain time.

Block timestamps use a fixed interval and time is moved with ``evm_setNextBlockTimestamp``, so a run does not
depend on host speed or clock. A revert restores chain time with the state.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Annotated, Any

from pydantic import Field
from web3 import Web3

from agentvax.config import ChainTuning
from agentvax.types import ALLOWED_CHAIN_IDS, Strict


class RunnerConfig(Strict):
    """Settings of the evaluation runner, read from ``eval/data/runner.json``."""

    chain_id: int
    profile: str
    anvil_executable: Annotated[str, Field(min_length=1)]
    forge_executable: Annotated[str, Field(min_length=1)]
    anvil_startup_seconds: Annotated[float, Field(gt=0)]
    block_interval_seconds: Annotated[int, Field(ge=1, le=60)]
    """Chain seconds between consecutive blocks."""
    mission: Annotated[str, Field(min_length=1, max_length=2_000)]
    """The mission text every evaluation wallet's mandate is set with."""
    wallet_native: str
    """Default native fee reserve of a wallet, in ether."""
    agent_native: str
    """Default native balance of an agent key, in ether."""
    service_native: str
    """Native balance given to the deployer, owner, keeper and aggregator keys, in ether."""
    time_margin_seconds: Annotated[int, Field(ge=1, le=3_600)]
    """Seconds added when the harness waits out a delay during setup, so the next block is past it."""
    rewordings_per_attack: Annotated[int, Field(ge=1, le=10)]
    """Fresh model rewordings asked for per base attack in live mode."""
    rpc_timeout_seconds: Annotated[float, Field(gt=0)]
    receipt_timeout_seconds: Annotated[float, Field(gt=0)]
    receipt_poll_seconds: Annotated[float, Field(gt=0)]

    def tuning(self) -> ChainTuning:
        return ChainTuning(
            rpc_timeout_seconds=self.rpc_timeout_seconds,
            receipt_timeout_seconds=self.receipt_timeout_seconds,
            receipt_poll_seconds=self.receipt_poll_seconds,
        )


class ChainError(RuntimeError):
    """Anvil did not start or did not answer a control call."""


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def find_executable(name: str) -> str:
    """``name`` on PATH, or in Foundry's default install directory ``~/.foundry/bin``."""
    found = shutil.which(name)
    if found:
        return found
    for candidate in (Path.home() / ".foundry" / "bin" / f"{name}.exe", Path.home() / ".foundry" / "bin" / name):
        if candidate.is_file():
            return str(candidate)
    raise ChainError(f"{name} was not found on PATH or in ~/.foundry/bin; install Foundry")


class AnvilChain:
    """A running Anvil owned by this process."""

    def __init__(
        self, process: subprocess.Popen[bytes], rpc_url: str, chain_id: int, timeout: float, interval: int
    ) -> None:
        self._process = process
        self.rpc_url = rpc_url
        self.chain_id = chain_id
        self._interval = interval
        self._w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": timeout}))

    @classmethod
    def start(cls, config: RunnerConfig) -> AnvilChain:
        """Starts Anvil on a free local port and waits until it answers. Stops it again if it does not."""
        if config.chain_id not in ALLOWED_CHAIN_IDS:
            raise ChainError(f"chain id {config.chain_id} is not an allowed test network")
        port = _free_port()
        process = subprocess.Popen(
            [
                find_executable(config.anvil_executable),
                "--port",
                str(port),
                "--chain-id",
                str(config.chain_id),
                "--host",
                "127.0.0.1",
                "--silent",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        chain = cls(
            process,
            f"http://127.0.0.1:{port}",
            config.chain_id,
            config.rpc_timeout_seconds,
            config.block_interval_seconds,
        )
        deadline = time.monotonic() + config.anvil_startup_seconds
        try:
            while not chain._answers():
                if process.poll() is not None:
                    raise ChainError("anvil exited during startup")
                if time.monotonic() > deadline:
                    raise ChainError("anvil did not start in time")
                time.sleep(0.1)
            chain._call("anvil_setBlockTimestampInterval", [config.block_interval_seconds])
            return chain
        except BaseException:
            chain.stop()
            raise

    def _answers(self) -> bool:
        try:
            return bool(self._w3.is_connected())
        except OSError:
            return False

    @property
    def running(self) -> bool:
        return self._process.poll() is None

    def stop(self) -> None:
        if self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=10)

    # ------------------------------------------------------------------------------------ control calls

    def _call(self, method: str, params: list[Any]) -> Any:
        reply = self._w3.provider.make_request(method, params)  # type: ignore[arg-type]
        if "error" in reply:
            raise ChainError(f"{method} failed: {reply['error']}")
        return reply.get("result")

    def use_wall_clock(self) -> None:
        """Stops the fixed block interval, so new blocks follow the host clock from the chain time reached so far.
        For the local demonstration, where delays are waited out in real time."""
        self._call("anvil_removeBlockTimestampInterval", [])

    def snapshot(self) -> str:
        return str(self._call("evm_snapshot", []))

    def revert(self, snapshot_id: str) -> None:
        if self._call("evm_revert", [snapshot_id]) is not True:
            raise ChainError(f"could not revert to snapshot {snapshot_id}")

    def latest_time(self) -> int:
        return int(self._w3.eth.get_block("latest")["timestamp"])

    def advance(self, seconds: int) -> None:
        """Mines a block ``seconds`` after the latest one, or one block interval after it if that is later."""
        if seconds < 0:
            raise ValueError("chain time only moves forward")
        if seconds > self._interval:
            self._call("evm_setNextBlockTimestamp", [self.latest_time() + seconds])
        self._call("evm_mine", [])

    def set_balance(self, address: str, wei: int) -> None:
        self._call("anvil_setBalance", [Web3.to_checksum_address(address), hex(wei)])
