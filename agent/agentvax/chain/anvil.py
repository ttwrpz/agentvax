"""A local Anvil node owned by this process, and the Foundry executables.

Used by the local self-test of the evidence run. Anvil listens on loopback only and ``stop`` always ends it.
Control calls fund a fresh key and move chain time forward.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

from eth_utils import to_checksum_address
from web3 import Web3

LOCAL_CHAIN_ID = 31337
"""The only chain id a local node may have. Anvil's default, and one of ``ALLOWED_CHAIN_IDS``."""


class LocalNodeError(RuntimeError):
    """Anvil could not be found, did not start, or refused a control call."""


def foundry_executable(name: str) -> str:
    """Path of Foundry executable ``name``: on PATH, or in Foundry's default install directory ``~/.foundry/bin``."""
    found = shutil.which(name)
    if found:
        return found
    for candidate in (Path.home() / ".foundry" / "bin" / f"{name}.exe", Path.home() / ".foundry" / "bin" / name):
        if candidate.is_file():
            return str(candidate)
    raise LocalNodeError(f"{name} was not found on PATH or in ~/.foundry/bin. Install Foundry.")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def control_call(rpc_url: str, method: str, params: list[Any], timeout: float) -> Any:
    """One Anvil control call on the node at ``rpc_url``. Raises ``LocalNodeError`` when the node refuses it."""
    w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": timeout}))
    reply = w3.provider.make_request(method, params)  # type: ignore[arg-type]
    if "error" in reply:
        raise LocalNodeError(f"{method} failed: {reply['error']}")
    return reply.get("result")


class LocalNode:
    """A running Anvil with chain id 31337 on the loopback interface."""

    def __init__(self, process: subprocess.Popen[bytes] | None, rpc_url: str, timeout: float) -> None:
        self._process = process
        self.rpc_url = rpc_url
        self._timeout = timeout

    @classmethod
    def start(cls, anvil_executable: str, startup_seconds: float, rpc_timeout: float) -> LocalNode:
        """Starts Anvil on a free local port and waits until it answers. Stops it again if it does not."""
        port = _free_port()
        process = subprocess.Popen(
            [
                anvil_executable,
                "--port",
                str(port),
                "--chain-id",
                str(LOCAL_CHAIN_ID),
                "--host",
                "127.0.0.1",
                "--silent",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        node = cls(process, f"http://127.0.0.1:{port}", rpc_timeout)
        deadline = time.monotonic() + startup_seconds
        try:
            while not node._answers():
                if process.poll() is not None:
                    raise LocalNodeError("anvil exited during startup")
                if time.monotonic() > deadline:
                    raise LocalNodeError("anvil did not start in time")
                time.sleep(0.1)
            return node
        except BaseException:
            node.stop()
            raise

    @classmethod
    def attach(cls, rpc_url: str, rpc_timeout: float) -> LocalNode:
        """A node started by someone else. ``stop`` leaves it running. Its chain id must be 31337."""
        node = cls(None, rpc_url, rpc_timeout)
        chain_id = int(Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": rpc_timeout})).eth.chain_id)
        if chain_id != LOCAL_CHAIN_ID:
            raise LocalNodeError(f"the local node reports chain id {chain_id}, expected {LOCAL_CHAIN_ID}")
        return node

    def _answers(self) -> bool:
        try:
            return bool(Web3(Web3.HTTPProvider(self.rpc_url, request_kwargs={"timeout": 2})).is_connected())
        except OSError:
            return False

    def stop(self) -> None:
        """Ends a node this object started. A node it attached to is left running."""
        if self._process is not None and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=10)

    def set_balance(self, address: str, wei: int) -> None:
        control_call(self.rpc_url, "anvil_setBalance", [to_checksum_address(address), hex(wei)], self._timeout)

    def advance_to(self, chain_time: int) -> None:
        """Mines a block with a timestamp of at least ``chain_time``. Chain time never moves backwards."""
        w3 = Web3(Web3.HTTPProvider(self.rpc_url, request_kwargs={"timeout": self._timeout}))
        latest = int(w3.eth.get_block("latest")["timestamp"])
        if chain_time > latest:
            control_call(self.rpc_url, "evm_setNextBlockTimestamp", [chain_time], self._timeout)
        control_call(self.rpc_url, "evm_mine", [], self._timeout)
