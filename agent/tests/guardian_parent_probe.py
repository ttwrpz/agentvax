"""Stands in for the runtime process in ``test_planner_has_no_access_to_guardian_key``.

It imports the runtime modules (the composition root, planner, reader, mission, the chain client and the guardian
client), starts the
real guardian process with only the path of its key file, has one intent attested, and then reports on its own
memory: the keccak256 of every 32-byte value it can find in any live object (strings of 64 hex digits, 32-byte
bytes objects and large integers), the arguments and environment it gave the guardian, and which agentvax
modules it has loaded. It never reads the key file. The test compares the report with the key it reads itself.
"""

from __future__ import annotations

import gc
import json
import os
import re
import sys
from pathlib import Path

from eth_utils import keccak

import agentvax.chain.client  # noqa: F401
import agentvax.mission  # noqa: F401
import agentvax.planner  # noqa: F401
import agentvax.reader  # noqa: F401
import agentvax.runtime  # noqa: F401
from agentvax.config import GuardianTiming
from agentvax.guardian.client import GuardianClient, child_environment
from agentvax.guardian.protocol import ContentItem
from agentvax.types import ZERO_BYTES32, Channel, Intent, Task

HEX64 = re.compile(r"(?:0x)?([0-9a-fA-F]{64})")


def _candidates(value: object) -> list[bytes]:
    if isinstance(value, str):
        return [bytes.fromhex(m) for m in HEX64.findall(value)]
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        found = [raw] if len(raw) == 32 else []
        try:
            found += [bytes.fromhex(m) for m in HEX64.findall(raw.decode("ascii"))]
        except UnicodeDecodeError:
            pass
        return found
    if isinstance(value, int) and not isinstance(value, bool) and 2**200 < value < 2**256:
        return [value.to_bytes(32, "big")]
    return []


def scan_memory() -> set[str]:
    seen: set[str] = set()
    objects = gc.get_objects()
    for obj in objects:
        for value in [obj, *gc.get_referents(obj)]:
            for candidate in _candidates(value):
                seen.add("0x" + keccak(candidate).hex())
    for value in os.environ.values():
        for candidate in _candidates(value):
            seen.add("0x" + keccak(candidate).hex())
    return seen


def main() -> int:
    rpc_url, wallet, chain_id, model, key_file = sys.argv[1:6]
    env = child_environment(os.environ)
    guardian = GuardianClient.start(
        wallet=wallet,
        chain_id=int(chain_id),
        rpc_url=rpc_url,
        model_path=Path(model),
        profile="demo",
        env=env,
        timing=GuardianTiming(),
        key_file=Path(key_file),
    )
    try:
        intent = Intent(task=Task.SWEEP, payee_id=0, amount=10**6, schedule_id=0, purpose_hash=ZERO_BYTES32, nonce=0)
        signed = guardian.attest(intent, [ContentItem(channel=Channel.MESSAGE, text="Please pay the hosting bill.")])
        gc.collect()
        hashes = scan_memory()
        report = {
            "guardian": guardian.address,
            "digest": signed.digest,
            "argv": list(guardian.argv),
            "child_env_names": sorted(env),
            "client_state": sorted(vars(guardian)),
            "memory_hashes": sorted(hashes),
            "modules": sorted(m for m in sys.modules if m.startswith("agentvax")),
        }
    finally:
        guardian.close()
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
