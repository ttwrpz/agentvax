"""Progress of an evidence run, kept in a state file so that a failed run continues where it stopped.

A step is recorded only after its receipts came back with status 1 and is never repeated. The file is written
atomically after every step and holds hashes, addresses and numbers, never a key.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field
from web3.types import TxReceipt

from agentvax.chain.deploy import Deployment
from agentvax.types import Bytes32, Strict

STATE_FORMAT = 1


class RowFailed(RuntimeError):
    """A row could not be produced. Names the row. Nothing is recorded for it."""

    def __init__(self, row: str, reason: str) -> None:
        self.row = row
        self.reason = reason
        super().__init__(f"{row}: {reason}")


class StepRecord(Strict):
    """The mined transactions of one step and the values the later steps need (ids, chain times, addresses)."""

    hashes: tuple[Bytes32, ...]
    values: dict[str, int | str]


class RowRecord(Strict):
    """The transactions that evidence one row, and the numbers its description in ``docs/EVIDENCE.md`` names."""

    hashes: tuple[Bytes32, ...]
    details: dict[str, str]


class RunState(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    format: Literal[1]
    chain_id: int
    profile: Annotated[str, Field(min_length=1)]
    agent_model: Annotated[str, Field(min_length=1)]
    deployment: Deployment | None = None
    steps: dict[str, StepRecord] = Field(default_factory=dict)
    rows: dict[str, RowRecord] = Field(default_factory=dict)


def receipt_hash(receipt: TxReceipt) -> str:
    """The hash of a mined, successful transaction. Raises if the receipt does not show status 1."""
    tx_hash = "0x" + bytes(receipt["transactionHash"]).hex()
    if int(receipt["status"]) != 1:
        raise RuntimeError(f"transaction {tx_hash} did not succeed")
    return tx_hash


class StateStore:
    """Reads and atomically writes one state file."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def exists(self) -> bool:
        return self.path.is_file()

    def load(self) -> RunState:
        return RunState.model_validate_json(self.path.read_text(encoding="utf-8"))

    def save(self, state: RunState) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(self.path.name + ".partial")
        temporary.write_text(json.dumps(state.model_dump(mode="json"), indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, self.path)


class Progress:
    """The steps and rows recorded so far, saved after every change.

    ``verify`` is called with the hashes of every step and row before they are recorded. It raises unless each one
    is a transaction mined with status 1 on the chain the run is connected to, so nothing is recorded on the word
    of the code that sent it alone.
    """

    def __init__(self, store: StateStore, state: RunState, verify: Callable[[Iterable[str]], None]) -> None:
        self._store = store
        self._verify = verify
        self.state = state

    def save(self) -> None:
        self._store.save(self.state)

    def done(self, key: str) -> bool:
        return key in self.state.steps

    def record(self, key: str) -> StepRecord:
        return self.state.steps[key]

    def step(self, key: str, action: Callable[[], StepRecord]) -> StepRecord:
        """The record of step ``key``: the stored one, or the result of ``action``, which is stored at once."""
        if key in self.state.steps:
            return self.state.steps[key]
        record = action()
        self._verify(record.hashes)
        self.state.steps[key] = record
        self.save()
        return record

    def row_done(self, row: str) -> bool:
        return row in self.state.rows

    def complete_row(self, row: str, hashes: list[str], details: dict[str, str]) -> None:
        if not hashes:
            raise RowFailed(row, "the row produced no transaction")
        self._verify(hashes)
        self.state.rows[row] = RowRecord(hashes=tuple(hashes), details=details)
        self.save()

    def set_deployment(self, deployment: Deployment) -> None:
        self.state.deployment = deployment
        self.save()

    def every_hash(self) -> list[str]:
        """Every hash recorded in a step or a row, each once, in the order first recorded."""
        seen: dict[str, None] = {}
        for record in self.state.steps.values():
            seen.update(dict.fromkeys(record.hashes))
        for row in self.state.rows.values():
            seen.update(dict.fromkeys(row.hashes))
        return list(seen)
