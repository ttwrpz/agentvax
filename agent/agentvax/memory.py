"""Structured memory.

A closed schema of enums, bounded numbers, hashes, timestamps and on-chain identifiers. Only deterministic code
writes it, through the methods below. No method accepts free text, so no prompt, document or conversation can be
stored. Any fact read from here that shapes an intent makes the validator set MEMORY_SOURCED.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Annotated

from eth_utils import keccak
from pydantic import Field

from agentvax.types import Bytes32, Channel, Family, Strict, Uint16

SCHEMA_VERSION = 1
SQLITE_INT_MAX = 2**63 - 1

MemoryAmount = Annotated[int, Field(ge=0, le=SQLITE_INT_MAX)]
MemoryTime = Annotated[int, Field(ge=0, le=SQLITE_INT_MAX)]
PayeeKey = Annotated[int, Field(ge=1, le=2**32 - 1)]


def account_hash(account: str) -> str:
    """keccak256 of the 20 address bytes. What memory keeps to recognise an account without storing it as text."""
    return "0x" + keccak(bytes.fromhex(account.removeprefix("0x"))).hex()


class MemoryStoreError(Exception):
    """The store has an unexpected schema version."""


class PayeeFact(Strict):
    """What the agent has learned about one payee from payments it saw settle."""

    payee_id: PayeeKey
    usual_amount: MemoryAmount
    last_paid: MemoryTime
    last_verified: MemoryTime
    account_hash: Bytes32


class ThreatRecord(Strict):
    """A confirmed attack, kept as its fixed features and the capsule that was published for it."""

    family: Family
    channel: Channel
    features: Uint16
    capsule_id: MemoryAmount
    observed_at: MemoryTime


_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS payee_facts ("
    " payee_id INTEGER PRIMARY KEY, usual_amount INTEGER NOT NULL, last_paid INTEGER NOT NULL,"
    " last_verified INTEGER NOT NULL, account_hash TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS threats ("
    " id INTEGER PRIMARY KEY AUTOINCREMENT, family INTEGER NOT NULL, channel INTEGER NOT NULL,"
    " features INTEGER NOT NULL, capsule_id INTEGER NOT NULL, observed_at INTEGER NOT NULL)",
)


class MemoryStore:
    """SQLite store. Pass ``":memory:"`` or a file path.

    ``shared_between_threads`` lets another thread use the connection, for a server that handles requests on a pool
    of threads. The caller must then run every use of the store one at a time, as the interface does under its
    chain lock.
    """

    def __init__(self, path: str | Path, shared_between_threads: bool = False) -> None:
        self._db = sqlite3.connect(str(path), check_same_thread=not shared_between_threads)
        with self._db:
            for statement in _SCHEMA:
                self._db.execute(statement)
            row = self._db.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
            if row is None:
                self._db.execute("INSERT INTO meta (key, value) VALUES ('schema_version', ?)", (SCHEMA_VERSION,))
        if row is not None and row[0] != SCHEMA_VERSION:
            self._db.close()
            raise MemoryStoreError(f"memory schema version {row[0]} is not {SCHEMA_VERSION}")

    def close(self) -> None:
        self._db.close()

    @property
    def schema_version(self) -> int:
        return int(self._db.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()[0])

    def record_payment(self, payee_id: int, amount: int, paid_at: int) -> None:
        """Note a payment that settled. The most recent amount becomes the usual amount."""
        fact = self.payee_fact(payee_id)
        verified = fact.last_verified if fact else 0
        digest = fact.account_hash if fact else "0x" + "00" * 32
        self._write(
            PayeeFact(
                payee_id=payee_id, usual_amount=amount, last_paid=paid_at, last_verified=verified, account_hash=digest
            )
        )

    def record_verification(self, payee_id: int, account_hash: str, verified_at: int) -> None:
        """Note that the owner confirmed the payee's account, identified by its hash."""
        fact = self.payee_fact(payee_id)
        self._write(
            PayeeFact(
                payee_id=payee_id,
                usual_amount=fact.usual_amount if fact else 0,
                last_paid=fact.last_paid if fact else 0,
                last_verified=verified_at,
                account_hash=account_hash,
            )
        )

    def record_threat(self, record: ThreatRecord) -> None:
        with self._db:
            self._db.execute(
                "INSERT INTO threats (family, channel, features, capsule_id, observed_at) VALUES (?, ?, ?, ?, ?)",
                (int(record.family), int(record.channel), record.features, record.capsule_id, record.observed_at),
            )

    def payee_fact(self, payee_id: int) -> PayeeFact | None:
        row = self._db.execute(
            "SELECT payee_id, usual_amount, last_paid, last_verified, account_hash FROM payee_facts WHERE payee_id = ?",
            (payee_id,),
        ).fetchone()
        return PayeeFact(**dict(zip(PayeeFact.model_fields, row))) if row else None

    def payee_facts(self) -> tuple[PayeeFact, ...]:
        rows = self._db.execute(
            "SELECT payee_id, usual_amount, last_paid, last_verified, account_hash FROM payee_facts ORDER BY payee_id"
        ).fetchall()
        return tuple(PayeeFact(**dict(zip(PayeeFact.model_fields, row))) for row in rows)

    def threats(self) -> tuple[ThreatRecord, ...]:
        rows = self._db.execute(
            "SELECT family, channel, features, capsule_id, observed_at FROM threats ORDER BY id"
        ).fetchall()
        return tuple(
            ThreatRecord(family=Family(r[0]), channel=Channel(r[1]), features=r[2], capsule_id=r[3], observed_at=r[4])
            for r in rows
        )

    def column_types(self) -> Iterator[tuple[str, str, str]]:
        """Every (table, column, declared type) of the store, for schema checks."""
        tables = [
            r[0]
            for r in self._db.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            )
        ]
        for table in tables:
            for info in self._db.execute(f"PRAGMA table_info({table})"):
                yield table, info[1], info[2]

    def _write(self, fact: PayeeFact) -> None:
        with self._db:
            self._db.execute(
                "INSERT INTO payee_facts (payee_id, usual_amount, last_paid, last_verified, account_hash)"
                " VALUES (?, ?, ?, ?, ?) ON CONFLICT(payee_id) DO UPDATE SET usual_amount = excluded.usual_amount,"
                " last_paid = excluded.last_paid, last_verified = excluded.last_verified,"
                " account_hash = excluded.account_hash",
                (fact.payee_id, fact.usual_amount, fact.last_paid, fact.last_verified, fact.account_hash),
            )
