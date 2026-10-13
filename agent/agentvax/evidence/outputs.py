"""The files an evidence run writes, and the check that every hash in them is a successful transaction.

Outputs are the deployment file, ``evidence/hashes.json`` and ``docs/EVIDENCE.md``. The last two are written
only when every row is done and every hash was read back from the chain with status 1.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentvax.chain.client import ChainClient
from agentvax.chain.deploy import Deployment
from agentvax.evidence.plan import ROW_IDS, EvidenceText
from agentvax.evidence.state import RunState

SETUP_STEP_ORDER = ("fund", "mandates", "payees_proposed", "payees_applied", "tokens", "agent_funding")


class EvidenceUnverified(RuntimeError):
    """A recorded hash is not a successful transaction on the chain the run is connected to."""


@dataclass(frozen=True)
class OutputPaths:
    deployment: Path
    hashes: Path
    document: Path

    def remove_evidence(self) -> None:
        """Removes the hashes file and the evidence document, which describe a deployment no longer in use."""
        for path in (self.hashes, self.document):
            if path.is_file():
                path.unlink()


def verify_hashes(client: ChainClient, hashes: Iterable[str]) -> None:
    """Every hash must have a receipt with status 1 on the connected chain. Raises ``EvidenceUnverified``."""
    for tx_hash in hashes:
        try:
            receipt = client.web3.eth.get_transaction_receipt(tx_hash)  # type: ignore[arg-type]
        except Exception as exc:
            raise EvidenceUnverified(f"transaction {tx_hash} has no receipt on chain {client.chain_id}") from exc
        if int(receipt["status"]) != 1:
            raise EvidenceUnverified(f"transaction {tx_hash} did not succeed on chain {client.chain_id}")


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".partial")
    temporary.write_text(text, encoding="utf-8")
    os.replace(temporary, path)


def write_deployment(path: Path, deployment: Deployment, extra: Mapping[str, Any]) -> None:
    data = deployment.to_file_dict()
    data["evidence"] = dict(extra)
    _write(path, json.dumps(data, indent=2) + "\n")


def hashes_document(state: RunState) -> dict[str, list[str]]:
    missing = [row for row in ROW_IDS if row not in state.rows]
    if missing:
        raise EvidenceUnverified(f"rows {', '.join(missing)} are not done")
    return {row: list(state.rows[row].hashes) for row in ROW_IDS}


def _link(explorer: str | None, kind: str, value: str) -> str:
    if explorer is None:
        return f"`{value}`"
    return f"[{value}]({explorer}/{kind}/{value})"


def evidence_markdown(
    state: RunState,
    text: EvidenceText,
    intro_values: Mapping[str, object],
    explorer: str | None,
    setup: Mapping[str, list[str]],
) -> str:
    """The evidence document. Every sentence comes from ``text``. Every hash of every row is in the table."""
    if state.deployment is None:
        raise EvidenceUnverified("the run has no deployment")
    lines = [text.title, ""]
    for sentence in text.intro:
        lines += [sentence.format_map(dict(intro_values)), ""]

    lines += [text.contracts_heading, "", f"| {text.contracts_columns[0]} | {text.contracts_columns[1]} |", "|---|---|"]
    for name, address in state.deployment.to_file_dict()["contracts"].items():
        lines.append(f"| {name} | {_link(explorer, 'address', address)} |")
    lines.append("")

    columns = text.rows_columns
    lines += [text.rows_heading, "", f"| {columns[0]} | {columns[1]} | {columns[2]} |", "|---|---|---|"]
    for row in ROW_IDS:
        record = state.rows[row]
        description = text.rows[row].format_map(dict(record.details))
        links = "<br>".join(_link(explorer, "tx", h) for h in record.hashes)
        lines.append(f"| {row} | {description} | {links} |")
    lines.append("")

    steps = [(key, setup[key]) for key in SETUP_STEP_ORDER if setup.get(key)]
    if steps:
        lines += [text.setup_heading, "", text.setup_intro, ""]
        lines += [f"| {text.setup_columns[0]} | {text.setup_columns[1]} |", "|---|---|"]
        for key, hashes in steps:
            links = "<br>".join(_link(explorer, "tx", h) for h in hashes)
            lines.append(f"| {text.setup_steps[key]} | {links} |")
        lines.append("")
    return "\n".join(lines)


def write_evidence(
    paths: OutputPaths,
    client: ChainClient,
    state: RunState,
    text: EvidenceText,
    intro_values: Mapping[str, object],
    explorer: str | None,
    setup: Mapping[str, list[str]],
) -> None:
    """Verifies every hash of every row and setup step on chain, then writes the document and, last, the hashes
    file, which is the file that claims the evidence is complete."""
    hashes = hashes_document(state)
    verify_hashes(client, [h for row in hashes.values() for h in row])
    verify_hashes(client, [h for step in setup.values() for h in step])
    _write(paths.document, evidence_markdown(state, text, intro_values, explorer, setup))
    _write(paths.hashes, json.dumps(hashes, indent=2) + "\n")
