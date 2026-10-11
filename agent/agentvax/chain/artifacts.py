"""Foundry build artifacts, read at runtime from ``contracts/out``.

An artifact is found by fully qualified name and checked against its compilation target. If it is missing or a
source changed since the build, ``forge build`` runs once.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from eth_utils import keccak
from pydantic import BaseModel, ConfigDict


class ArtifactError(RuntimeError):
    """An artifact is missing, malformed or does not match the requested contract."""


class LinkReference(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    start: int
    length: int


class Artifact(BaseModel):
    """One compiled contract. ``bytecode`` may contain library placeholders listed in ``link_references``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    fqn: str
    abi: tuple[dict[str, Any], ...]
    bytecode: str
    deployed_bytecode: str
    link_references: dict[str, tuple[LinkReference, ...]]
    """Placeholder positions in ``bytecode`` (byte offsets), keyed by the library's fully qualified name."""
    deployed_link_references: dict[str, tuple[LinkReference, ...]]
    immutable_references: tuple[LinkReference, ...]
    """Positions in ``deployed_bytecode`` the constructor fills with immutable values."""

    @property
    def name(self) -> str:
        return self.fqn.split(":", 1)[1]


def _flatten_links(raw: dict[str, dict[str, list[dict[str, int]]]]) -> dict[str, tuple[LinkReference, ...]]:
    out: dict[str, tuple[LinkReference, ...]] = {}
    for source, libraries in raw.items():
        for library, refs in libraries.items():
            out[f"{source}:{library}"] = tuple(LinkReference(**r) for r in refs)
    return out


class ArtifactStore:
    """Reads artifacts from ``artifacts_dir``, building with forge in ``contracts_dir`` when needed."""

    def __init__(self, contracts_dir: Path, artifacts_dir: Path, forge_executable: str) -> None:
        self._contracts_dir = contracts_dir
        self._artifacts_dir = artifacts_dir
        self._forge = forge_executable
        self._built_this_session = False
        self._cache: dict[str, Artifact] = {}

    def load(self, fqn: str) -> Artifact:
        """Artifact for ``fqn``, for example ``src/PolicyWallet.sol:PolicyWallet``."""
        if fqn in self._cache:
            return self._cache[fqn]
        raw = self._read(fqn)
        if raw is None or not self._is_fresh(raw):
            self.build()
            raw = self._read(fqn)
            if raw is None:
                raise ArtifactError(f"forge build produced no artifact for {fqn}")
        artifact = self._parse(fqn, raw)
        self._cache[fqn] = artifact
        return artifact

    def build(self) -> None:
        """Runs ``forge build`` once per store. Raises ``ArtifactError`` if compilation fails."""
        if self._built_this_session:
            return
        try:
            result = subprocess.run(
                [self._forge, "build"],
                cwd=self._contracts_dir,
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError as exc:
            raise ArtifactError(f"forge executable {self._forge!r} not found") from exc
        if result.returncode != 0:
            raise ArtifactError(f"forge build failed:\n{result.stdout}\n{result.stderr}")
        self._built_this_session = True
        self._cache.clear()

    def _path(self, fqn: str) -> Path:
        if ":" not in fqn:
            raise ArtifactError(f"{fqn!r} is not a fully qualified name")
        source, name = fqn.split(":", 1)
        return self._artifacts_dir / Path(source).name / f"{name}.json"

    def _read(self, fqn: str) -> dict[str, Any] | None:
        path = self._path(fqn)
        if not path.is_file():
            return None
        raw: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        source, name = fqn.split(":", 1)
        target = raw.get("metadata", {}).get("settings", {}).get("compilationTarget", {})
        if target != {source: name}:
            raise ArtifactError(f"artifact {path} is for {target}, not {fqn}")
        return raw

    def _is_fresh(self, raw: dict[str, Any]) -> bool:
        """True if every source the artifact was compiled from still has the recorded keccak256."""
        sources: dict[str, dict[str, Any]] = raw.get("metadata", {}).get("sources", {})
        for rel, info in sources.items():
            path = self._contracts_dir / rel
            if not path.is_file():
                return False
            if "0x" + keccak(path.read_bytes()).hex() != info.get("keccak256"):
                return False
        return bool(sources)

    @staticmethod
    def _parse(fqn: str, raw: dict[str, Any]) -> Artifact:
        try:
            immutables = tuple(
                LinkReference(**ref)
                for refs in raw["deployedBytecode"].get("immutableReferences", {}).values()
                for ref in refs
            )
            return Artifact(
                fqn=fqn,
                abi=tuple(raw["abi"]),
                bytecode=raw["bytecode"]["object"],
                deployed_bytecode=raw["deployedBytecode"]["object"],
                link_references=_flatten_links(raw["bytecode"].get("linkReferences", {})),
                deployed_link_references=_flatten_links(raw["deployedBytecode"].get("linkReferences", {})),
                immutable_references=immutables,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ArtifactError(f"malformed artifact for {fqn}: {exc}") from exc
