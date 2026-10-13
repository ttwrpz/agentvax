"""Where the evidence run keeps what it produces. This module only names paths.

The deployment goes to ``deployments/testnet.json``. Keys, the released model and run progress go under
the git-ignored ``secrets/evidence/<chain id>/``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from agentvax.detector.model import MODEL_FILE

KEYS_DIRECTORY = "keys"
STATE_FILE = "state.json"


def testnet_deployment_file(repo_root: Path) -> Path:
    """The deployment record of the evidence run on the configured public test network."""
    return repo_root / "deployments" / "testnet.json"


def testnet_work_directory(repo_root: Path, chain_id: int) -> Path:
    """The ignored work directory of the evidence run on chain ``chain_id``."""
    return repo_root / "secrets" / "evidence" / str(chain_id)


@dataclass(frozen=True)
class WorkLayout:
    """The files inside one evidence work directory."""

    directory: Path

    @property
    def keys(self) -> Path:
        return self.directory / KEYS_DIRECTORY

    @property
    def model(self) -> Path:
        """The detector model the run released and anchored in E14."""
        return self.directory / MODEL_FILE

    @property
    def state(self) -> Path:
        return self.directory / STATE_FILE
