"""Helper keys of an evidence run, kept in the git-ignored ``secrets/`` directory.

Keys are generated on first need, written once with exclusive create and read back on later runs. Guardian keys are
created inside the guardian process, so this process only keeps their addresses. No key is printed or logged.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from pathlib import Path

from eth_account import Account
from eth_account.signers.local import LocalAccount
from eth_utils import to_checksum_address

from agentvax.config import GuardianTiming
from agentvax.guardian.client import GuardianClient

_NAME = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_GUARDIAN_LABEL = re.compile(r"^[A-Z][A-Za-z0-9]{0,15}$")


class KeyStoreError(RuntimeError):
    """A key file is missing, malformed, or exists without the record that belongs to it."""


def _write_once(path: Path, text: str) -> None:
    """Creates ``path`` with ``text``. Fails if it exists. Readable by the user only where the system enforces it."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        handle.write(text)


class KeyStore:
    """The helper and guardian keys of one evidence run, in ``directory``."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def _ensure_directory(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)

    def helper_key_file(self, name: str) -> Path:
        """Where the helper key ``name`` is kept. Only names the path: nothing is read or created."""
        if not _NAME.match(name):
            raise ValueError(f"invalid helper key name {name!r}")
        return self.directory / f"{name}.key"

    def agent_key_file(self, label: str) -> Path:
        """Where the agent key of wallet ``label`` is kept. Only names the path."""
        if not _GUARDIAN_LABEL.match(label):
            raise ValueError(f"invalid wallet label {label!r}")
        return self.helper_key_file(f"agent_{label.lower()}")

    def agent(self, label: str) -> LocalAccount:
        """The agent key of wallet ``label``, generated and saved the first time."""
        return self.helper(self.agent_key_file(label).stem)

    def helper(self, name: str) -> LocalAccount:
        """The helper key ``name``, generated and saved the first time."""
        path = self.helper_key_file(name)
        self._ensure_directory()
        if not path.exists():
            account: LocalAccount = Account.create()
            _write_once(path, account.key.hex())
            return account
        try:
            loaded: LocalAccount = Account.from_key(path.read_text(encoding="ascii").strip())
        except Exception:
            raise KeyStoreError(f"helper key file {path} is not a valid private key") from None
        return loaded

    def has_helper(self, name: str) -> bool:
        return (self.directory / f"{name}.key").is_file()

    def guardian_key_file(self, label: str) -> Path:
        if not _GUARDIAN_LABEL.match(label):
            raise ValueError(f"invalid wallet label {label!r}")
        return self.directory / f"guardian_{label}.key"

    def _guardian_address_file(self, label: str) -> Path:
        return self.directory / f"guardian_{label}.address"

    def guardian_address(self, label: str) -> str | None:
        """The recorded address of wallet ``label``'s guardian, or None if no guardian key was created."""
        key_file, address_file = self.guardian_key_file(label), self._guardian_address_file(label)
        if address_file.is_file():
            if not key_file.is_file():
                raise KeyStoreError(f"guardian address recorded for wallet {label} but its key file is missing")
            return to_checksum_address(address_file.read_text(encoding="ascii").strip())
        if key_file.is_file():
            raise KeyStoreError(
                f"guardian key file {key_file} exists without its address record. Remove it to create a new one."
            )
        return None

    def create_guardian(self, label: str, env: Mapping[str, str], timing: GuardianTiming) -> str:
        """The address of wallet ``label``'s guardian, creating its key in a guardian process the first time."""
        existing = self.guardian_address(label)
        if existing is not None:
            return existing
        self._ensure_directory()
        address = to_checksum_address(GuardianClient.create_key_file(self.guardian_key_file(label), env, timing))
        _write_once(self._guardian_address_file(label), address)
        return address
