"""What code and which suite files a run used, recorded in the ledger's run record without any local absolute path.

The code revision is the commit git reports for the repository root, and whether the working tree differed from it
when the run started. The run's own output directory is left out of that comparison, because a run rewrites it.
Where git or the repository is not available, both are recorded as unknown (``None``), never guessed.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from pydantic import Field

from agentvax.types import Strict

GIT_TIMEOUT_SECONDS = 30.0
_COMMIT = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")


class CodeRevision(Strict):
    """The code a run used. ``None`` means git could not tell."""

    commit: str | None = Field(pattern=_COMMIT.pattern)
    dirty: bool | None
    """True when a tracked file differed from the commit, or an untracked file that git does not ignore was present,
    outside the run's output directory."""


def _git(repo_root: Path, *arguments: str) -> str | None:
    executable = shutil.which("git")
    if executable is None:
        return None
    try:
        done = subprocess.run(
            [executable, "-C", str(repo_root), *arguments],
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return done.stdout if done.returncode == 0 else None


def relative_to_root(path: Path, repo_root: Path) -> Path | None:
    """``path`` relative to ``repo_root``, or None when it lies outside the repository."""
    try:
        return path.resolve().relative_to(repo_root.resolve())
    except ValueError:
        return None


def code_revision(repo_root: Path, output_dir: Path) -> CodeRevision:
    """The commit at ``repo_root`` and whether the tree differs from it, ignoring ``output_dir``."""
    head = _git(repo_root, "rev-parse", "HEAD")
    commit = head.strip() if head is not None else None
    if commit is None or not _COMMIT.match(commit):
        return CodeRevision(commit=None, dirty=None)
    pathspec = ["--", "."]
    output = relative_to_root(output_dir, repo_root)
    if output is not None and output.parts:
        pathspec.append(f":(exclude){output.as_posix()}")
    status = _git(repo_root, "status", "--porcelain", "--untracked-files=normal", *pathspec)
    return CodeRevision(commit=commit, dirty=None if status is None else bool(status.strip()))


def suites_location(suites_dir: Path, repo_root: Path) -> str | None:
    """The suite directory relative to the repository root in POSIX form, or None when it lies outside the
    repository. The suite files themselves are identified by their hashes in any case."""
    relative = relative_to_root(suites_dir, repo_root)
    return None if relative is None else relative.as_posix()
