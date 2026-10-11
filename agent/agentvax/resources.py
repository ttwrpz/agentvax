"""Reading of the data files that ship inside the package.

Every module reads its data files through these functions. Paths are given relative to the ``agentvax`` package
with forward slashes, for example ``"profiles/default.json"``. Files are located with ``importlib.resources``, so
they are found however the package is installed.
"""

from __future__ import annotations

import json
from importlib.resources import files
from importlib.resources.abc import Traversable
from pathlib import Path
from typing import Any, TypeVar

from pydantic import BaseModel

M = TypeVar("M", bound=BaseModel)


class ResourceMissing(FileNotFoundError):
    """A data file is not part of the package."""


def _resource(relative_path: str) -> Traversable:
    parts = [p for p in relative_path.split("/") if p]
    if not parts or any(p in (".", "..") for p in parts):
        raise ResourceMissing(f"invalid resource path {relative_path!r}")
    resource = files("agentvax").joinpath(*parts)
    if not resource.is_file():
        raise ResourceMissing(f"no packaged file {relative_path}")
    return resource


def exists(relative_path: str) -> bool:
    try:
        _resource(relative_path)
    except ResourceMissing:
        return False
    return True


def list_dir(relative_path: str) -> tuple[str, ...]:
    """Names of the files in a packaged directory, sorted."""
    directory = files("agentvax").joinpath(*[p for p in relative_path.split("/") if p])
    return tuple(sorted(entry.name for entry in directory.iterdir() if entry.is_file()))


def read_text(relative_path: str) -> str:
    return _resource(relative_path).read_text(encoding="utf-8")


def read_bytes(relative_path: str) -> bytes:
    return _resource(relative_path).read_bytes()


def read_json(relative_path: str) -> Any:
    """Parse a packaged JSON file."""
    return json.loads(read_text(relative_path))


def load_model(model: type[M], relative_path: str) -> M:
    """Validate a packaged data file against a model. JSON text is parsed by pydantic so that arrays become
    tuples under strict models."""
    return model.model_validate_json(read_text(relative_path))


def file_path(relative_path: str) -> Path:
    """A filesystem path of a packaged file, for handing to another process.

    Raises ``ResourceMissing`` if the package is not installed as plain files.
    """
    resource = _resource(relative_path)
    if not isinstance(resource, Path):
        raise ResourceMissing(f"{relative_path} is not available as a plain file")
    return resource
