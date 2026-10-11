"""Interface wording. Every sentence a user reads is a template in ``api/static/strings.json``."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from agentvax.resources import read_json

STRINGS_PATH = "api/static/strings.json"


class StringsError(KeyError):
    """A template is missing or a placeholder has no value."""


class Strings:
    """An immutable table of templates, filled in with ``str.format_map``."""

    def __init__(self, table: Mapping[str, str]) -> None:
        self._table: Mapping[str, str] = MappingProxyType(dict(table))

    @classmethod
    def load(cls) -> Strings:
        raw = read_json(STRINGS_PATH)
        return cls({str(key): str(value) for key, value in raw.items()})

    def table(self) -> dict[str, str]:
        """A copy of every template, keyed by identifier. The interface serves it to the page."""
        return dict(self._table)

    def has(self, key: str) -> bool:
        return key in self._table

    def render(self, key: str, **params: object) -> str:
        template = self._table.get(key)
        if template is None:
            raise StringsError(f"no template named {key}")
        try:
            return template.format_map(params)
        except KeyError as missing:
            raise StringsError(f"template {key} needs {missing}") from missing


_DURATION_UNITS = ((86_400, "day"), (3_600, "hour"), (60, "minute"), (1, "second"))


def describe_duration(strings: Strings, seconds: int) -> str:
    """"3600" becomes "1 hour". The largest unit that divides the value exactly is used."""
    for size, unit in _DURATION_UNITS:
        if seconds >= size and seconds % size == 0:
            count = seconds // size
            return strings.render(f"duration.{unit}.{'one' if count == 1 else 'other'}", count=count)
    return strings.render("duration.second.other", count=seconds)
