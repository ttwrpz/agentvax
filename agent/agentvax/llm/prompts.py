"""System prompts for the model roles, kept as data in ``prompts.json``."""

from __future__ import annotations

from agentvax.llm.base import Role
from agentvax.resources import read_json


def system_prompt(role: Role) -> str:
    return str(read_json("llm/prompts.json")[role.value])
