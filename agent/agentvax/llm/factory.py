"""Builds the hosted language model from configuration.

Only providers listed in ``llm/providers.json`` are accepted. The factory never returns ``MockLLM``.
"""

from __future__ import annotations

import httpx
from pydantic import SecretStr

from agentvax.config import LlmConfig
from agentvax.llm.hosted import HostedModel, HostedModelConfig
from agentvax.resources import read_text
from agentvax.types import Strict


class ProviderSettings(Strict):
    default_base_url: str | None


class ProviderTable(Strict):
    providers: dict[str, ProviderSettings]


class UnsupportedProvider(ValueError):
    """The configuration names a provider this build does not support, or lacks a needed value."""


def _providers() -> dict[str, ProviderSettings]:
    return ProviderTable.model_validate_json('{"providers": ' + read_text("llm/providers.json") + "}").providers


def build(config: LlmConfig, api_key: SecretStr, transport: httpx.BaseTransport | None = None) -> HostedModel:
    """The hosted model for ``config``. ``transport`` replaces the network in tests."""
    providers = _providers()
    settings = providers.get(config.provider)
    if settings is None:
        raise UnsupportedProvider(f"provider {config.provider!r} is not supported; use one of {sorted(providers)}")
    base_url = config.base_url or settings.default_base_url
    if not base_url:
        raise UnsupportedProvider(f"provider {config.provider!r} needs LLM_BASE_URL")
    if not api_key.get_secret_value():
        raise UnsupportedProvider("the model API key is empty")
    hosted = HostedModelConfig(
        base_url=base_url,
        model=config.model,
        api_key=api_key,
        timeout=config.timeout_seconds,
        temperature=config.temperature,
    )
    return HostedModel(hosted, transport=transport)
