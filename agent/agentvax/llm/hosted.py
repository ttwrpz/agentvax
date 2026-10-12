"""Adapter for an OpenAI-compatible chat completions endpoint with JSON-schema output."""

from __future__ import annotations

from collections.abc import Sequence

import httpx
from pydantic import Field, SecretStr, ValidationError

from agentvax.llm.base import LLMError, Message, Role, T
from agentvax.types import Strict


class HostedModelConfig(Strict):
    base_url: str = Field(min_length=1)
    model: str = Field(min_length=1)
    api_key: SecretStr
    timeout: float = Field(gt=0)
    temperature: float = Field(ge=0.0, le=2.0)


class HostedModel:
    """Sends one request per call. The key is read from the config object and goes only into the header."""

    def __init__(self, config: HostedModelConfig, transport: httpx.BaseTransport | None = None) -> None:
        self._config = config
        self._client = httpx.Client(timeout=config.timeout, transport=transport)

    def close(self) -> None:
        self._client.close()

    def complete(self, role: Role, messages: Sequence[Message], schema: type[T]) -> T:
        payload = {
            "model": self._config.model,
            "temperature": self._config.temperature,
            "messages": [{"role": m.role.value, "content": m.content} for m in messages],
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": f"{role.value}_reply", "schema": schema.model_json_schema()},
            },
        }
        url = self._config.base_url.rstrip("/") + "/chat/completions"
        headers = {"Authorization": f"Bearer {self._config.api_key.get_secret_value()}"}
        try:
            response = self._client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            body = response.json()
            message = body["choices"][0]["message"]
            content = message.get("content")
            if not isinstance(content, str) or message.get("refusal"):
                raise LLMError("the model gave no usable content")
            return schema.model_validate_json(content)
        except LLMError:
            raise
        except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError, ValidationError) as error:
            raise LLMError(f"model call failed: {type(error).__name__}") from error
