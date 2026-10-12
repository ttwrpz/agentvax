"""The hosted adapter, exercised through httpx.MockTransport so that no test touches the network."""

from __future__ import annotations

import json

import httpx
import pytest
from pydantic import SecretStr

from agentvax.llm.base import LLMError, Message, MessageRole, Role
from agentvax.llm.hosted import HostedModel, HostedModelConfig
from agentvax.reader import ReaderReading

SECRET = "sk-test-secret-value"
MESSAGES = [Message(role=MessageRole.SYSTEM, content="read"), Message(role=MessageRole.USER, content="{}")]
REPLY = {"document_kind": 1, "payee_index": 0, "amount": 5, "due": None, "flags": 4}


def _model(handler) -> HostedModel:
    config = HostedModelConfig(
        base_url="https://llm.example/v1/", model="test-model", api_key=SecretStr(SECRET), timeout=5.0, temperature=0.0
    )
    return HostedModel(config, transport=httpx.MockTransport(handler))


def _ok(body: dict) -> httpx.Response:
    return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(body)}}]})


def test_hosted_model_sends_schema_and_validates_reply() -> None:
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers["authorization"]
        seen["body"] = json.loads(request.content)
        return _ok(REPLY)

    reading = _model(handler).complete(Role.READER, MESSAGES, ReaderReading)
    assert reading.amount == 5 and reading.flags == 4
    assert seen["url"] == "https://llm.example/v1/chat/completions"
    assert seen["auth"] == f"Bearer {SECRET}"
    assert SECRET not in json.dumps(seen["body"])
    assert seen["body"]["response_format"]["type"] == "json_schema"
    assert seen["body"]["messages"][1] == {"role": "user", "content": "{}"}


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(500, json={"error": "down"}),
        httpx.Response(200, text="not json"),
        httpx.Response(200, json={"choices": []}),
        httpx.Response(200, json={"choices": [{"message": {"content": "not json"}}]}),
        httpx.Response(200, json={"choices": [{"message": {"content": None, "refusal": "no"}}]}),
        _ok({**REPLY, "extra": "field"}),
        _ok({**REPLY, "flags": 9999}),
    ],
)
def test_hosted_model_fails_closed(response: httpx.Response) -> None:
    with pytest.raises(LLMError):
        _model(lambda request: response).complete(Role.READER, MESSAGES, ReaderReading)


def test_hosted_model_reports_a_transport_error_as_llm_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    with pytest.raises(LLMError):
        _model(handler).complete(Role.READER, MESSAGES, ReaderReading)


def test_the_key_is_not_shown_by_the_config() -> None:
    config = HostedModelConfig(base_url="https://x", model="m", api_key=SecretStr(SECRET), timeout=1.0, temperature=0.0)
    assert SECRET not in repr(config) and SECRET not in config.model_dump_json()


def test_build_makes_the_hosted_model_from_configuration() -> None:
    from agentvax.config import LlmConfig
    from agentvax.harness.mock_llm import MockLLM
    from agentvax.llm import UnsupportedProvider, build

    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        seen["timeout"] = request.extensions["timeout"]
        return _ok(REPLY)

    config = LlmConfig(
        provider="openai-compatible", model="m-1", base_url="https://llm.example/v1", timeout_seconds=7.5, temperature=0.2
    )
    model = build(config, SecretStr(SECRET), transport=httpx.MockTransport(handler))
    assert not isinstance(model, MockLLM)
    assert model.complete(Role.READER, MESSAGES, ReaderReading).amount == 5
    assert seen["url"] == "https://llm.example/v1/chat/completions"
    assert seen["body"]["model"] == "m-1" and seen["body"]["temperature"] == 0.2
    assert seen["timeout"]["read"] == 7.5

    for bad in (
        config.model_copy(update={"provider": "anthropic"}),
        config.model_copy(update={"provider": "mock"}),
        config.model_copy(update={"base_url": None}),
    ):
        with pytest.raises(UnsupportedProvider):
            build(bad, SecretStr(SECRET))
    with pytest.raises(UnsupportedProvider):
        build(config, SecretStr(""))
