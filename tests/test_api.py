"""Synthetic request/response boundaries and safe HTTP errors; no upstream calls."""

import copy

import httpx
import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from shield.api import (
    ChatCompletionChunk,
    ChatCompletionRequest,
    ChatCompletionResponse,
)
from shield.app import create_app
from shield.contracts import ErrorCode
from shield.errors import ERRORS, ShieldError


@pytest.fixture
def payload():
    return {
        "model": "synthetic-model",
        "messages": [
            {"role": role, "content": "Synthetic Person 🙂"}
            for role in ["system", "developer", "user", "assistant"]
        ],
    }


def test_explicit_request_contract_supports_all_text_roles_and_stream_usage(payload):
    request = ChatCompletionRequest.model_validate(
        payload
        | {
            "stream": True,
            "stream_options": {"include_usage": True},
            "temperature": 0,
            "top_p": 1,
            "n": 2,
            "max_completion_tokens": 100,
            "presence_penalty": -2,
            "frequency_penalty": 2,
            "seed": 42,
        }
    )
    assert request.stream is True
    assert request.stream_options.include_usage is True
    assert [message.role for message in request.messages] == [
        "system",
        "developer",
        "user",
        "assistant",
    ]
    assert all(message.content == "Synthetic Person 🙂" for message in request.messages)
    assert "Synthetic Person" not in repr(request)


@pytest.mark.parametrize(
    "extra",
    [
        {"tools": []},
        {"tool_choice": "none"},
        {"functions": []},
        {"user": "synthetic-sensitive"},
        {"metadata": {"person": "synthetic-sensitive"}},
        {"stop": "synthetic-sensitive"},
        {"response_format": {"type": "text"}},
        {"api_key": "synthetic-sensitive"},
        {"store": False},
    ],
)
def test_unlisted_top_level_request_fields_are_rejected(payload, extra):
    with pytest.raises(ValidationError):
        ChatCompletionRequest.model_validate(payload | extra)


@pytest.mark.parametrize("role", ["system", "developer", "user", "assistant"])
@pytest.mark.parametrize(
    "change",
    [
        {"name": "synthetic-sensitive"},
        {"tool_calls": []},
        {"function_call": {"arguments": "synthetic-sensitive"}},
        {"content": [{"type": "text", "text": "synthetic-sensitive"}]},
        {"content": None},
        {"content": 42},
    ],
)
def test_nested_message_fields_and_non_string_content_rejected(payload, role, change):
    payload["messages"] = [{"role": role, "content": "synthetic"} | change]
    with pytest.raises(ValidationError):
        ChatCompletionRequest.model_validate(payload)


@pytest.mark.parametrize(
    "change",
    [
        {"stream": "true"},
        {"stream": 1},
        {"stream": None},
        {"stream_options": {}},
        {"stream": True, "stream_options": {"include_usage": "true"}},
        {"stream": True, "stream_options": {"metadata": "synthetic-sensitive"}},
        {"max_tokens": 1, "max_completion_tokens": 1},
        {"max_tokens": 0},
        {"max_completion_tokens": True},
        {"messages": []},
        {"messages": [{"role": "tool", "content": "synthetic"}]},
        {"temperature": float("nan")},
        {"temperature": 2.1},
        {"top_p": -0.1},
        {"n": 0},
        {"n": True},
        {"n": 129},
        {"presence_penalty": 2.1},
        {"frequency_penalty": -2.1},
        {"seed": 2**63},
    ],
)
def test_invalid_options_are_rejected(payload, change):
    with pytest.raises(ValidationError):
        ChatCompletionRequest.model_validate(payload | change)


@pytest.fixture
def completion():
    return {
        "id": "chatcmpl-synthetic",
        "object": "chat.completion",
        "created": 1,
        "model": "synthetic-model",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "[PERSON_7K2Q]",
                    "refusal": None,
                    "annotations": [],
                },
                "finish_reason": "stop",
                "logprobs": None,
            },
            {
                "index": 1,
                "message": {
                    "role": "assistant",
                    "content": None,
                    "refusal": "Synthetic refusal",
                },
                "finish_reason": "content_filter",
            },
        ],
        "usage": {
            "prompt_tokens": 10,
            "completion_tokens": 5,
            "total_tokens": 15,
            "prompt_tokens_details": {"cached_tokens": 0, "audio_tokens": 0},
            "completion_tokens_details": {"reasoning_tokens": 1},
        },
        "system_fingerprint": None,
        "service_tier": "default",
    }


def test_response_contract_covers_multiple_choices_and_refusal_text(completion):
    response = ChatCompletionResponse.model_validate(completion)
    assert [choice.index for choice in response.choices] == [0, 1]
    assert response.choices[1].message.refusal == "Synthetic refusal"
    assert response.usage.total_tokens == 15
    assert "Synthetic refusal" not in repr(response)
    assert (
        ChatCompletionResponse.model_validate_json(response.model_dump_json())
        == response
    )


@pytest.mark.parametrize("target", ["root", "choice", "message", "usage", "details"])
def test_response_extras_are_rejected_at_every_model_level(completion, target):
    containers = {
        "root": completion,
        "choice": completion["choices"][0],
        "message": completion["choices"][0]["message"],
        "usage": completion["usage"],
        "details": completion["usage"]["completion_tokens_details"],
    }
    containers[target]["unsupported"] = "synthetic-sensitive"
    with pytest.raises(ValidationError):
        ChatCompletionResponse.model_validate(completion)


def test_rich_outputs_tools_and_ambiguous_choice_indices_rejected(completion):
    for change in [
        {"tool_calls": []},
        {"content": [{"type": "text", "text": "synthetic"}]},
        {"annotations": [{"type": "url_citation", "url": "https://example.test"}]},
    ]:
        changed = copy.deepcopy(completion)
        changed["choices"][0]["message"].update(change)
        with pytest.raises(ValidationError):
            ChatCompletionResponse.model_validate(changed)
    completion["choices"][1]["index"] = 0
    with pytest.raises(ValidationError):
        ChatCompletionResponse.model_validate(completion)


def test_sse_contract_covers_role_content_finish_and_usage_chunks(completion):
    base = {key: completion[key] for key in ["id", "created", "model"]}
    base["object"] = "chat.completion.chunk"
    for choice in [
        {"index": 0, "delta": {"role": "assistant", "content": "[PERSON_7K2Q]"}},
        {"index": 1, "delta": {"refusal": "Synthetic refusal"}},
        {"index": 0, "delta": {}, "finish_reason": "stop"},
    ]:
        assert (
            ChatCompletionChunk.model_validate(base | {"choices": [choice]}).id
            == base["id"]
        )
    usage = ChatCompletionChunk.model_validate(
        base | {"choices": [], "usage": completion["usage"]}
    )
    assert usage.usage.total_tokens == 15
    with pytest.raises(ValidationError):
        ChatCompletionChunk.model_validate(base | {"choices": []})
    with pytest.raises(ValidationError):
        ChatCompletionChunk.model_validate(
            base | {"choices": [{"index": 0, "delta": {"tool_calls": []}}]}
        )


async def test_valid_http_requests_fail_safely_until_protection_exists(payload):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app()), base_url="http://test"
    ) as client:
        for stream in [False, True]:
            response = await client.post(
                "/v1/chat/completions", json=payload | {"stream": stream}
            )
            assert response.status_code == 503
            assert response.json()["error"]["code"] == "protection_unavailable"
            assert response.headers["content-type"] == "application/json"
            assert "x-shield-session" not in response.headers


async def test_invalid_http_requests_do_not_echo_pii_or_unknown_field_names(
    payload, caplog
):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app()), base_url="http://test"
    ) as client:
        payload["messages"][0]["synthetic-sensitive-field"] = (
            "synthetic-sensitive-value"
        )
        response = await client.post("/v1/chat/completions", json=payload)
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "invalid_request"
        assert "synthetic-sensitive" not in response.text
        assert "synthetic-sensitive" not in caplog.text
        malformed = await client.post(
            "/v1/chat/completions",
            content='{"synthetic-sensitive":',
            headers={"Content-Type": "application/json"},
        )
        assert malformed.status_code == 400
        assert "synthetic-sensitive" not in malformed.text
        wrong_type = await client.post(
            "/v1/chat/completions",
            content="synthetic-sensitive",
            headers={"Content-Type": "text/plain"},
        )
        assert wrong_type.status_code == 415


async def test_http_errors_and_unexpected_exceptions_never_echo_details(caplog):
    app = create_app()

    @app.get("/unexpected")
    async def unexpected():
        raise RuntimeError("synthetic-sensitive-exception")

    @app.get("/known")
    async def known():
        raise ShieldError(ErrorCode.VAULT_LOCKED)

    @app.get("/http-error")
    async def http_error():
        raise HTTPException(400, detail="synthetic-sensitive-detail")

    @app.get("/invalid-response", response_model=ChatCompletionResponse)
    async def invalid_response():
        return {"synthetic-sensitive-field": "synthetic-sensitive-value"}

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        assert (await client.get("/synthetic-sensitive-path")).status_code == 404
        method = await client.get("/v1/chat/completions")
        assert method.status_code == 405
        assert method.headers["allow"] == "POST"
        response = await client.get("/unexpected")
        assert response.status_code == 500
        assert response.json()["error"]["code"] == "internal_error"
        assert "synthetic-sensitive" not in response.text
        assert (await client.get("/known")).status_code == 423
        response = await client.get("/http-error")
        assert response.status_code == 400
        assert "synthetic-sensitive" not in response.text
        response = await client.get("/invalid-response")
        assert response.status_code == 500
        assert "synthetic-sensitive" not in response.text
    assert "synthetic-sensitive-exception" not in caplog.text
    assert "synthetic-sensitive-value" not in caplog.text


def test_openapi_lists_supported_fields_and_safe_validation_errors():
    schema = create_app().openapi()
    models = schema["components"]["schemas"]
    for name in ["ChatCompletionRequest", "ChatMessage", "StreamOptions"]:
        assert models[name]["additionalProperties"] is False
    assert models["ChatCompletionRequest"]["properties"]["stream"]["type"] == "boolean"
    responses = schema["paths"]["/v1/chat/completions"]["post"]["responses"]
    assert "400" in responses and "503" in responses
    assert "text/event-stream" in responses["200"]["content"]
    assert "422" not in responses
    assert set(ERRORS) == set(ErrorCode)
