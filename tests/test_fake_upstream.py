"""The fake captures actual serialized requests and supplies controlled replies."""

import asyncio
import json
from pathlib import Path

import httpx
import pytest

from shield.api import ChatCompletionRequest, ChatCompletionResponse
from shield.contracts import DetectedSpan, EntityType


async def test_fake_captures_exact_json_bytes_without_auth_headers(caplog):
    from shield.fake_upstream import create_fake_upstream

    fake = create_fake_upstream()
    raw = (
        b'{ "model": "synthetic-model", "messages": ['
        b'{"role":"user","content":"Hello \\u674e [PERSON_7K2Q]"}], "n": 2 }'
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=fake), base_url="http://fake"
    ) as client:
        response = await client.post(
            "/v1/chat/completions",
            content=raw,
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer synthetic-secret",
            },
        )
    assert response.status_code == 200
    parsed = ChatCompletionResponse.model_validate(response.json())
    assert [choice.index for choice in parsed.choices] == [0, 1]
    assert parsed.model == "synthetic-model"
    assert "[PERSON_7K2Q]" in parsed.choices[0].message.content
    assert "[EMAIL_2M4R]" in parsed.choices[0].message.content
    assert len(fake.state.captures) == 1
    capture = fake.state.captures[0]
    assert capture.body == raw
    assert "Authorization" not in repr(capture)
    assert "Hello" not in repr(capture)
    assert "synthetic-secret" not in caplog.text
    assert "Hello" not in caplog.text


async def test_controlled_reply_can_reflect_request_tokens_without_network_calls():
    from shield.fake_upstream import create_fake_upstream

    def reply(request: ChatCompletionRequest) -> ChatCompletionResponse:
        return ChatCompletionResponse.model_validate(
            {
                "id": "chatcmpl-controlled",
                "object": "chat.completion",
                "created": 0,
                "model": request.model,
                "choices": [
                    {
                        "index": 3,
                        "message": {
                            "role": "assistant",
                            "content": request.messages[-1].content,
                        },
                        "finish_reason": "length",
                    }
                ],
            }
        )

    fake = create_fake_upstream(response_factory=reply)
    payload = {
        "model": "synthetic-model",
        "messages": [{"role": "user", "content": "[PERSON_ABCD12]"}],
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=fake), base_url="http://fake"
    ) as client:
        response = await client.post("/v1/chat/completions", json=payload)
    assert response.status_code == 200
    choice = response.json()["choices"][0]
    assert choice["index"] == 3
    assert choice["finish_reason"] == "length"
    assert choice["message"]["content"] == "[PERSON_ABCD12]"


async def test_refusal_only_reply_preserves_required_null_content():
    from shield.fake_upstream import create_fake_upstream

    def refusal(request: ChatCompletionRequest) -> ChatCompletionResponse:
        return ChatCompletionResponse.model_validate(
            {
                "id": "chatcmpl-refusal",
                "object": "chat.completion",
                "created": 0,
                "model": request.model,
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "refusal": "Cannot discuss [PERSON_7K2Q].",
                        },
                        "finish_reason": "content_filter",
                    }
                ],
            }
        )

    fake = create_fake_upstream(response_factory=refusal)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=fake), base_url="http://fake"
    ) as client:
        response = await client.post(
            "/v1/chat/completions",
            json={
                "model": "synthetic-model",
                "messages": [{"role": "user", "content": "Synthetic prompt"}],
            },
        )
    assert response.status_code == 200
    message = response.json()["choices"][0]["message"]
    assert "content" in message and message["content"] is None
    assert (
        ChatCompletionResponse.model_validate(response.json())
        .choices[0]
        .message.refusal
        == "Cannot discuss [PERSON_7K2Q]."
    )


@pytest.mark.parametrize(
    "raw",
    [
        b'{"model":"synthetic-model","messages":[],"synthetic-sensitive":"value"}',
        b'{"synthetic-sensitive":',
        b'{"model":"synthetic-model","messages":[{"role":"user","content":"synthetic-sensitive"}],"stream":true}',
    ],
)
async def test_rejected_requests_are_captured_and_errors_do_not_echo_inputs(raw):
    from shield.fake_upstream import create_fake_upstream

    fake = create_fake_upstream()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=fake), base_url="http://fake"
    ) as client:
        response = await client.post(
            "/v1/chat/completions",
            content=raw,
            headers={"Content-Type": "application/json"},
        )
    assert response.status_code == 400
    assert "synthetic-sensitive" not in response.text
    assert [capture.body for capture in fake.state.captures] == [raw]


async def test_concurrent_requests_are_captured_individually_and_apps_are_isolated():
    from shield.fake_upstream import create_fake_upstream

    fake = create_fake_upstream()
    other = create_fake_upstream()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=fake), base_url="http://fake"
    ) as client:
        responses = await asyncio.gather(
            *[
                client.post(
                    "/v1/chat/completions",
                    json={
                        "model": "synthetic-model",
                        "messages": [
                            {"role": "user", "content": f"[PERSON_TEST{index}]"}
                        ],
                    },
                )
                for index in range(8)
            ]
        )
    assert all(response.status_code == 200 for response in responses)
    assert len(fake.state.captures) == 8
    assert {
        json.loads(item.body)["messages"][0]["content"] for item in fake.state.captures
    } == {f"[PERSON_TEST{index}]" for index in range(8)}
    assert other.state.captures == []


def test_fake_command_binds_only_to_localhost(monkeypatch):
    from shield.fake_upstream import main

    calls = []
    monkeypatch.setattr(
        "shield.fake_upstream.uvicorn.run", lambda app, **kwargs: calls.append(kwargs)
    )
    main()
    assert calls == [{"host": "127.0.0.1", "port": 8001, "access_log": False}]


async def test_synthetic_fixture_offsets_and_round_trip_examples():
    from shield.fake_upstream import create_fake_upstream

    path = (
        Path(__file__).resolve().parents[1] / "eval/datasets/fixtures/foundation.json"
    )
    cases = json.loads(path.read_text(encoding="utf-8"))
    assert len(cases) >= 3
    assert any(not case["entities"] for case in cases)
    for case in cases:
        assert case["synthetic"] is True
        original = ChatCompletionRequest.model_validate(case["request"])
        sanitized = ChatCompletionRequest.model_validate(case["sanitized_request"])
        completion = ChatCompletionResponse.model_validate(case["response"])
        assert len(original.messages) == len(sanitized.messages)
        assert "[" in completion.choices[0].message.content or not case["entities"]
        for entity in case["entities"]:
            span = DetectedSpan(
                start=entity["start"],
                end=entity["end"],
                entity_type=EntityType(entity["entity_type"]),
                confidence=1.0,
            )
            text = original.messages[entity["message_index"]].content
            span.validate_for_text(text)
            assert text[span.start : span.end] == entity["value"]
            assert (
                entity["value"]
                not in sanitized.messages[entity["message_index"]].content
            )
        fake = create_fake_upstream(
            response_factory=lambda request, result=completion: result
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=fake), base_url="http://fake"
        ) as client:
            response = await client.post(
                "/v1/chat/completions", json=case["sanitized_request"]
            )
        assert response.status_code == 200
        assert json.loads(fake.state.captures[0].body) == case["sanitized_request"]
        assert (
            response.json()["choices"][0]["message"]["content"]
            == case["response"]["choices"][0]["message"]["content"]
        )
