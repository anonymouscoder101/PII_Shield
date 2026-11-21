"""Protected local round trips and parseable buffered SSE, no provider calls."""

import json
import re

import httpx
import pytest

from shield.api import ChatCompletionChunk, ChatCompletionResponse
from shield.app import create_app
from shield.contracts import DetectedSpan, EntityType
from shield.detect.resolve import SpanPolicy
from shield.fake_upstream import create_fake_upstream


class Detector:
    def __init__(self, config):
        self.policy = SpanPolicy(config)

    def detect(self, text):
        return [
            DetectedSpan(
                start=m.start(),
                end=m.end(),
                entity_type=EntityType.PERSON,
                confidence=0.99,
            )
            for m in re.finditer(r"\bAlice\b", text)
        ]


def echo(request):
    token = request.messages[0].content
    return ChatCompletionResponse.model_validate(
        {
            "id": 'chat-id\nquoted"',
            "object": "chat.completion",
            "created": 123,
            "model": request.model,
            "system_fingerprint": "synthetic",
            "choices": [
                {
                    "index": 3,
                    "message": {"role": "assistant", "content": token + '\n"hello"'},
                    "finish_reason": "stop",
                },
                {
                    "index": 7,
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "refusal": token.lower() + "’s refusal",
                    },
                    "finish_reason": "content_filter",
                },
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        }
    )


@pytest.mark.parametrize("stream,usage", [(False, False), (True, False), (True, True)])
async def test_roundtrip_restores_all_choices_and_sse_frames(stream, usage):
    upstream = create_fake_upstream(echo)
    app = create_app(
        detector_factory=Detector, upstream_transport=httpx.ASGITransport(app=upstream)
    )
    payload = {
        "model": "synthetic",
        "stream": stream,
        "messages": [
            {"role": role, "content": "Alice"}
            for role in ("system", "developer", "user", "assistant")
        ],
        "n": 2,
    }
    if stream:
        payload["stream_options"] = {"include_usage": usage}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as api:
        response = await api.post("/v1/chat/completions", json=payload)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    sent = json.loads(upstream.state.captures[0].body)
    assert sent["stream"] is False and "stream_options" not in sent
    assert "Alice" not in upstream.state.captures[0].body.decode()
    assert len({m["content"] for m in sent["messages"]}) == 1
    if not stream:
        result = response.json()
        assert result["choices"][0]["message"]["content"] == 'Alice\n"hello"'
        assert result["choices"][1]["message"]["content"] is None
        assert result["choices"][1]["message"]["refusal"] == "Alice’s refusal"
        assert result["usage"]["total_tokens"] == 15
    else:
        assert response.headers["content-type"].startswith("text/event-stream")
        frames = response.text.strip().split("\n\n")
        assert frames[-1] == "data: [DONE]"
        chunks = [
            ChatCompletionChunk.model_validate_json(f.removeprefix("data: "))
            for f in frames[:-1]
        ]
        assert all(c.id == 'chat-id\nquoted"' and c.created == 123 for c in chunks)
        choices = [choice for chunk in chunks for choice in chunk.choices]
        assert [(c.index, c.delta.role) for c in choices if c.delta.role] == [
            (3, "assistant"),
            (7, "assistant"),
        ]
        assert (
            next(c.delta.content for c in choices if c.index == 3 and c.delta.role)
            == 'Alice\n"hello"'
        )
        assert (
            next(c.delta.refusal for c in choices if c.index == 7 and c.delta.role)
            == "Alice’s refusal"
        )
        assert [(c.index, c.finish_reason) for c in choices if c.finish_reason] == [
            (3, "stop"),
            (7, "content_filter"),
        ]
        assert sum(c.usage is not None for c in chunks) == int(usage)


@pytest.mark.parametrize(
    "mode,status,code",
    [("error", 502, "upstream_error"), ("timeout", 504, "upstream_timeout")],
)
async def test_streaming_failures_return_json_before_headers(mode, status, code):
    from shield.config import ShieldConfig, UpstreamConfig

    calls = []

    async def fail(request):
        calls.append(request)
        if mode == "timeout":
            raise httpx.ReadTimeout("private-seed")
        return httpx.Response(500, text="private-seed")

    app = create_app(
        ShieldConfig(upstream=UpstreamConfig(timeout_s=0.1)),
        detector_factory=Detector,
        upstream_transport=httpx.MockTransport(fail),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as api:
        response = await api.post(
            "/v1/chat/completions",
            json={
                "model": "synthetic",
                "stream": True,
                "messages": [{"role": "user", "content": "Alice"}],
            },
        )
    assert response.status_code == status
    assert response.headers["content-type"] == "application/json"
    assert response.json()["error"]["code"] == code
    assert "private-seed" not in response.text and len(calls) == 1


@pytest.mark.parametrize("stream", [False, True])
async def test_session_is_restored_and_closed_before_success_headers(
    monkeypatch, stream
):
    from contextlib import contextmanager

    from shield import analysis
    from shield.session import ephemeral_session

    states, starts = [], []

    @contextmanager
    def capture():
        with ephemeral_session() as state:
            states.append(state)
            yield state

    monkeypatch.setattr(analysis, "ephemeral_session", capture)
    app = create_app(
        detector_factory=Detector,
        upstream_transport=httpx.ASGITransport(app=create_fake_upstream(echo)),
    )

    async def checked(scope, receive, send):
        async def inspect(message):
            if message["type"] == "http.response.start":
                starts.append(message["status"])
                assert len(states) == 1 and not states[0].mappings
                with pytest.raises(RuntimeError, match="closed"):
                    _ = states[0].key
            await send(message)

        await app(scope, receive, inspect)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=checked), base_url="http://test"
    ) as api:
        response = await api.post(
            "/v1/chat/completions",
            json={
                "model": "synthetic",
                "stream": stream,
                "messages": [{"role": "user", "content": "Alice"}],
            },
        )
    assert starts == [200] and "Alice" in response.text


async def test_cancellation_stops_async_upstream_and_cleans_state(monkeypatch):
    import asyncio
    from contextlib import contextmanager

    from shield import analysis
    from shield.session import ephemeral_session

    entered, cancelled = asyncio.Event(), asyncio.Event()
    states = []

    @contextmanager
    def capture():
        with ephemeral_session() as state:
            states.append(state)
            yield state

    async def blocked(request):
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    monkeypatch.setattr(analysis, "ephemeral_session", capture)
    app = create_app(
        detector_factory=Detector, upstream_transport=httpx.MockTransport(blocked)
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as api:
        task = asyncio.create_task(
            api.post(
                "/v1/chat/completions",
                json={
                    "model": "synthetic",
                    "messages": [{"role": "user", "content": "Alice"}],
                },
            )
        )
        await asyncio.wait_for(entered.wait(), 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.wait_for(cancelled.wait(), 1)
    assert len(states) == 1 and not states[0].mappings
    with pytest.raises(RuntimeError, match="closed"):
        _ = states[0].key


async def test_persistent_lease_is_held_across_fetch(tmp_path):
    import asyncio

    from pydantic import SecretStr

    from shield.config import Argon2Config, SessionsConfig, ShieldConfig, VaultConfig
    from shield.credentials import RuntimeCredentials

    entered, release = asyncio.Event(), asyncio.Event()
    upstream = create_fake_upstream(echo)
    delegate = httpx.ASGITransport(app=upstream)

    class BlockedTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            entered.set()
            await release.wait()
            return await delegate.handle_async_request(request)

    config = ShieldConfig(
        sessions=SessionsConfig(persistent_enabled=True),
        vault=VaultConfig(
            path=tmp_path / "vault.db",
            argon2=Argon2Config(memory_kib=32, time_cost=1, parallelism=1),
        ),
    )
    app = create_app(
        config,
        RuntimeCredentials(vault_passphrase=SecretStr("synthetic")),
        detector_factory=Detector,
        upstream_transport=BlockedTransport(),
    )
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as api:
            sid = (await api.post("/shield/sessions", json={})).json()["session_id"]
            task = asyncio.create_task(
                api.post(
                    "/v1/chat/completions",
                    headers={"X-Shield-Session": sid},
                    json={
                        "model": "synthetic",
                        "messages": [{"role": "assistant", "content": "Alice"}],
                    },
                )
            )
            try:
                await asyncio.wait_for(entered.wait(), 1)
                assert (await api.delete(f"/shield/sessions/{sid}")).status_code == 409
            finally:
                release.set()
            response = await task
            assert response.status_code == 200
            assert response.json()["choices"][0]["message"]["content"].startswith(
                "Alice"
            )
            assert (await api.delete(f"/shield/sessions/{sid}")).status_code == 204


async def test_restoration_failure_returns_json_without_partial_sse(monkeypatch):
    from shield import delivery
    from shield.rehydrate import RehydrationError

    def failed(text, session):
        raise RehydrationError()

    monkeypatch.setattr(delivery, "rehydrate_text", failed)
    upstream = create_fake_upstream(echo)
    app = create_app(
        detector_factory=Detector, upstream_transport=httpx.ASGITransport(app=upstream)
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as api:
        response = await api.post(
            "/v1/chat/completions",
            json={
                "model": "synthetic",
                "stream": True,
                "messages": [{"role": "user", "content": "Alice"}],
            },
        )
    assert response.status_code == 500
    assert response.headers["content-type"] == "application/json"
    assert "Alice" not in response.text and "data:" not in response.text


async def test_real_disconnect_cancels_fetch_before_success_headers():
    import asyncio

    entered, stopped = asyncio.Event(), asyncio.Event()

    async def blocked(request):
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            stopped.set()

    app = create_app(
        detector_factory=Detector, upstream_transport=httpx.MockTransport(blocked)
    )
    messages = asyncio.Queue()
    await messages.put(
        {
            "type": "http.request",
            "body": json.dumps(
                {
                    "model": "synthetic",
                    "stream": True,
                    "messages": [{"role": "user", "content": "Alice"}],
                }
            ).encode(),
            "more_body": False,
        }
    )
    sent = []

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/v1/chat/completions",
        "raw_path": b"/v1/chat/completions",
        "query_string": b"",
        "headers": [(b"content-type", b"application/json")],
        "client": ("127.0.0.1", 123),
        "server": ("127.0.0.1", 8000),
    }
    task = asyncio.create_task(app(scope, messages.get, send))
    try:
        await asyncio.wait_for(entered.wait(), 1)
        await messages.put({"type": "http.disconnect"})
        await asyncio.wait_for(task, 1)
        await asyncio.wait_for(stopped.wait(), 1)
    finally:
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    assert not any(
        m["type"] == "http.response.start" and m["status"] == 200 for m in sent
    )


async def test_cancelled_fetch_keeps_lease_until_transport_cleanup(
    tmp_path, monkeypatch
):
    import asyncio
    from contextlib import contextmanager
    from threading import Event

    from pydantic import SecretStr

    from shield.config import Argon2Config, SessionsConfig, ShieldConfig, VaultConfig
    from shield.credentials import RuntimeCredentials

    entered, cleaning, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
    drained = Event()

    async def blocked(request):
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cleaning.set()
            await release.wait()

    config = ShieldConfig(
        sessions=SessionsConfig(persistent_enabled=True),
        vault=VaultConfig(
            path=tmp_path / "vault.db",
            argon2=Argon2Config(memory_kib=32, time_cost=1, parallelism=1),
        ),
    )
    app = create_app(
        config,
        RuntimeCredentials(vault_passphrase=SecretStr("synthetic")),
        detector_factory=Detector,
        upstream_transport=httpx.MockTransport(blocked),
    )
    async with app.router.lifespan_context(app):
        service = app.state.vault
        original = service.use

        @contextmanager
        def captured(sid):
            try:
                with original(sid) as state:
                    yield state
            finally:
                drained.set()

        monkeypatch.setattr(service, "use", captured)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as api:
            sid = (await api.post("/shield/sessions", json={})).json()["session_id"]
            task = asyncio.create_task(
                api.post(
                    "/v1/chat/completions",
                    headers={"X-Shield-Session": sid},
                    json={
                        "model": "synthetic",
                        "messages": [{"role": "user", "content": "Alice"}],
                    },
                )
            )
            try:
                await asyncio.wait_for(entered.wait(), 1)
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
                await asyncio.wait_for(cleaning.wait(), 1)
                assert not await asyncio.to_thread(drained.wait, 0.05)
                assert (await api.delete(f"/shield/sessions/{sid}")).status_code == 409
            finally:
                release.set()
                await asyncio.to_thread(drained.wait, 1)
            assert (await api.delete(f"/shield/sessions/{sid}")).status_code == 204
