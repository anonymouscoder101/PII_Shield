"""Async transport uses synthetic payloads and never contacts a provider."""

import asyncio
import logging

import httpx
import pytest
from pydantic import SecretStr

from shield.config import UpstreamConfig
from shield.contracts import ErrorCode
from shield.errors import ShieldError
from shield.fake_upstream import create_fake_upstream

PAYLOAD = (
    b'{"model":"synthetic","messages":['
    b'{"role":"user","content":"[PERSON_ABCD]"}],"stream":false}'
)


async def test_fake_upstream_receives_exact_bytes_and_auth():
    from shield.upstream import UpstreamClient

    app = create_fake_upstream()
    async with UpstreamClient(
        UpstreamConfig(),
        SecretStr("synthetic-key"),
        transport=httpx.ASGITransport(app=app),
    ) as client:
        result = await client.complete(PAYLOAD)
    assert app.state.captures[0].body == PAYLOAD
    assert result.id == "chatcmpl-fake"
    assert result.choices[0].message.content


@pytest.mark.parametrize("status", [301, 307, 400, 401, 429, 500, 503])
async def test_status_errors_are_safe_and_never_retried(status, caplog):
    from shield.upstream import UpstreamClient

    calls = []

    async def handle(request):
        calls.append(request)
        return httpx.Response(
            status,
            text="private-seed",
            headers={
                "location": "https://private-seed.test/",
                "x-private": "private-seed",
            },
        )

    caplog.set_level(logging.DEBUG)
    async with UpstreamClient(
        UpstreamConfig(),
        SecretStr("synthetic-key"),
        transport=httpx.MockTransport(handle),
    ) as client:
        with pytest.raises(ShieldError) as error:
            await client.complete(PAYLOAD)
    assert error.value.code == ErrorCode.UPSTREAM_ERROR
    assert len(calls) == 1
    assert str(calls[0].url) == "http://127.0.0.1:8001/v1/chat/completions"
    assert calls[0].headers["authorization"] == "Bearer synthetic-key"
    assert "private-seed" not in str(error.value) + caplog.text
    assert "synthetic-key" not in caplog.text


@pytest.mark.parametrize(
    "exception,code",
    [
        (httpx.ConnectTimeout, ErrorCode.UPSTREAM_TIMEOUT),
        (httpx.ReadTimeout, ErrorCode.UPSTREAM_TIMEOUT),
        (httpx.PoolTimeout, ErrorCode.UPSTREAM_TIMEOUT),
        (httpx.ConnectError, ErrorCode.UPSTREAM_ERROR),
        (httpx.ReadError, ErrorCode.UPSTREAM_ERROR),
        (httpx.RemoteProtocolError, ErrorCode.UPSTREAM_ERROR),
    ],
)
async def test_transport_failures_no_retries(exception, code):
    from shield.upstream import UpstreamClient

    calls = []

    async def handle(request):
        calls.append(request)
        raise exception("private-seed")

    async with UpstreamClient(
        UpstreamConfig(), transport=httpx.MockTransport(handle)
    ) as client:
        with pytest.raises(ShieldError) as error:
            await client.complete(PAYLOAD)
    assert error.value.code == code
    assert len(calls) == 1 and "private-seed" not in str(error.value)


async def test_total_timeout_and_cancellation():
    from shield.upstream import UpstreamClient

    started = asyncio.Event()

    async def handle(request):
        started.set()
        await asyncio.Event().wait()

    async with UpstreamClient(
        UpstreamConfig(timeout_s=0.02), transport=httpx.MockTransport(handle)
    ) as client:
        with pytest.raises(ShieldError) as error:
            await client.complete(PAYLOAD)
        assert error.value.code == ErrorCode.UPSTREAM_TIMEOUT
    async with UpstreamClient(
        UpstreamConfig(), transport=httpx.MockTransport(handle)
    ) as client:
        started.clear()
        task = asyncio.create_task(client.complete(PAYLOAD))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


@pytest.mark.parametrize(
    "body", [b"not json private-seed", b'{"private":"private-seed"}']
)
async def test_invalid_response_is_static_error(body):
    from shield.upstream import UpstreamClient

    async with UpstreamClient(
        UpstreamConfig(),
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, content=body)
        ),
    ) as client:
        with pytest.raises(ShieldError) as error:
            await client.complete(PAYLOAD)
    assert error.value.code == ErrorCode.UPSTREAM_ERROR
    assert "private-seed" not in str(error.value)


async def test_tls_environment_and_phase_timeout_configuration(monkeypatch):
    from shield.upstream import UpstreamClient

    original = httpx.AsyncClient
    options = []

    def capture(**kwargs):
        options.append(kwargs)
        return original(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", capture)
    calls = []

    async def handle(request):
        calls.append(request)
        return httpx.Response(401)

    config = UpstreamConfig(base_url="https://example.test/custom/v1/", timeout_s=2.5)
    async with UpstreamClient(config, transport=httpx.MockTransport(handle)) as client:
        with pytest.raises(ShieldError):
            await client.complete(PAYLOAD)
    assert options[0]["verify"] is True
    assert options[0]["trust_env"] is False
    assert options[0]["follow_redirects"] is False
    assert str(calls[0].url) == "https://example.test/custom/v1/chat/completions"
    assert calls[0].extensions["timeout"] == {
        "connect": 2.5,
        "read": 2.5,
        "write": 2.5,
        "pool": 2.5,
    }
    assert "authorization" not in calls[0].headers


async def test_transport_debug_logs_are_suppressed_only_during_request(caplog):
    from shield.upstream import UpstreamClient

    caplog.set_level(logging.DEBUG)

    async def handle(request):
        logging.getLogger("httpcore.http11").debug("private-seed response headers")
        return httpx.Response(500, text="private-seed")

    async with UpstreamClient(
        UpstreamConfig(), transport=httpx.MockTransport(handle)
    ) as client:
        with pytest.raises(ShieldError):
            await client.complete(PAYLOAD)
    logging.getLogger("httpcore.http11").debug("unrelated transport message")
    assert "private-seed" not in caplog.text
    assert "unrelated transport message" in caplog.text


async def test_synchronous_validation_overrun_cannot_return_success(monkeypatch):
    import time

    from shield.api import ChatCompletionResponse
    from shield.upstream import UpstreamClient

    original = ChatCompletionResponse.model_validate_json

    def delayed(value):
        time.sleep(0.03)
        return original(value)

    monkeypatch.setattr(ChatCompletionResponse, "model_validate_json", delayed)
    async with UpstreamClient(
        UpstreamConfig(timeout_s=0.005),
        transport=httpx.ASGITransport(app=create_fake_upstream()),
    ) as client:
        with pytest.raises(ShieldError) as error:
            await client.complete(PAYLOAD)
    assert error.value.code == ErrorCode.UPSTREAM_TIMEOUT
