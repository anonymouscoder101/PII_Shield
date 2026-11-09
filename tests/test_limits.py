"""Enforce byte and time budgets before routes can use an incoming body."""

import asyncio
import time

import httpx
import pytest
from fastapi import Request
from starlette.responses import StreamingResponse

from shield.app import create_app
from shield.config import ServerConfig, ShieldConfig


def limited_app(*, max_bytes=64, timeout_s=1):
    return create_app(
        ShieldConfig(
            server=ServerConfig(
                max_request_bytes=max_bytes, request_timeout_s=timeout_s
            )
        )
    )


async def test_default_gateway_rejects_oversized_json_before_validation():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app()), base_url="http://test"
    ) as client:
        response = await client.post(
            "/v1/chat/completions",
            content=b"x" * (1048576 + 1),
            headers={"Content-Type": "application/json"},
        )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "request_too_large"


async def test_declared_oversize_is_rejected_without_reading_the_body():
    app = limited_app(max_bytes=8)
    read = []

    async def body():
        read.append(True)
        yield b"synthetic-private-body"

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/v1/chat/completions", content=body(), headers={"Content-Length": "100"}
        )
    assert response.status_code == 413
    assert read == []
    assert "synthetic-private" not in response.text


@pytest.mark.parametrize("declared_length", [None, "1"])
async def test_streamed_bytes_cannot_bypass_limit_with_missing_or_false_length(
    declared_length,
):
    app = limited_app(max_bytes=8)
    entered = []
    consumed = []

    @app.post("/probe")
    async def probe():
        entered.append(True)
        return {}

    async def body():
        for chunk in [b"1234", b"56789", b"not-read"]:
            consumed.append(chunk)
            yield chunk

    headers = {"Content-Length": declared_length} if declared_length else {}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post("/probe", content=body(), headers=headers)
    assert response.status_code == 413
    assert entered == []
    assert consumed == [b"1234", b"56789"]


async def test_byte_boundary_accepts_exact_size_and_counts_unicode_as_utf8():
    app = limited_app(max_bytes=8)

    @app.post("/probe")
    async def probe(request: Request):
        return {"size": len(await request.body())}

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        exact = await client.post("/probe", content="🙂🙂".encode())
        oversized = await client.post("/probe", content="🙂🙂a".encode())
    assert exact.status_code == 200 and exact.json() == {"size": 8}
    assert oversized.status_code == 413


@pytest.mark.parametrize("length", ["-1", "+1", "1.0", "private-invalid-length", ""])
async def test_invalid_content_length_has_a_safe_error(length):
    app = limited_app()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/probe", content=b"a", headers={"Content-Length": length}
        )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"
    assert "private-invalid-length" not in response.text


async def test_duplicate_or_incorrect_content_lengths_are_rejected():
    app = limited_app()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        duplicate = await client.post(
            "/probe",
            content=b"a",
            headers=[("Content-Length", "1"), ("Content-Length", "2")],
        )
        incorrect = await client.post(
            "/probe", content=b"abc", headers={"Content-Length": "1"}
        )
    assert duplicate.status_code == 400
    assert incorrect.status_code == 400


async def test_stalled_upload_times_out_before_route_and_releases_generator(caplog):
    app = limited_app(timeout_s=0.02)
    entered = []
    released = []

    @app.post("/probe")
    async def probe():
        entered.append(True)
        return {}

    async def body():
        try:
            yield b"synthetic-private"
            await asyncio.Event().wait()
        finally:
            released.append(True)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await asyncio.wait_for(
            client.post("/probe", content=body()), timeout=1
        )
    assert response.status_code == 408
    assert response.json()["error"]["code"] == "request_timeout"
    assert entered == []
    assert released == [True]
    assert "synthetic-private" not in response.text + caplog.text


async def test_processing_timeout_cancels_handler_and_runs_cleanup(caplog):
    app = limited_app(timeout_s=0.02)
    released = []

    @app.post("/probe")
    async def probe():
        try:
            await asyncio.Event().wait()
        finally:
            released.append(True)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await asyncio.wait_for(
            client.post("/probe", content=b"{}"), timeout=1
        )
    assert response.status_code == 408
    assert response.json()["error"]["code"] == "request_timeout"
    assert released == [True]
    assert "Traceback" not in caplog.text


async def test_late_headers_after_blocking_work_are_not_sent_as_success():
    app = limited_app(timeout_s=0.01)

    @app.get("/probe")
    async def probe():
        time.sleep(0.03)  # Simulate short synchronous work that cannot be preempted.
        return {"synthetic-private": "must not be sent"}

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/probe")
    assert response.status_code == 408
    assert "synthetic-private" not in response.text


async def test_deadline_ends_at_headers_without_truncating_response_delivery():
    app = limited_app(timeout_s=0.02)

    async def chunks():
        yield b"first "
        await asyncio.sleep(0.04)
        yield b"last"

    @app.get("/probe")
    async def probe():
        return StreamingResponse(chunks())

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/probe")
    assert response.status_code == 200
    assert response.content == b"first last"


async def test_external_cancellation_is_propagated_and_handler_cleans_up():
    app = limited_app()
    entered = asyncio.Event()
    released = asyncio.Event()

    @app.post("/probe")
    async def probe():
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            released.set()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        task = asyncio.create_task(client.post("/probe", content=b"{}"))
        await asyncio.wait_for(entered.wait(), timeout=1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert released.is_set()


async def test_slow_delivery_of_limit_error_does_not_start_a_second_response():
    app = limited_app(max_bytes=8, timeout_s=0.01)
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"123456789", "more_body": False}

    async def send(message):
        sent.append(message)
        if message["type"] == "http.response.start":
            await asyncio.sleep(0.03)

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "path": "/probe",
        "headers": [],
        "query_string": b"",
    }
    await app(scope, receive, send)
    starts = [
        message["status"]
        for message in sent
        if message["type"] == "http.response.start"
    ]
    assert starts == [413]


async def test_deadline_crossed_during_receive_does_not_invoke_handler():
    app = limited_app(timeout_s=0.01)
    entered = []
    sent = []

    @app.post("/probe")
    async def probe():
        entered.append(True)
        return {}

    async def receive():
        time.sleep(0.03)
        return {"type": "http.request", "body": b"{}", "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "path": "/probe",
        "headers": [],
        "query_string": b"",
        "scheme": "http",
    }
    await app(scope, receive, send)
    assert entered == []
    assert (
        next(item["status"] for item in sent if item["type"] == "http.response.start")
        == 408
    )
