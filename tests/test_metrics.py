"""Structured observability contains only approved categories and counts."""

import asyncio
import json
import logging

import httpx
import pytest

from shield.app import create_app
from shield.contracts import ErrorCode, ProtectionReport
from shield.errors import ShieldError
from shield.fake_upstream import create_fake_upstream


def events(caplog):
    return [
        json.loads(r.getMessage()) for r in caplog.records if r.name == "shield.metrics"
    ]


async def test_request_metrics_do_not_include_private_url_or_validation_inputs(caplog):
    caplog.set_level(logging.INFO, logger="shield.metrics")
    app = create_app()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as api:
        response = await api.post(
            "/v1/chat/completions?private-query", json={"private-field": "private-body"}
        )
        await api.get("/private-path")
    assert response.status_code == 400
    records = events(caplog)
    assert len(records) == 2
    assert records[0]["endpoint"] == "chat"
    assert records[0]["error_code"] == "invalid_request"
    assert records[0]["status"] == 400
    assert records[1]["endpoint"] == "other"
    assert records[1]["error_code"] == "not_found"
    assert all(r["duration_ms"] >= 0 for r in records)
    assert "private-" not in json.dumps(records)


async def test_success_metrics_contain_counts_without_values(caplog):
    from shield.config import DetectionConfig, ShieldConfig

    caplog.set_level(logging.INFO, logger="shield.metrics")
    app = create_app(
        ShieldConfig(detection=DetectionConfig(allowlist=["synthetic@example.test"])),
        upstream_transport=httpx.ASGITransport(app=create_fake_upstream()),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as api:
        response = await api.post(
            "/v1/chat/completions",
            json={
                "model": "synthetic",
                "messages": [
                    {"role": "user", "content": "Email synthetic@example.test"}
                ],
            },
        )
    assert response.status_code == 200
    (record,) = events(caplog)
    assert record["outcome"] == "success"
    assert record["report"]["allowlisted_disclosure_counts"] == {"EMAIL_ADDRESS": 1}
    assert "synthetic@example.test" not in json.dumps(record)
    assert "[PERSON_" not in json.dumps(record)


async def test_exception_details_are_absent_from_logs_and_response(caplog):
    caplog.set_level(logging.DEBUG)
    app = create_app()

    @app.get("/private-exception")
    async def fail():
        raise RuntimeError("private-body private-reviewer-reason private-api-key")

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as api:
        response = await api.get("/private-exception")
    assert response.status_code == 500
    (record,) = events(caplog)
    assert record["error_code"] == "internal_error"
    assert "private-body" not in response.text + caplog.text
    assert "private-reviewer-reason" not in caplog.text
    assert all(
        r.exc_info is None for r in caplog.records if r.name.startswith("shield")
    )


async def test_limits_and_cancellation_are_recorded_once(caplog):
    from shield.config import ServerConfig, ShieldConfig

    caplog.set_level(logging.INFO, logger="shield.metrics")
    app = create_app(ShieldConfig(server=ServerConfig(max_request_bytes=8)))
    entered = asyncio.Event()

    @app.get("/blocked")
    async def blocked():
        entered.set()
        await asyncio.Event().wait()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as api:
        assert (
            await api.post("/shield/analyze", content=b"private-body")
        ).status_code == 413
        task = asyncio.create_task(api.get("/blocked"))
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    records = events(caplog)
    assert len(records) == 2
    assert records[0]["error_code"] == "request_too_large"
    assert records[1]["outcome"] == "cancelled" and records[1]["status"] is None


async def test_untrusted_report_or_error_values_cannot_be_logged(caplog):
    from shield.metrics import record_error, record_protection

    caplog.set_level(logging.INFO, logger="shield.metrics")
    app = create_app()

    @app.get("/metrics-contract")
    async def invalid():
        with pytest.raises((TypeError, ValueError)):
            record_error("private-error")
        with pytest.raises((TypeError, ValueError)):
            record_protection(
                ProtectionReport.model_construct(protected_counts={"private-type": 1})
            )
        raise ShieldError(ErrorCode.UPSTREAM_ERROR)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as api:
        assert (await api.get("/metrics-contract")).status_code == 502
    assert "private-error" not in json.dumps(events(caplog))
    assert "private-type" not in json.dumps(events(caplog))


async def test_provider_body_headers_and_credentials_never_enter_logs(caplog):
    from pydantic import SecretStr

    from shield.config import ShieldConfig, UpstreamConfig
    from shield.credentials import RuntimeCredentials

    caplog.set_level(logging.DEBUG)

    async def fail(request):
        logging.getLogger("httpcore.http11").debug(
            "private-provider-body private-reviewer-reason"
        )
        return httpx.Response(
            500,
            text="private-provider-body",
            headers={"x-private": "private-response-header"},
        )

    app = create_app(
        ShieldConfig(
            upstream=UpstreamConfig(base_url="https://example.test/private-url")
        ),
        RuntimeCredentials(api_key=SecretStr("private-provider-key")),
        upstream_transport=httpx.MockTransport(fail),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as api:
        response = await api.post(
            "/v1/chat/completions",
            json={
                "model": "synthetic",
                "messages": [{"role": "user", "content": "private-prompt"}],
            },
        )
    assert response.status_code == 502
    assert events(caplog)[0]["error_code"] == "upstream_error"
    for seed in (
        "private-provider-body",
        "private-reviewer-reason",
        "private-response-header",
        "private-provider-key",
        "private-prompt",
        "private-url",
    ):
        assert seed not in caplog.text + response.text


async def test_concurrent_request_metrics_are_isolated(caplog):
    from shield.metrics import record_protection

    caplog.set_level(logging.INFO, logger="shield.metrics")
    app = create_app()
    ready, release = asyncio.Event(), asyncio.Event()

    @app.get("/good")
    async def good():
        record_protection(ProtectionReport(unknown_token_count=3))
        ready.set()
        await release.wait()
        return {}

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as api:
        pending = asyncio.create_task(api.get("/good"))
        await ready.wait()
        await api.post("/shield/analyze", json={"text": 123})
        release.set()
        await pending
    failed, success = events(caplog)
    assert failed["error_code"] == "invalid_request" and "report" not in failed
    assert (
        success["error_code"] is None and success["report"]["unknown_token_count"] == 3
    )


async def test_late_exception_is_an_error_even_after_200_headers(caplog):
    from starlette.responses import StreamingResponse

    caplog.set_level(logging.INFO, logger="shield.metrics")
    app = create_app()

    @app.get("/late")
    async def late():
        async def body():
            yield b"synthetic"
            raise RuntimeError("private-late-exception")

        return StreamingResponse(body())

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as api:
        response = await api.get("/late")
    assert response.status_code == 200
    (record,) = events(caplog)
    assert record["outcome"] == "error"
    assert record["error_code"] == "internal_error"
    assert "private-late-exception" not in caplog.text + response.text


async def test_upload_exceptions_are_also_safe(caplog):
    caplog.set_level(logging.INFO, logger="shield.metrics")
    app = create_app()
    sent = []

    async def receive():
        raise RuntimeError("private-upload-failure")

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/shield/analyze",
        "raw_path": b"/shield/analyze",
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 1),
        "server": ("127.0.0.1", 8000),
    }
    await app(scope, receive, send)
    assert sent[0]["status"] == 500
    assert "private-upload-failure" not in str(sent) + caplog.text
    assert events(caplog)[0]["error_code"] == "internal_error"
