"""Local analysis endpoint: synthetic text, strict schemas and lifecycle cleanup."""

import asyncio
import re
import socket
from contextlib import contextmanager
from threading import Event

import httpx
import pytest
from pydantic import SecretStr

from shield.app import create_app
from shield.config import (
    Argon2Config,
    DetectionConfig,
    ServerConfig,
    SessionsConfig,
    ShieldConfig,
    VaultConfig,
)
from shield.contracts import DetectedSpan, EntityType
from shield.credentials import RuntimeCredentials
from shield.detect.resolve import SpanPolicy


class FakeDetector:
    def __init__(self, config):
        self.policy = SpanPolicy(config)

    def detect(self, text):
        result = []
        for pattern, entity in [
            (r"\bAlice\b", EntityType.PERSON),
            (r"synthetic@example\.test", EntityType.EMAIL_ADDRESS),
        ]:
            result.extend(
                DetectedSpan(
                    start=m.start(), end=m.end(), entity_type=entity, confidence=0.9
                )
                for m in re.finditer(pattern, text, re.IGNORECASE)
            )
        return result


def settings(tmp_path, **kwargs):
    return ShieldConfig(
        vault=VaultConfig(
            path=tmp_path / "vault.db",
            argon2=Argon2Config(memory_kib=32, time_cost=1, parallelism=1),
        ),
        **kwargs,
    )


def client(app):
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    )


async def test_ephemeral_analysis_coordinates_counts_and_cleanup(tmp_path, monkeypatch):
    from shield import analysis
    from shield.session import ephemeral_session

    states, keys = [], []

    @contextmanager
    def captured():
        with ephemeral_session() as state:
            states.append(state)
            keys.append(state.key.get_secret_value())
            yield state

    monkeypatch.setattr(analysis, "ephemeral_session", captured)
    app = create_app(settings(tmp_path), detector_factory=FakeDetector)
    text = "🛡️ Alice and Alice use synthetic@example.test."
    async with client(app) as api:
        response = await api.post("/shield/analyze", json={"text": text})
        again = await api.post("/shield/analyze", json={"text": text})
    assert response.status_code == again.status_code == 200
    data = response.json()
    assert data["preview_only"] is True and data.get("session_id") is None
    assert "x-shield-session" not in response.headers
    assert data["report"]["protected_counts"] == {"PERSON": 2, "EMAIL_ADDRESS": 1}
    assert [text[item["start"] : item["end"]] for item in data["spans"]] == [
        "Alice",
        "Alice",
        "synthetic@example.test",
    ]
    assert (
        "Alice" not in data["sanitized_text"]
        and "synthetic@example.test" not in data["sanitized_text"]
    )
    assert keys[0] != keys[1]
    assert not tmp_path.joinpath("vault.db").exists()
    for state in states:
        assert not state.mappings
        with pytest.raises(RuntimeError, match="closed"):
            _ = state.key
    assert (
        "entity_digest" not in response.text and "original_value" not in response.text
    )
    assert response.headers["cache-control"] == "no-store"


async def test_analysis_applies_allowlist_and_explicit_threshold(tmp_path):
    config = settings(tmp_path, detection=DetectionConfig(allowlist=["Alice"]))
    app = create_app(config, detector_factory=FakeDetector)
    async with client(app) as api:
        response = await api.post(
            "/shield/analyze", json={"text": "Alice synthetic@example.test"}
        )
    data = response.json()
    assert data["report"]["allowlisted_disclosure_counts"] == {"PERSON": 1}
    assert data["sanitized_text"].startswith("Alice ")
    app = create_app(
        settings(tmp_path, detection=DetectionConfig(threshold=1)),
        detector_factory=FakeDetector,
    )
    async with client(app) as api:
        data = (await api.post("/shield/analyze", json={"text": "Alice"})).json()
    assert data["sanitized_text"] == "Alice" and data["spans"] == []
    assert data["below_threshold_count"] == 1


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"text": None},
        {"text": 3},
        {"text": []},
        {"text": "Alice", "session_id": "synthetic"},
        {"text": "Alice", "metadata": {}},
    ],
)
async def test_analysis_schema_is_strict(body):
    async with client(create_app(detector_factory=FakeDetector)) as api:
        response = await api.post("/shield/analyze", json=body)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"


async def test_empty_analysis_and_media_type():
    async with client(create_app(detector_factory=FakeDetector)) as api:
        response = await api.post("/shield/analyze", json={"text": ""})
        assert response.status_code == 200 and response.json()["sanitized_text"] == ""
        invalid = await api.post(
            "/shield/analyze",
            content='{"text":"Alice"}',
            headers={"Content-Type": "text/plain"},
        )
    assert invalid.status_code == 415


async def test_analysis_model_failure_is_safe_and_does_not_contact_upstream(
    tmp_path, caplog, monkeypatch
):
    def forbidden(*args, **kwargs):
        pytest.fail("analysis must never contact an upstream")

    monkeypatch.setattr(socket.socket, "connect", forbidden)

    def unavailable(config):
        raise RuntimeError("synthetic sensitive model failure")

    app = create_app(settings(tmp_path), detector_factory=unavailable)
    async with client(app) as api:
        response = await api.post(
            "/shield/analyze", json={"text": "synthetic private input"}
        )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "detection_failed"
    assert "sensitive" not in response.text + caplog.text
    assert "private" not in response.text + caplog.text
    assert "x-shield-session" not in response.headers


async def test_persistent_analysis_commits_reuses_and_preserves_tokens(tmp_path):
    config = settings(tmp_path, sessions=SessionsConfig(persistent_enabled=True))
    app = create_app(
        config,
        RuntimeCredentials(vault_passphrase=SecretStr("synthetic")),
        detector_factory=FakeDetector,
    )
    async with app.router.lifespan_context(app):
        async with client(app) as api:
            sid = (await api.post("/shield/sessions", json={})).json()["session_id"]
            headers = {"X-Shield-Session": sid}
            first = await api.post(
                "/shield/analyze", headers=headers, json={"text": "Alice"}
            )
            second = await api.post(
                "/shield/analyze", headers=headers, json={"text": "ALICE"}
            )
            assert first.status_code == second.status_code == 200
            data = first.json()
            assert not data["preview_only"] and data["session_id"] == sid
            assert first.headers["x-shield-session"] == sid
            assert data["sanitized_text"] == second.json()["sanitized_text"]
            preserved = await api.post(
                "/shield/analyze",
                headers=headers,
                json={"text": data["sanitized_text"]},
            )
            assert preserved.json()["preserved_token_count"] == 1
            assert preserved.json()["sanitized_text"] == data["sanitized_text"]
            stored = app.state.vault.read_mapping(sid, data["sanitized_text"])
            assert stored.original_value.get_secret_value() == "Alice"
        token = data["sanitized_text"]
    app = create_app(
        config,
        RuntimeCredentials(vault_passphrase=SecretStr("synthetic")),
        detector_factory=FakeDetector,
    )
    async with app.router.lifespan_context(app):
        async with client(app) as api:
            response = await api.post(
                "/shield/analyze",
                headers={"X-Shield-Session": sid},
                json={"text": "Alice"},
            )
            assert response.json()["sanitized_text"] == token


async def test_session_selection_errors_and_unknown_input_placeholder(tmp_path):
    app = create_app(settings(tmp_path), detector_factory=FakeDetector)
    async with client(app) as api:
        selected = await api.post(
            "/shield/analyze",
            headers={"X-Shield-Session": "synthetic"},
            json={"text": "Alice"},
        )
        assert selected.status_code == 423
        bad = await api.post(
            "/shield/analyze",
            headers=[("X-Shield-Session", "one"), ("X-Shield-Session", "two")],
            json={"text": "Alice"},
        )
        assert bad.status_code == 400
        unknown = await api.post("/shield/analyze", json={"text": "[PERSON_ABCD]"})
        assert unknown.status_code == 400
        assert "[PERSON_ABCD]" not in unknown.text


async def test_real_detector_analysis_is_local_and_usable(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("analysis must remain local")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    app = create_app()
    async with client(app) as api:
        response = await api.post(
            "/shield/analyze", json={"text": "Email synthetic@example.test."}
        )
    assert response.status_code == 200
    assert "synthetic@example.test" not in response.json()["sanitized_text"]
    assert response.json()["report"]["protected_counts"]["EMAIL_ADDRESS"] == 1


async def test_timeout_releases_ephemeral_state_before_worker_finishes(
    tmp_path, monkeypatch
):
    from shield import analysis
    from shield.session import ephemeral_session

    entered, release, finished = Event(), Event(), Event()
    states = []

    @contextmanager
    def captured():
        try:
            with ephemeral_session() as state:
                states.append(state)
                yield state
        finally:
            finished.set()

    class Blocked(FakeDetector):
        def detect(self, text):
            entered.set()
            if not release.wait(2):
                raise RuntimeError("synthetic wait expired")
            return super().detect(text)

    monkeypatch.setattr(analysis, "ephemeral_session", captured)
    config = settings(tmp_path, server=ServerConfig(request_timeout_s=0.05))
    app = create_app(config, detector_factory=Blocked)
    try:
        async with client(app) as api:
            response = await api.post("/shield/analyze", json={"text": "Alice"})
        assert entered.is_set()
        assert response.status_code == 408
        assert response.json()["error"]["code"] == "request_timeout"
        assert not states[0].mappings
        with pytest.raises(RuntimeError, match="closed"):
            _ = states[0].key
    finally:
        release.set()
        assert await asyncio.to_thread(finished.wait, 1)
    assert not config.vault.path.exists()


async def test_cancelled_persistent_worker_retains_lease_until_drained(
    tmp_path, monkeypatch
):
    entered, release, finished = Event(), Event(), Event()
    states = []

    class Blocked(FakeDetector):
        def detect(self, text):
            entered.set()
            if not release.wait(2):
                raise RuntimeError("synthetic wait expired")
            return super().detect(text)

    config = settings(tmp_path, sessions=SessionsConfig(persistent_enabled=True))
    app = create_app(
        config,
        RuntimeCredentials(vault_passphrase=SecretStr("synthetic")),
        detector_factory=Blocked,
    )
    async with app.router.lifespan_context(app):
        original_use = app.state.vault.use

        @contextmanager
        def captured(sid):
            try:
                with original_use(sid) as state:
                    states.append(state)
                    yield state
            finally:
                finished.set()

        monkeypatch.setattr(app.state.vault, "use", captured)
        async with client(app) as api:
            sid = (await api.post("/shield/sessions", json={})).json()["session_id"]
            task = asyncio.create_task(
                api.post(
                    "/shield/analyze",
                    headers={"X-Shield-Session": sid},
                    json={"text": "Alice"},
                )
            )
            try:
                assert await asyncio.to_thread(entered.wait, 1)
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
                with pytest.raises(RuntimeError, match="closed"):
                    _ = states[0].key
                assert (await api.delete(f"/shield/sessions/{sid}")).status_code == 409
            finally:
                release.set()
                assert await asyncio.to_thread(finished.wait, 1)
            assert (await api.delete(f"/shield/sessions/{sid}")).status_code == 204


async def test_analysis_size_limit_and_invalid_session_statuses(tmp_path):
    app = create_app(
        settings(tmp_path, server=ServerConfig(max_request_bytes=32)),
        detector_factory=FakeDetector,
    )
    async with client(app) as api:
        assert (
            await api.post("/shield/analyze", json={"text": "x" * 50})
        ).status_code == 413
    app = create_app(
        settings(tmp_path, sessions=SessionsConfig(persistent_enabled=True)),
        RuntimeCredentials(vault_passphrase=SecretStr("synthetic")),
        detector_factory=FakeDetector,
    )
    async with app.router.lifespan_context(app):
        async with client(app) as api:
            assert (
                await api.post(
                    "/shield/analyze",
                    headers={"X-Shield-Session": "unknown"},
                    json={"text": "Alice"},
                )
            ).status_code == 404
            sid = (await api.post("/shield/sessions", json={})).json()["session_id"]
            from datetime import UTC, datetime

            app.state.vault.clock = lambda: datetime(2099, 1, 1, tzinfo=UTC)
            expired = await api.post(
                "/shield/analyze",
                headers={"X-Shield-Session": sid},
                json={"text": "Alice"},
            )
            assert expired.status_code == 410
            assert "x-shield-session" not in expired.headers


async def test_ephemeral_preview_does_not_consult_vault_readiness(tmp_path):
    class UnusableVault:
        @property
        def is_unlocked(self):
            pytest.fail("ephemeral analysis must ignore the vault")

    app = create_app(settings(tmp_path), detector_factory=FakeDetector)
    app.state.vault = UnusableVault()
    async with client(app) as api:
        response = await api.post("/shield/analyze", json={"text": "Alice"})
    assert response.status_code == 200
    assert not tmp_path.joinpath("vault.db").exists()


def test_cancelled_queued_job_creates_no_state_or_model(monkeypatch):
    from shield import analysis

    def forbidden(*args, **kwargs):
        pytest.fail("cancelled queued work must not initialize anything")

    monkeypatch.setattr(analysis, "ephemeral_session", forbidden)
    job = analysis.AnalysisJob(
        analysis.DetectorProvider(DetectionConfig(), forbidden), None, None
    )
    job.cancel()
    assert job.run("Alice") is None


async def test_actual_asgi_disconnect_closes_ephemeral_state(tmp_path, monkeypatch):
    import json

    from shield import analysis
    from shield.session import ephemeral_session

    entered, release, finished = Event(), Event(), Event()
    closed = asyncio.Event()
    loop = asyncio.get_running_loop()
    states = []

    @contextmanager
    def captured():
        try:
            with ephemeral_session() as state:
                states.append(state)
                yield state
        finally:
            finished.set()

    class Blocked(FakeDetector):
        def detect(self, text):
            entered.set()
            if not release.wait(2):
                raise RuntimeError("synthetic wait expired")
            return super().detect(text)

    monkeypatch.setattr(analysis, "ephemeral_session", captured)
    from shield.session import EphemeralSession

    original_close = EphemeralSession.close

    def observed_close(state):
        original_close(state)
        loop.call_soon_threadsafe(closed.set)

    monkeypatch.setattr(EphemeralSession, "close", observed_close)
    app = create_app(settings(tmp_path), detector_factory=Blocked)
    incoming = asyncio.Queue()
    await incoming.put(
        {
            "type": "http.request",
            "body": json.dumps({"text": "Alice"}).encode(),
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
        "path": "/shield/analyze",
        "raw_path": b"/shield/analyze",
        "query_string": b"",
        "headers": [(b"content-type", b"application/json")],
        "client": ("127.0.0.1", 1234),
        "server": ("test", 80),
    }
    task = asyncio.create_task(app(scope, incoming.get, send))
    try:
        assert await asyncio.to_thread(entered.wait, 1)
        await incoming.put({"type": "http.disconnect"})
        await asyncio.wait_for(closed.wait(), 0.3)
        assert not states[0].mappings
        with pytest.raises(RuntimeError, match="closed"):
            _ = states[0].key
        await asyncio.wait_for(task, 1)
        assert not any(item.get("status") == 200 for item in sent)
    finally:
        release.set()
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        assert await asyncio.to_thread(finished.wait, 1)
