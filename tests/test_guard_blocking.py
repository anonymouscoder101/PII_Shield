"""Deliberately incomplete masking must fail before any upstream send."""

import re
import socket
from contextlib import contextmanager

import httpx
import pytest

from shield import analysis, gateway
from shield.app import create_app
from shield.config import DetectionConfig
from shield.contracts import DetectedSpan, EntityType
from shield.detect.resolve import SpanPolicy
from shield.session import ephemeral_session


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


def incomplete_masking(monkeypatch):
    original = gateway.sanitize_texts

    def incomplete(texts, session, detector):
        texts = tuple(texts)
        results = original(texts, session, detector)
        # Inject a masking defect after real detection and mapping registration.
        return tuple(
            result.model_copy(update={"sanitized_text": text})
            for text, result in zip(texts, results, strict=True)
        )

    monkeypatch.setattr(gateway, "sanitize_texts", incomplete)


@pytest.mark.parametrize("role", ["system", "developer", "user", "assistant"])
@pytest.mark.parametrize("stream", [False, True])
async def test_incomplete_masking_blocks_all_roles_before_send(
    monkeypatch, caplog, role, stream
):
    incomplete_masking(monkeypatch)
    states, sends = [], []

    @contextmanager
    def captured():
        with ephemeral_session() as state:
            states.append(state)
            yield state

    def forbidden(*args, **kwargs):
        sends.append(True)
        raise AssertionError("Network send attempted")

    monkeypatch.setattr(analysis, "ephemeral_session", captured)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    app = create_app(detector_factory=Detector)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as api:
        response = await api.post(
            "/v1/chat/completions",
            json={
                "model": "synthetic",
                "stream": stream,
                "messages": [{"role": role, "content": "Hello Alice"}],
            },
        )
    assert response.status_code == 422
    assert response.json() == {
        "error": {
            "code": "protection_blocked",
            "message": "Request was blocked by the protection guard.",
        }
    }
    assert response.headers["content-type"] == "application/json"
    assert "x-shield-session" not in response.headers
    assert "Alice" not in response.text + caplog.text
    assert not sends
    assert len(states) == 1 and not states[0].mappings
    with pytest.raises(RuntimeError, match="closed"):
        _ = states[0].key


@pytest.mark.parametrize(
    "config",
    [
        DetectionConfig(allowlist=["Alice"]),
        DetectionConfig(threshold=1.0),
    ],
)
async def test_intentional_or_below_threshold_text_does_not_block(monkeypatch, config):
    from shield.config import ShieldConfig

    incomplete_masking(monkeypatch)
    app = create_app(ShieldConfig(detection=config), detector_factory=Detector)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as api:
        response = await api.post(
            "/v1/chat/completions",
            json={
                "model": "synthetic",
                "messages": [{"role": "user", "content": "Alice"}],
            },
        )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "protection_unavailable"


async def test_unsanitized_model_is_blocked():
    app = create_app(detector_factory=Detector)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as api:
        response = await api.post(
            "/v1/chat/completions",
            json={
                "model": "Alice",
                "messages": [{"role": "user", "content": "ordinary text"}],
            },
        )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "protection_blocked"


async def test_blocked_persistent_request_releases_lease(monkeypatch, tmp_path):
    from pydantic import SecretStr

    from shield.config import Argon2Config, SessionsConfig, ShieldConfig, VaultConfig
    from shield.credentials import RuntimeCredentials

    incomplete_masking(monkeypatch)
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
    )
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as api:
            created = await api.post("/shield/sessions", json={})
            sid = created.json()["session_id"]
            response = await api.post(
                "/v1/chat/completions",
                headers={"X-Shield-Session": sid},
                json={
                    "model": "synthetic",
                    "messages": [{"role": "user", "content": "Alice"}],
                },
            )
            assert response.status_code == 422
            assert response.json()["error"]["code"] == "protection_blocked"
            assert "x-shield-session" not in response.headers
            # Guard failure leaves prior committed allocations intact but releases
            # the lease, allowing normal lookup/deletion immediately afterward.
            assert (await api.get(f"/shield/sessions/{sid}")).status_code == 200
            assert (await api.delete(f"/shield/sessions/{sid}")).status_code == 204
