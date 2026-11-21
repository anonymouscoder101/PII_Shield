"""Health snapshots are local, non-blocking and exclude sensitive configuration."""

import asyncio
import json
import logging
import socket
from threading import Event

import httpx
import pytest
from pydantic import SecretStr

from shield.app import create_app
from shield.config import (
    Argon2Config,
    DetectionConfig,
    SessionsConfig,
    ShieldConfig,
    VaultConfig,
)
from shield.credentials import RuntimeCredentials
from shield.detect.resolve import SpanPolicy


class Detector:
    def __init__(self, config):
        self.policy = SpanPolicy(config)

    def detect(self, text):
        return []


def client(app):
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    )


async def test_default_health_is_local_and_never_loads_or_unlocks(
    tmp_path, monkeypatch, caplog
):
    calls = []

    def forbidden(*args, **kwargs):
        calls.append(True)
        raise AssertionError("Health attempted I/O or model loading")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    config = ShieldConfig(
        vault=VaultConfig(path=tmp_path / "private-vault.db"),
        detection=DetectionConfig(
            allowlist=["private-allowlist"], stage2_model="private-model"
        ),
    )
    app = create_app(
        config,
        RuntimeCredentials(api_key=SecretStr("private-key")),
        detector_factory=forbidden,
    )
    caplog.set_level(logging.INFO, logger="shield.metrics")
    async with client(app) as api:
        response = await api.get(
            "/shield/health", headers={"X-Shield-Session": "private-session"}
        )
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "ephemeral_available": True,
        "persistent_sessions_enabled": False,
        "vault_state": "disabled",
        "stage1_status": "not_loaded",
        "stage2_available": False,
    }
    assert response.headers["cache-control"] == "no-store"
    assert (
        "x-shield-session" not in response.headers
        and "x-shield-report" not in response.headers
    )
    assert not calls and not config.vault.path.exists()
    assert "private-" not in response.text
    records = [
        json.loads(r.getMessage()) for r in caplog.records if r.name == "shield.metrics"
    ]
    assert records[0]["endpoint"] == "health" and "report" not in records[0]


async def test_vault_health_tracks_authenticated_lifecycle(tmp_path):
    config = ShieldConfig(
        sessions=SessionsConfig(persistent_enabled=True),
        vault=VaultConfig(
            path=tmp_path / "vault.db",
            argon2=Argon2Config(memory_kib=32, time_cost=1, parallelism=1),
        ),
    )
    app = create_app(
        config, RuntimeCredentials(vault_passphrase=SecretStr("private-passphrase"))
    )
    async with client(app) as api:
        assert (await api.get("/shield/health")).json()["vault_state"] == "locked"
        async with app.router.lifespan_context(app):
            data = (await api.get("/shield/health")).json()
            assert data["persistent_sessions_enabled"] is True
            assert (
                data["vault_state"] == "unlocked"
                and data["ephemeral_available"] is True
            )
            app.state.vault.close()
            assert (await api.get("/shield/health")).json()["vault_state"] == "locked"
        assert (await api.get("/shield/health")).json()["vault_state"] == "locked"


async def test_disabled_vault_is_not_consulted():
    class Unusable:
        @property
        def is_unlocked(self):
            pytest.fail("Disabled vault must not be consulted")

    app = create_app()
    app.state.vault = Unusable()
    async with client(app) as api:
        assert (await api.get("/shield/health")).json()["vault_state"] == "disabled"


async def test_detector_failure_and_recovery_are_visible_without_retrying_health():
    calls = []

    def load(config):
        calls.append(True)
        if len(calls) == 1:
            raise RuntimeError("private-model-failure")
        return Detector(config)

    app = create_app(detector_factory=load)
    async with client(app) as api:
        assert (
            await api.post("/shield/analyze", json={"text": "synthetic"})
        ).status_code == 503
        data = (await api.get("/shield/health")).json()
        assert (
            data["stage1_status"] == "unavailable"
            and data["ephemeral_available"] is True
        )
        assert len(calls) == 1 and "private-" not in str(data)
        assert (
            await api.post("/shield/analyze", json={"text": "synthetic"})
        ).status_code == 200
        assert (await api.get("/shield/health")).json()["stage1_status"] == "loaded"
        assert len(calls) == 2


async def test_health_does_not_wait_for_detector_loading_lock():
    entered, release = Event(), Event()

    def load(config):
        entered.set()
        assert release.wait(2)
        return Detector(config)

    app = create_app(detector_factory=load)
    async with client(app) as api:
        pending = asyncio.create_task(
            api.post("/shield/analyze", json={"text": "synthetic"})
        )
        try:
            assert await asyncio.to_thread(entered.wait, 1)
            response = await asyncio.wait_for(api.get("/shield/health"), 0.2)
            assert (
                response.status_code == 200
                and response.json()["stage1_status"] == "loading"
            )
        finally:
            release.set()
            await pending


def test_health_openapi_contract_is_explicit():
    spec = create_app().openapi()
    response = spec["paths"]["/shield/health"]["get"]["responses"]["200"]
    assert response["content"]["application/json"]["schema"]["$ref"].endswith(
        "/HealthResponse"
    )
    model = spec["components"]["schemas"]["HealthResponse"]
    assert model["additionalProperties"] is False
