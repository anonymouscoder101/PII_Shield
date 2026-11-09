"""No persistent request can bypass a locked vault or become ephemeral silently."""

import httpx
import pytest

from shield.app import create_app
from shield.config import SessionsConfig, ShieldConfig, VaultConfig
from shield.credentials import RuntimeCredentials


@pytest.mark.parametrize("enabled", [False, True])
async def test_locked_vault_blocks_creation_and_reuse_but_not_ephemeral(
    tmp_path, enabled
):
    path = tmp_path / "vault.db"
    config = ShieldConfig(
        sessions=SessionsConfig(persistent_enabled=enabled),
        vault=VaultConfig(path=path),
    )
    app = create_app(
        config, RuntimeCredentials(vault_passphrase="synthetic-passphrase")
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        payload = {
            "model": "synthetic-model",
            "messages": [{"role": "user", "content": "Synthetic prompt"}],
        }
        ephemeral = await client.post("/v1/chat/completions", json=payload)
        assert ephemeral.status_code == 503
        assert ephemeral.json()["error"]["code"] == "protection_unavailable"
        for stream in [False, True]:
            persistent = await client.post(
                "/v1/chat/completions",
                json=payload | {"stream": stream},
                headers={"X-Shield-Session": "synthetic-private-id"},
            )
            assert persistent.status_code == 423
            assert persistent.json()["error"]["code"] == "vault_locked"
            assert "synthetic-private-id" not in persistent.text
            assert "x-shield-session" not in persistent.headers
            assert persistent.headers["content-type"] == "application/json"
        creation = await client.post("/shield/sessions", json={})
        assert creation.status_code == 423
        assert creation.json()["error"]["code"] == "vault_locked"
        assert "x-shield-session" not in creation.headers
    assert not path.exists()


@pytest.mark.parametrize(
    "headers",
    [
        [("X-Shield-Session", "")],
        [("X-Shield-Session", "   ")],
        [("X-Shield-Session", "one"), ("X-Shield-Session", "two")],
    ],
)
async def test_empty_or_multiple_session_headers_are_invalid(headers):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app()), base_url="http://test"
    ) as client:
        response = await client.post(
            "/v1/chat/completions",
            json={
                "model": "synthetic-model",
                "messages": [{"role": "user", "content": "Synthetic"}],
            },
            headers=headers,
        )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"


async def test_ephemeral_requests_do_not_consult_vault_readiness():
    class UnusableVault:
        @property
        def is_unlocked(self):
            pytest.fail("Ephemeral requests must not consult the vault")

    app = create_app()
    app.state.vault = UnusableVault()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/v1/chat/completions",
            json={
                "model": "synthetic-model",
                "messages": [{"role": "user", "content": "Synthetic"}],
            },
        )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "protection_unavailable"
