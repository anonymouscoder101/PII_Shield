"""Synthetic persistent-session lifecycle and API tests, without provider calls."""

import asyncio
import sqlite3
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from pydantic import SecretStr

from shield.app import create_app
from shield.config import Argon2Config, SessionsConfig, ShieldConfig, VaultConfig
from shield.contracts import EntityType, ErrorCode, TokenMapping
from shield.credentials import RuntimeCredentials
from shield.persistent import PersistentSessions, SessionAccessError, VaultStartupError
from shield.session import ephemeral_session

PASSWORD = SecretStr("synthetic passphrase")
PAYLOAD = {"model": "synthetic", "messages": [{"role": "user", "content": "Synthetic"}]}


def settings(tmp_path):
    return VaultConfig(
        path=tmp_path / "vault.db",
        session_ttl_hours=1,
        argon2=Argon2Config(memory_kib=32, time_cost=1, parallelism=1),
    )


def counts(path):
    with sqlite3.connect(path) as db:
        return tuple(
            db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            for table in ("sessions", "entries")
        )


def test_creation_restart_recovery_and_scoped_key_release(tmp_path):
    config = settings(tmp_path)
    service = PersistentSessions.open(config, PASSWORD)
    record = service.create()
    with service.use(record.session_id) as active:
        secret = active.key.get_secret_value()
        mapping = TokenMapping(
            session_id=record.session_id,
            token="[PERSON_ABCD]",
            entity_type=EntityType.PERSON,
            entity_digest=b"d" * 32,
            original_value=SecretStr("Synthetic Person"),
        )
        active.mappings[mapping.token] = mapping
        active.commit_mappings()
    with pytest.raises(RuntimeError, match="closed"):
        _ = active.key
    service.close()
    assert not service.is_unlocked
    with pytest.raises(SessionAccessError) as exc:
        service.create()
    assert exc.value.code == ErrorCode.VAULT_LOCKED
    with PersistentSessions.open(config, PASSWORD) as reopened:
        assert reopened.lookup(record.session_id) == record
        with reopened.use(record.session_id) as active:
            assert active.key.get_secret_value() == secret
        assert reopened.read_mapping(record.session_id, "[PERSON_ABCD]") == mapping
        reopened.delete(record.session_id)
        assert counts(config.path) == (0, 0)
        with pytest.raises(SessionAccessError) as exc:
            reopened.lookup(record.session_id)
        assert exc.value.code == ErrorCode.SESSION_NOT_FOUND
    for file in tmp_path.iterdir():
        assert secret not in file.read_bytes()
        assert b"Synthetic Person" not in file.read_bytes()


def test_expiry_is_inclusive_and_removes_entries(tmp_path):
    now = datetime(2026, 1, 1, tzinfo=UTC)
    config = settings(tmp_path)
    with PersistentSessions.open(config, PASSWORD, clock=lambda: now) as service:
        record = service.create()
        service.insert_mappings(
            [
                TokenMapping(
                    session_id=record.session_id,
                    token="[PERSON_ABCD]",
                    entity_type=EntityType.PERSON,
                    entity_digest=b"d" * 32,
                    original_value=SecretStr("Synthetic"),
                )
            ]
        )
        now = record.expires_at
        with pytest.raises(SessionAccessError) as exc:
            service.lookup(record.session_id)
        assert exc.value.code == ErrorCode.SESSION_EXPIRED
        assert counts(config.path) == (0, 0)
        with pytest.raises(SessionAccessError) as exc:
            service.lookup(record.session_id)
        assert exc.value.code == ErrorCode.SESSION_NOT_FOUND


def test_restart_prunes_expired_sessions(tmp_path):
    now = datetime(2026, 1, 1, tzinfo=UTC)
    config = settings(tmp_path)
    with PersistentSessions.open(config, PASSWORD, clock=lambda: now) as service:
        service.create()
    now += timedelta(hours=2)
    with PersistentSessions.open(config, PASSWORD, clock=lambda: now):
        assert counts(config.path) == (0, 0)


def test_wrong_passphrase_fails_without_reinitializing(tmp_path):
    config = settings(tmp_path)
    with PersistentSessions.open(config, PASSWORD) as service:
        record = service.create()
    with pytest.raises(VaultStartupError, match="Vault startup failed"):
        PersistentSessions.open(config, SecretStr("synthetic wrong password"))
    with PersistentSessions.open(config, PASSWORD) as service:
        assert service.lookup(record.session_id) == record


def test_tampered_expiry_fails_authentication_and_does_not_delete(tmp_path):
    config = settings(tmp_path)
    with PersistentSessions.open(config, PASSWORD) as service:
        record = service.create()
        with sqlite3.connect(config.path) as db:
            db.execute("UPDATE sessions SET expires_at=created_at+1")
        with pytest.raises(SessionAccessError) as exc:
            service.lookup(record.session_id)
        assert exc.value.code == ErrorCode.INTERNAL_ERROR
        assert counts(config.path) == (1, 0)


async def test_session_endpoints_and_restart(tmp_path):
    config = ShieldConfig(
        vault=settings(tmp_path), sessions=SessionsConfig(persistent_enabled=True)
    )
    app = create_app(config, RuntimeCredentials(vault_passphrase=PASSWORD))
    async with app.router.lifespan_context(app):
        assert app.state.vault.is_unlocked
        assert app.state.credentials.vault_passphrase is None
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            created = await client.post("/shield/sessions", json={})
            assert created.status_code == 201
            record = created.json()
            sid = record["session_id"]
            assert created.headers["x-shield-session"] == sid
            selected = await client.get(f"/shield/sessions/{sid}")
            assert selected.status_code == 200 and selected.json() == record
            assert selected.headers["x-shield-session"] == sid
            unknown = await client.post(
                "/v1/chat/completions",
                json=PAYLOAD,
                headers={"X-Shield-Session": "synthetic-unknown"},
            )
            assert unknown.status_code == 404
            valid = await client.post(
                "/v1/chat/completions", json=PAYLOAD, headers={"X-Shield-Session": sid}
            )
            assert valid.status_code == 503
    assert app.state.vault is None
    app = create_app(config, RuntimeCredentials(vault_passphrase=PASSWORD))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            assert (await client.get(f"/shield/sessions/{sid}")).status_code == 200
            deleted = await client.delete(f"/shield/sessions/{sid}")
            assert deleted.status_code == 204 and not deleted.content
            assert (await client.get(f"/shield/sessions/{sid}")).status_code == 404
            assert (
                await client.post(
                    "/v1/chat/completions",
                    json=PAYLOAD,
                    headers={"X-Shield-Session": sid},
                )
            ).status_code == 404


async def test_expired_session_api_fails_and_removes_rows(tmp_path):
    app = create_app(
        ShieldConfig(
            vault=settings(tmp_path), sessions=SessionsConfig(persistent_enabled=True)
        ),
        RuntimeCredentials(vault_passphrase=PASSWORD),
    )
    async with app.router.lifespan_context(app):
        now = datetime(2026, 1, 1, tzinfo=UTC)
        app.state.vault.clock = lambda: now
        record = app.state.vault.create()
        now = record.expires_at
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/v1/chat/completions",
                json=PAYLOAD,
                headers={"X-Shield-Session": record.session_id},
            )
            assert response.status_code == 410
            assert response.json()["error"]["code"] == "session_expired"
            assert "x-shield-session" not in response.headers
        assert counts(app.state.config.vault.path) == (0, 0)


async def test_disabled_startup_creates_no_files_and_needs_no_passphrase(tmp_path):
    app = create_app(ShieldConfig(vault=settings(tmp_path)))
    async with app.router.lifespan_context(app):
        assert app.state.vault is None
        assert not app.state.config.vault.path.exists()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            assert (await client.post("/shield/sessions", json={})).status_code == 423
            assert (
                await client.delete("/shield/sessions/synthetic")
            ).status_code == 423


async def test_ephemeral_cleanup_on_actual_timeout():
    with pytest.raises(TimeoutError):
        async with asyncio.timeout(0.01):
            with ephemeral_session() as state:
                await asyncio.Event().wait()
    assert not state.mappings
    with pytest.raises(RuntimeError, match="closed"):
        _ = state.key


async def test_wrong_passphrase_startup_leaves_no_ready_service_or_credentials(
    tmp_path,
):
    config = ShieldConfig(
        vault=settings(tmp_path), sessions=SessionsConfig(persistent_enabled=True)
    )
    with PersistentSessions.open(config.vault, PASSWORD) as service:
        record = service.create()
    app = create_app(
        config, RuntimeCredentials(vault_passphrase=SecretStr("synthetic wrong"))
    )
    with pytest.raises(VaultStartupError):
        async with app.router.lifespan_context(app):
            pytest.fail("startup must fail before serving")
    assert app.state.vault is None
    assert app.state.credentials.vault_passphrase is None
    with PersistentSessions.open(config.vault, PASSWORD) as service:
        assert service.lookup(record.session_id) == record


@pytest.mark.parametrize("error", [RuntimeError("synthetic"), asyncio.CancelledError()])
def test_persistent_scopes_release_on_failure_or_cancellation(tmp_path, error):
    with PersistentSessions.open(settings(tmp_path), PASSWORD) as service:
        record = service.create()
        with pytest.raises(type(error)):
            with service.use(record.session_id) as active:
                active.mappings["synthetic"] = None
                raise error
        assert not active.mappings
        with pytest.raises(RuntimeError, match="closed"):
            _ = active.key
        with service.use(record.session_id) as fresh:
            assert len(fresh.key.get_secret_value()) == 32


async def test_missing_startup_passphrase_fails_without_creating_database(tmp_path):
    config = ShieldConfig(
        vault=settings(tmp_path), sessions=SessionsConfig(persistent_enabled=True)
    )
    app = create_app(config)
    with pytest.raises(VaultStartupError):
        async with app.router.lifespan_context(app):
            pytest.fail("missing credentials must abort startup")
    assert not config.vault.path.exists()


def test_missing_header_in_nonempty_vault_never_resets_keys(tmp_path):
    config = settings(tmp_path)
    with PersistentSessions.open(config, PASSWORD) as service:
        service.create()
    with sqlite3.connect(config.path) as db:
        db.execute("DELETE FROM vault_meta")
    with pytest.raises(VaultStartupError):
        PersistentSessions.open(config, PASSWORD)
    assert counts(config.path) == (1, 0)


def test_cli_releases_original_credentials_after_startup(tmp_path, monkeypatch):
    import gc
    import weakref

    from shield import __main__ as cli

    path = tmp_path / "config.yaml"
    path.write_text(
        "sessions: {persistent_enabled: true}\nvault:\n  path: vault.db\n"
        "  argon2: {memory_kib: 32, time_cost: 1, parallelism: 1}\n"
    )
    refs = []

    def credentials(config):
        value = RuntimeCredentials(vault_passphrase=PASSWORD)
        refs.append(weakref.ref(value))
        return value

    def serve(app, **kwargs):
        async def startup():
            async with app.router.lifespan_context(app):
                gc.collect()
                assert refs[0]() is None

        asyncio.run(startup())

    monkeypatch.setattr(cli, "load_credentials", credentials)
    monkeypatch.setattr(cli.uvicorn, "run", serve)
    monkeypatch.setattr("sys.argv", ["pii-shield", "--config", str(path)])
    cli.main()
