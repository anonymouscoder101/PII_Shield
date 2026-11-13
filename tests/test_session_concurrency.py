"""Event-controlled concurrency tests; all values and send callbacks are synthetic."""

import asyncio
import sqlite3
from datetime import UTC, datetime

import pytest
from pydantic import SecretStr

from shield.config import Argon2Config, VaultConfig
from shield.contracts import EntityType, ErrorCode, TokenMapping
from shield.persistent import PersistentSessions, SessionAccessError, VaultStartupError
from shield.session import ephemeral_session


def config(tmp_path):
    return VaultConfig(
        path=tmp_path / "vault.db",
        argon2=Argon2Config(memory_kib=32, time_cost=1, parallelism=1),
    )


def mapping(sid, token="[PERSON_ABCD]"):
    return TokenMapping(
        session_id=sid,
        token=token,
        entity_type=EntityType.PERSON,
        entity_digest=b"d" * 32,
        original_value=SecretStr("Synthetic Person"),
    )


def assert_busy(operation):
    with pytest.raises(SessionAccessError) as exc:
        operation()
    assert exc.value.code == ErrorCode.SESSION_BUSY


def test_active_scope_blocks_delete_lookup_and_direct_mapping_changes(tmp_path):
    with PersistentSessions.open(config(tmp_path), SecretStr("synthetic")) as service:
        record = service.create()
        other = service.create()
        with service.use(record.session_id) as active:
            assert_busy(lambda: service.delete(record.session_id))
            assert_busy(lambda: service.lookup(record.session_id))
            assert_busy(lambda: service.insert_mappings([mapping(record.session_id)]))
            assert_busy(
                lambda: service.read_mapping(record.session_id, "[PERSON_ABCD]")
            )
            assert service.lookup(other.session_id) == other
            active.mappings["[PERSON_ABCD]"] = mapping(record.session_id)
            active.commit_mappings()
            assert active.read_mapping("[PERSON_ABCD]") == mapping(record.session_id)
        assert service.read_mapping(record.session_id, "[PERSON_ABCD]") == mapping(
            record.session_id
        )
        service.delete(record.session_id)


async def test_same_session_competition_and_send_after_visible_commit(tmp_path):
    with PersistentSessions.open(config(tmp_path), SecretStr("synthetic")) as service:
        record = service.create()
        sent, restore = asyncio.Event(), asyncio.Event()

        async def upstream():
            with sqlite3.connect(service.config.path) as db:
                assert db.execute("SELECT count(*) FROM entries").fetchone() == (1,)
            sent.set()
            await restore.wait()
            return "synthetic response"

        async def request():
            with service.use(record.session_id) as active:
                active.mappings["[PERSON_ABCD]"] = mapping(record.session_id)
                assert await active.send(upstream) == "synthetic response"
                # The lease also covers restoration after the callback returns.
                assert_busy(lambda: service.delete(record.session_id))

        task = asyncio.create_task(request())
        try:
            await asyncio.wait_for(sent.wait(), 1)
            assert_busy(lambda: service.lookup(record.session_id))
            assert_busy(lambda: service.delete(record.session_id))
        finally:
            restore.set()
            await task
        service.delete(record.session_id)


async def test_failed_mapping_commit_never_calls_send(tmp_path):
    with PersistentSessions.open(config(tmp_path), SecretStr("synthetic")) as service:
        record = service.create()
        service.insert_mappings([mapping(record.session_id)])
        called = False

        async def upstream():
            nonlocal called
            called = True

        with service.use(record.session_id) as active:
            active.mappings["[PERSON_ABCD]"] = mapping(record.session_id)
            with pytest.raises(sqlite3.IntegrityError):
                await active.send(upstream)
        assert not called
        assert service.lookup(record.session_id) == record


@pytest.mark.parametrize("cancel", [False, True])
async def test_cancellation_or_timeout_releases_lease_and_key(tmp_path, cancel):
    with PersistentSessions.open(config(tmp_path), SecretStr("synthetic")) as service:
        record = service.create()
        entered = asyncio.Event()
        states = []

        async def request():
            async with asyncio.timeout(10 if cancel else 0.01):
                with service.use(record.session_id) as state:
                    states.append(state)
                    state.mappings["[PERSON_ABCD]"] = mapping(record.session_id)

                    async def upstream():
                        entered.set()
                        await asyncio.Event().wait()

                    await state.send(upstream)

        task = asyncio.create_task(request())
        await asyncio.wait_for(entered.wait(), 1)
        if cancel:
            task.cancel()
        with pytest.raises(asyncio.CancelledError if cancel else TimeoutError):
            await task
        with pytest.raises(RuntimeError, match="closed"):
            _ = states[0].key
        service.delete(record.session_id)


def test_expiry_is_deferred_for_an_admitted_scope(tmp_path):
    now = datetime(2026, 1, 1, tzinfo=UTC)
    with PersistentSessions.open(
        config(tmp_path), SecretStr("synthetic"), clock=lambda: now
    ) as service:
        record = service.create()
        with service.use(record.session_id) as active:
            now = record.expires_at
            service.prune_expired()  # Busy sessions must be skipped.
            assert_busy(lambda: service.delete(record.session_id))
            active.mappings["[PERSON_ABCD]"] = mapping(record.session_id)
            active.commit_mappings()
            assert active.read_mapping("[PERSON_ABCD]") is not None
        with pytest.raises(SessionAccessError) as exc:
            service.lookup(record.session_id)
        assert exc.value.code == ErrorCode.SESSION_EXPIRED
        with sqlite3.connect(service.config.path) as db:
            assert db.execute("SELECT count(*) FROM entries").fetchone() == (0,)


def test_close_rejects_new_operations_but_allows_active_scope_to_finish(tmp_path):
    service = PersistentSessions.open(config(tmp_path), SecretStr("synthetic"))
    record = service.create()
    with service.use(record.session_id) as active:
        service.close()
        assert not service.is_unlocked
        with pytest.raises(SessionAccessError) as exc:
            service.create()
        assert exc.value.code == ErrorCode.VAULT_LOCKED
        active.mappings["[PERSON_ABCD]"] = mapping(record.session_id)
        active.commit_mappings()
    with pytest.raises(RuntimeError, match="closed"):
        _ = active.key
    # Last lease must release exclusive vault ownership too.
    with PersistentSessions.open(config(tmp_path), SecretStr("synthetic")):
        pass


def test_second_vault_owner_is_rejected(tmp_path):
    with PersistentSessions.open(config(tmp_path), SecretStr("synthetic")):
        with pytest.raises(VaultStartupError):
            PersistentSessions.open(config(tmp_path), SecretStr("synthetic"))


async def test_concurrent_ephemeral_requests_keep_independent_state():
    ready = asyncio.Event()
    states = []

    async def request(index):
        with ephemeral_session() as state:
            states.append(state)
            state.mappings[str(index)] = mapping(state.session_id)
            if len(states) == 2:
                ready.set()
            await asyncio.wait_for(ready.wait(), 1)
            assert set(state.mappings) == {str(index)}
            return state.key.get_secret_value()

    keys = await asyncio.gather(request(0), request(1))
    assert keys[0] != keys[1]
    assert all(not state.mappings for state in states)


async def test_busy_status_is_returned_by_session_and_chat_routes(tmp_path):
    import httpx

    from shield.app import create_app
    from shield.config import SessionsConfig, ShieldConfig
    from shield.credentials import RuntimeCredentials

    app = create_app(
        ShieldConfig(
            vault=config(tmp_path), sessions=SessionsConfig(persistent_enabled=True)
        ),
        RuntimeCredentials(vault_passphrase=SecretStr("synthetic")),
    )
    async with app.router.lifespan_context(app):
        record = app.state.vault.create()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            with app.state.vault.use(record.session_id):
                responses = [
                    await client.get(f"/shield/sessions/{record.session_id}"),
                    await client.delete(f"/shield/sessions/{record.session_id}"),
                    await client.post(
                        "/v1/chat/completions",
                        headers={"X-Shield-Session": record.session_id},
                        json={
                            "model": "synthetic",
                            "messages": [{"role": "user", "content": "Synthetic"}],
                        },
                    ),
                ]
                assert all(response.status_code == 409 for response in responses)
                assert all(
                    response.json()["error"]["code"] == "session_busy"
                    for response in responses
                )
                assert all(
                    "x-shield-session" not in response.headers for response in responses
                )
            assert (
                await client.delete(f"/shield/sessions/{record.session_id}")
            ).status_code == 204


def test_exclusive_vault_ownership_across_processes(tmp_path):
    import subprocess
    import sys

    code = """
import sys
from pathlib import Path
from shield.vault_owner import VaultOwnership
try:
    owner = VaultOwnership(Path(sys.argv[1]))
except OSError:
    sys.exit(10)
else:
    owner.close()
"""
    path = config(tmp_path).path
    with PersistentSessions.open(config(tmp_path), SecretStr("synthetic")):
        result = subprocess.run(
            [sys.executable, "-c", code, str(path)], capture_output=True, timeout=5
        )
        assert result.returncode == 10
    result = subprocess.run(
        [sys.executable, "-c", code, str(path)], capture_output=True, timeout=5
    )
    assert result.returncode == 0


def test_competing_thread_cannot_delete_an_active_session(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    with PersistentSessions.open(config(tmp_path), SecretStr("synthetic")) as service:
        record = service.create()
        with service.use(record.session_id), ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(assert_busy, lambda: service.delete(record.session_id)).result(
                timeout=1
            )
        service.delete(record.session_id)


async def test_pending_mapping_from_another_session_cannot_be_sent(tmp_path):
    with PersistentSessions.open(config(tmp_path), SecretStr("synthetic")) as service:
        first, second = service.create(), service.create()
        called = False

        async def callback():
            nonlocal called
            called = True

        with service.use(first.session_id) as state:
            state.mappings["[PERSON_ABCD]"] = mapping(second.session_id)
            with pytest.raises(SessionAccessError) as exc:
                await state.send(callback)
            assert exc.value.code == ErrorCode.INVALID_REQUEST
        assert not called


def test_startup_interruption_releases_vault_ownership(tmp_path, monkeypatch):
    def interrupted(self):
        raise KeyboardInterrupt

    with monkeypatch.context() as patch:
        patch.setattr(PersistentSessions, "prune_expired", interrupted)
        with pytest.raises(KeyboardInterrupt):
            PersistentSessions.open(config(tmp_path), SecretStr("synthetic"))
    with PersistentSessions.open(config(tmp_path), SecretStr("synthetic")):
        pass


async def test_cancelled_startup_closes_worker_result(tmp_path, monkeypatch):
    from threading import Event

    from shield.app import create_app
    from shield.config import SessionsConfig, ShieldConfig
    from shield.credentials import RuntimeCredentials

    opened, release, closed = Event(), Event(), Event()
    original_open = PersistentSessions.open
    original_close = PersistentSessions.close

    def delayed_open(*args, **kwargs):
        service = original_open(*args, **kwargs)
        opened.set()
        if not release.wait(3):
            service.close()
            raise RuntimeError("synthetic startup delay")
        return service

    def observed_close(service):
        original_close(service)
        closed.set()

    monkeypatch.setattr(PersistentSessions, "open", delayed_open)
    monkeypatch.setattr(PersistentSessions, "close", observed_close)
    app = create_app(
        ShieldConfig(
            vault=config(tmp_path), sessions=SessionsConfig(persistent_enabled=True)
        ),
        RuntimeCredentials(vault_passphrase=SecretStr("synthetic")),
    )
    context = app.router.lifespan_context(app)
    startup = asyncio.create_task(context.__aenter__())
    try:
        assert await asyncio.to_thread(opened.wait, 1)
        startup.cancel()
        with pytest.raises(asyncio.CancelledError):
            await startup
    finally:
        release.set()
    assert await asyncio.to_thread(closed.wait, 1)
    assert app.state.vault is None
    assert app.state.credentials.vault_passphrase is None
    with original_open(config(tmp_path), SecretStr("synthetic")):
        pass
