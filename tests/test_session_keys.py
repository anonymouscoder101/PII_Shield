"""Synthetic session keys and request-local ephemeral state."""

import asyncio
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import SecretBytes, SecretStr

from shield.contracts import EntityType, SessionKind, SessionRecord, TokenMapping
from shield.session import ephemeral_session, generate_hmac_key
from shield.vault import (
    PersistentSessionRow,
    VaultSessionKeyError,
    VaultStore,
    session_key_aad,
    unwrap_session_key,
    wrap_session_key,
)


def record(kind=SessionKind.PERSISTENT, session_id="synthetic-session"):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    return SessionRecord(
        session_id=session_id,
        kind=kind,
        created_at=start,
        expires_at=start + timedelta(hours=1)
        if kind == SessionKind.PERSISTENT
        else None,
    )


def vault_key():
    return SecretBytes(AESGCM.generate_key(bit_length=256))


def test_request_local_keys_and_mappings_are_independent_and_released():
    with ephemeral_session() as first, ephemeral_session() as second:
        assert first.session_id != second.session_id
        assert len(first.key.get_secret_value()) == 32
        assert first.key.get_secret_value() != second.key.get_secret_value()
        assert first.mappings is not second.mappings
        first.mappings["[PERSON_ABCD]"] = TokenMapping(
            session_id=first.session_id,
            token="[PERSON_ABCD]",
            entity_type=EntityType.PERSON,
            entity_digest=b"d" * 32,
            original_value=SecretStr("Synthetic Person"),
        )
        assert not second.mappings
        assert first.key.get_secret_value().hex() not in repr(first)
    assert not first.mappings
    with pytest.raises(RuntimeError, match="closed"):
        _ = first.key


@pytest.mark.parametrize(
    "error", [RuntimeError("synthetic failure"), asyncio.CancelledError()]
)
def test_ephemeral_context_releases_on_failure_or_cancellation(error):
    with pytest.raises(type(error)):
        with ephemeral_session() as state:
            state.mappings["synthetic"] = None
            raise error
    assert not state.mappings
    with pytest.raises(RuntimeError, match="closed"):
        _ = state.key


def test_wrap_round_trip_and_fresh_nonce():
    key, vk, metadata = generate_hmac_key(), vault_key(), record()
    rows = [wrap_session_key(metadata, key, vk) for _ in range(8)]
    assert len({row.sk_nonce for row in rows}) == 8
    for row in rows:
        assert len(row.sk_nonce) == 12 and len(row.sk_ct) == 48
        assert unwrap_session_key(row, vk).get_secret_value() == key.get_secret_value()
        assert (
            AESGCM(vk.get_secret_value()).decrypt(
                row.sk_nonce, row.sk_ct, session_key_aad(row)
            )
            == key.get_secret_value()
        )
        assert key.get_secret_value().hex() not in repr(row)


def test_ephemeral_metadata_cannot_be_wrapped():
    with pytest.raises(VaultSessionKeyError):
        wrap_session_key(
            record(SessionKind.EPHEMERAL), generate_hmac_key(), vault_key()
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"session_id": "another"},
        {"created_at": 0},
        {"expires_at": 9999999999},
        {"sk_nonce": b"x" * 12},
        {"sk_ct": b"x" * 48},
    ],
)
def test_wrapped_key_tampering_fails(changes, caplog):
    vk = vault_key()
    row = wrap_session_key(record(), generate_hmac_key(), vk)
    with pytest.raises(VaultSessionKeyError, match="authentication failed"):
        unwrap_session_key(row.model_copy(update=changes), vk)
    assert not caplog.text


def test_wrapped_key_domain_and_schema_cannot_be_substituted():
    vk, key = vault_key(), generate_hmac_key()
    row = wrap_session_key(record(), key, vk)
    for aad in (
        session_key_aad(row, schema_version=2),
        session_key_aad(row).replace(b"pii-shield/session-key", b"pii-shield/verifier"),
        session_key_aad(row).replace(b"pii-shield/session-key", b"pii-shield/entry"),
    ):
        ct = AESGCM(vk.get_secret_value()).encrypt(
            row.sk_nonce, key.get_secret_value(), aad
        )
        with pytest.raises(VaultSessionKeyError):
            unwrap_session_key(row.model_copy(update={"sk_ct": ct}), vk)
    with pytest.raises(VaultSessionKeyError):
        unwrap_session_key(row, vault_key())


@pytest.mark.parametrize("length", [16, 24, 31, 33])
def test_wrapping_requires_32_byte_session_and_vault_keys(length):
    bad = SecretBytes(b"k" * length)
    with pytest.raises(VaultSessionKeyError):
        wrap_session_key(record(), bad, vault_key())
    with pytest.raises(VaultSessionKeyError):
        wrap_session_key(record(), generate_hmac_key(), bad)
    row = wrap_session_key(record(), generate_hmac_key(), vault_key())
    with pytest.raises(VaultSessionKeyError):
        unwrap_session_key(row, bad)


def test_persistent_wrapped_key_survives_restart_without_plaintext(tmp_path):
    from shield.config import Argon2Config

    path = tmp_path / "vault.db"
    secret = generate_hmac_key()
    with VaultStore(path) as store:
        vk = store.initialize(
            SecretStr("synthetic passphrase"),
            params=Argon2Config(memory_kib=32, time_cost=1, parallelism=1),
        )
        store.insert_session(wrap_session_key(record(), secret, vk))
    with VaultStore(path) as store:
        vk = store.unlock(SecretStr("synthetic passphrase"))
        with store.transaction() as db:
            values = db.execute(
                "SELECT session_id, sk_nonce, sk_ct, created_at, expires_at "
                "FROM sessions"
            ).fetchone()
        row = PersistentSessionRow(
            **dict(
                zip(
                    ("session_id", "sk_nonce", "sk_ct", "created_at", "expires_at"),
                    values,
                    strict=True,
                )
            )
        )
        assert (
            unwrap_session_key(row, vk).get_secret_value() == secret.get_secret_value()
        )
    for artifact in tmp_path.iterdir():
        assert secret.get_secret_value() not in artifact.read_bytes()
        assert vk.get_secret_value() not in artifact.read_bytes()


async def test_chat_requests_get_fresh_ephemeral_state_without_disk(
    tmp_path, monkeypatch
):
    from contextlib import contextmanager

    from shield import app as app_module
    from shield.config import ShieldConfig, VaultConfig

    states, keys = [], []

    @contextmanager
    def capture_context():
        with ephemeral_session() as state:
            states.append(state)
            keys.append(state.key.get_secret_value())
            yield state

    monkeypatch.setattr(app_module, "ephemeral_session", capture_context)
    path = tmp_path / "not-created" / "vault.db"
    app = app_module.create_app(ShieldConfig(vault=VaultConfig(path=path)))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        for _ in range(2):
            response = await client.post(
                "/v1/chat/completions",
                json={
                    "model": "synthetic",
                    "messages": [{"role": "user", "content": "synthetic"}],
                },
            )
            assert response.status_code == 503
            assert "x-shield-session" not in response.headers
        response = await client.post(
            "/v1/chat/completions",
            headers={"X-Shield-Session": "selected"},
            json={
                "model": "synthetic",
                "messages": [{"role": "user", "content": "synthetic"}],
            },
        )
        assert response.status_code == 423
    assert len(states) == 2 and keys[0] != keys[1]
    for state in states:
        with pytest.raises(RuntimeError, match="closed"):
            _ = state.key
    assert not path.parent.exists()


def test_random_failure_returns_safe_error(monkeypatch):
    from shield import session

    def failed_random(size):
        raise OSError("synthetic sensitive underlying failure")

    monkeypatch.setattr(session.os, "urandom", failed_random)
    with pytest.raises(session.SessionKeyError) as error:
        generate_hmac_key()
    assert str(error.value) == "Session key generation failed."


def test_wrapped_key_ciphertext_swapping_is_rejected():
    vk = vault_key()
    first = wrap_session_key(record(session_id="one"), generate_hmac_key(), vk)
    second = wrap_session_key(record(session_id="two"), generate_hmac_key(), vk)
    for destination, source in ((first, second), (second, first)):
        with pytest.raises(VaultSessionKeyError):
            unwrap_session_key(
                destination.model_copy(
                    update={"sk_nonce": source.sk_nonce, "sk_ct": source.sk_ct}
                ),
                vk,
            )
