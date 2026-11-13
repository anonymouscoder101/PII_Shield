"""Synthetic passphrases only; real Argon2id and AES-GCM verification."""

import json
import sqlite3

import pytest
from argon2.low_level import Type, hash_secret_raw
from pydantic import SecretStr

from shield.config import Argon2Config
from shield.vault import VaultStore
from shield.vault_crypto import VaultInitializationError, VaultUnlockError

PASSWORD = SecretStr("synthetic passphrase 🛡️")
FAST = Argon2Config(memory_kib=32, time_cost=1, parallelism=1)


def metadata(path):
    with sqlite3.connect(path) as db:
        return db.execute(
            "SELECT salt, kdf_params, verifier_nonce, verifier_ct FROM vault_meta"
        ).fetchone()


def test_default_derivation_matches_argon2id_and_survives_restart(tmp_path):
    path = tmp_path / "vault.db"
    with VaultStore(path) as store:
        key = store.initialize(PASSWORD)
        assert len(key.get_secret_value()) == 32
        assert key.get_secret_value().hex() not in repr(key)
    salt, params, nonce, ct = metadata(path)
    assert len(salt) == 16 and len(nonce) == 12
    assert len(ct) > 16
    assert json.loads(params) == dict(
        algorithm="argon2id",
        version=19,
        hash_len=32,
        memory_kib=65536,
        time_cost=3,
        parallelism=4,
    )
    assert key.get_secret_value() == hash_secret_raw(
        PASSWORD.get_secret_value().encode(), salt, 3, 65536, 4, 32, Type.ID, version=19
    )
    with VaultStore(path) as store:
        assert store.unlock(PASSWORD).get_secret_value() == key.get_secret_value()
    for file in tmp_path.iterdir():
        assert PASSWORD.get_secret_value().encode() not in file.read_bytes()
        assert key.get_secret_value() not in file.read_bytes()


def test_fresh_vaults_have_independent_salts_nonces_and_keys(tmp_path):
    keys = []
    headers = []
    for i in range(2):
        path = tmp_path / f"{i}.db"
        with VaultStore(path) as store:
            keys.append(store.initialize(PASSWORD, params=FAST).get_secret_value())
        headers.append(metadata(path))
    assert keys[0] != keys[1]
    assert headers[0][0] != headers[1][0]
    assert headers[0][2] != headers[1][2]


def test_wrong_passphrase_fails_without_rewriting_metadata(tmp_path, caplog):
    path = tmp_path / "vault.db"
    with VaultStore(path) as store:
        key = store.initialize(PASSWORD, params=FAST)
        before = metadata(path)
        with pytest.raises(VaultUnlockError) as error:
            store.unlock(SecretStr("synthetic wrong passphrase"))
        assert PASSWORD.get_secret_value() not in str(error.value)
        assert metadata(path) == before
        assert store.unlock(PASSWORD).get_secret_value() == key.get_secret_value()
    assert "passphrase" not in caplog.text


@pytest.mark.parametrize(
    "column,value",
    [
        ("salt", b"x" * 16),
        ("salt", b"x"),
        ("verifier_nonce", b"x" * 12),
        ("verifier_ct", b"x" * 48),
        ("kdf_params", "{}"),
        ("kdf_params", "{invalid"),
        (
            "kdf_params",
            json.dumps(
                dict(
                    algorithm="argon2i",
                    version=19,
                    hash_len=32,
                    memory_kib=32,
                    time_cost=1,
                    parallelism=1,
                )
            ),
        ),
        (
            "kdf_params",
            json.dumps(
                dict(
                    algorithm="argon2id",
                    version=19,
                    hash_len=32,
                    memory_kib=2147483647,
                    time_cost=1,
                    parallelism=1,
                )
            ),
        ),
    ],
)
def test_corrupt_metadata_fails_closed(tmp_path, column, value):
    path = tmp_path / "vault.db"
    with VaultStore(path) as store:
        store.initialize(PASSWORD, params=FAST)
        with store.transaction() as db:
            db.execute(f"UPDATE vault_meta SET {column} = ?", (value,))
        with pytest.raises(VaultUnlockError):
            store.unlock(PASSWORD)


def test_valid_but_tampered_kdf_parameters_fail_authentication(tmp_path):
    path = tmp_path / "vault.db"
    with VaultStore(path) as store:
        store.initialize(PASSWORD, params=FAST)
        salt, params, *_ = metadata(path)
        changed = json.loads(params)
        changed["time_cost"] = 2
        with store.transaction() as db:
            db.execute("UPDATE vault_meta SET kdf_params = ?", (json.dumps(changed),))
        with pytest.raises(VaultUnlockError):
            store.unlock(PASSWORD)


def test_initialize_never_replaces_existing_metadata(tmp_path):
    path = tmp_path / "vault.db"
    with VaultStore(path) as store:
        with pytest.raises(VaultUnlockError):
            store.unlock(PASSWORD)
        store.initialize(PASSWORD, params=FAST)
        before = metadata(path)
        with pytest.raises(VaultInitializationError):
            store.initialize(SecretStr("different synthetic passphrase"), params=FAST)
        assert metadata(path) == before


def test_missing_metadata_with_existing_sessions_cannot_be_reinitialized(tmp_path):
    path = tmp_path / "vault.db"
    with VaultStore(path) as store:
        with store.transaction() as db:
            db.execute(
                "INSERT INTO sessions VALUES (?, ?, ?, ?, ?)",
                ("synthetic", b"n" * 12, b"c" * 48, 1, 2),
            )
        with pytest.raises(VaultInitializationError):
            store.initialize(PASSWORD, params=FAST)
        assert metadata(path) is None


@pytest.mark.parametrize("password", [SecretStr(""), SecretStr("  ")])
def test_empty_password_leaves_metadata_uninitialized(tmp_path, password):
    path = tmp_path / "vault.db"
    with VaultStore(path) as store:
        with pytest.raises(VaultInitializationError):
            store.initialize(password, params=FAST)
        assert metadata(path) is None


def test_incomplete_default_kdf_metadata_is_rejected(tmp_path):
    path = tmp_path / "vault.db"
    with VaultStore(path) as store:
        store.initialize(PASSWORD)
        with store.transaction() as db:
            db.execute("UPDATE vault_meta SET kdf_params = '{}' ")
        with pytest.raises(VaultUnlockError):
            store.unlock(PASSWORD)


def test_verifier_failure_during_initialization_rolls_back(tmp_path, monkeypatch):
    from shield import vault_crypto

    path = tmp_path / "vault.db"

    def failed_nonce(size):
        raise OSError("synthetic random source failure")

    with VaultStore(path) as store:
        with monkeypatch.context() as patch:
            patch.setattr(vault_crypto.os, "urandom", failed_nonce)
            with pytest.raises(VaultInitializationError):
                store.initialize(PASSWORD, params=FAST)
        assert metadata(path) is None
        store.initialize(PASSWORD, params=FAST)
        store.unlock(PASSWORD)


def test_excessive_cost_is_rejected_before_argon2(tmp_path, monkeypatch):
    from shield import vault_crypto

    path = tmp_path / "vault.db"
    with VaultStore(path) as store:
        store.initialize(PASSWORD, params=FAST)
        values = json.loads(metadata(path)[1])
        values["memory_kib"] = 2147483647
        with store.transaction() as db:
            db.execute("UPDATE vault_meta SET kdf_params = ?", (json.dumps(values),))

        def unexpected_derivation(*args, **kwargs):
            pytest.fail("untrusted costs reached Argon2")

        monkeypatch.setattr(vault_crypto, "hash_secret_raw", unexpected_derivation)
        with pytest.raises(VaultUnlockError):
            store.unlock(PASSWORD)


def test_stored_verifier_uses_distinct_authenticated_domain(tmp_path):
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from shield.vault_crypto import KDFParameters, verifier_aad

    path = tmp_path / "vault.db"
    with VaultStore(path) as store:
        key = store.initialize(PASSWORD, params=FAST)
    salt, serialized, nonce, ct = metadata(path)
    params = KDFParameters.model_validate_json(serialized)
    aad = verifier_aad(salt, params, 1)
    cipher = AESGCM(key.get_secret_value())
    assert cipher.decrypt(nonce, ct, aad) == b"pii-shield vault unlock verifier v1"
    for altered in (aad.replace(b"verifier", b"entry"), verifier_aad(salt, params, 2)):
        with pytest.raises(InvalidTag):
            cipher.decrypt(nonce, ct, altered)
