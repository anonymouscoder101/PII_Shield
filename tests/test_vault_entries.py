"""Synthetic entry values exercised through production encryption and storage."""

import sqlite3

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import SecretBytes, SecretStr

from shield.config import Argon2Config
from shield.contracts import EntityType, TokenMapping
from shield.vault import (
    PersistentSessionRow,
    VaultEntryError,
    VaultStore,
    decrypt_entry,
    encrypt_entry,
    entry_aad,
)


def mapping(**changes):
    fields = dict(
        session_id="synthetic-session",
        token="[PERSON_ABCD]",
        entity_type=EntityType.PERSON,
        entity_digest=b"d" * 32,
        original_value=SecretStr("Synthetic Person 🛡️ e\u0301"),
    )
    return TokenMapping(**(fields | changes))


def key():
    return SecretBytes(AESGCM.generate_key(bit_length=256))


def session(session_id="synthetic-session"):
    # Wrapped HMAC keys are implemented in task 4; these are synthetic row bytes.
    return PersistentSessionRow(
        session_id=session_id,
        sk_nonce=b"n" * 12,
        sk_ct=b"c" * 48,
        created_at=1,
        expires_at=2,
    )


def test_encrypt_decrypt_unicode_and_fresh_nonces():
    secret = key()
    original = mapping()
    rows = [encrypt_entry(original, secret) for _ in range(16)]
    assert len({row.nonce for row in rows}) == 16
    assert all(len(row.nonce) == 12 for row in rows)
    assert len({row.ciphertext for row in rows}) == 16
    for row in rows:
        restored = decrypt_entry(row, secret)
        assert restored == original
        assert original.original_value.get_secret_value() not in repr(row)
        assert (
            AESGCM(secret.get_secret_value()).decrypt(
                row.nonce, row.ciphertext, entry_aad(row)
            )
            == original.original_value.get_secret_value().encode()
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"session_id": "another-session"},
        {"token": "[PERSON_OTHER]"},
        {"entity_type": EntityType.SECRET},
        {"entity_digest": b"e" * 32},
        {"nonce": b"x" * 12},
        {"ciphertext": b"x" * 32},
    ],
)
def test_every_identity_field_and_ciphertext_are_authenticated(changes, caplog):
    secret = key()
    row = encrypt_entry(mapping(), secret)
    with pytest.raises(VaultEntryError) as error:
        decrypt_entry(row.model_copy(update=changes), secret)
    assert str(error.value) == "Vault entry authentication failed."
    assert not caplog.text


@pytest.mark.parametrize("length", [16, 24, 31, 33])
def test_only_256_bit_keys_are_accepted(length):
    wrong = SecretBytes(b"k" * length)
    with pytest.raises(VaultEntryError):
        encrypt_entry(mapping(), wrong)
    with pytest.raises(VaultEntryError):
        decrypt_entry(encrypt_entry(mapping(), key()), wrong)


def test_wrong_key_and_changed_aad_version_or_domain_fail():
    secret = key()
    original = mapping()
    row = encrypt_entry(original, secret)
    with pytest.raises(VaultEntryError):
        decrypt_entry(row, key())
    for aad in (
        entry_aad(row, schema_version=2),
        entry_aad(row).replace(b"pii-shield/entry", b"pii-shield/verifier"),
    ):
        ciphertext = AESGCM(secret.get_secret_value()).encrypt(
            row.nonce, b"Synthetic", aad
        )
        with pytest.raises(VaultEntryError):
            decrypt_entry(row.model_copy(update={"ciphertext": ciphertext}), secret)


@pytest.mark.parametrize("mode", ["DELETE", "WAL"])
def test_sqlite_restart_round_trip_and_no_plaintext_artifacts(tmp_path, mode):
    path = tmp_path / "vault.db"
    original = mapping()
    raw = original.original_value.get_secret_value().encode()
    with VaultStore(path) as store:
        secret = store.initialize(
            SecretStr("synthetic passphrase"),
            params=Argon2Config(memory_kib=32, time_cost=1, parallelism=1),
        )
        with sqlite3.connect(path) as db:
            db.execute(f"PRAGMA journal_mode = {mode}")
        store.insert_session(session())
        store.insert_mappings([original], secret)
        assert (
            store.read_mapping(original.session_id, original.token, secret) == original
        )
        assert store.read_mapping("other-session", original.token, secret) is None
        assert (
            store.read_mapping(original.session_id, "[PERSON_UNKNOWN]", secret) is None
        )
        with store.transaction() as db:
            db.execute("UPDATE entries SET ciphertext = ciphertext")
            for file in tmp_path.iterdir():
                assert raw not in file.read_bytes()
                assert secret.get_secret_value() not in file.read_bytes()
    with VaultStore(path) as store:
        reopened_key = store.unlock(SecretStr("synthetic passphrase"))
        assert (
            store.read_mapping(original.session_id, original.token, reopened_key)
            == original
        )
    for file in tmp_path.iterdir():
        assert raw not in file.read_bytes()


@pytest.mark.parametrize("different_session", [False, True])
def test_swapped_sqlite_ciphertexts_fail(different_session, tmp_path):
    secret = key()
    one = mapping()
    two = mapping(
        token="[PERSON_EFGH]",
        entity_digest=b"e" * 32,
        session_id="other" if different_session else one.session_id,
        original_value=SecretStr("Second Synthetic Person"),
    )
    with VaultStore(tmp_path / "vault.db") as store:
        store.insert_session(session())
        if different_session:
            store.insert_session(session("other"))
        store.insert_mappings([one, two], secret)
        with store.transaction() as db:
            rows = db.execute(
                "SELECT nonce, ciphertext FROM entries ORDER BY token"
            ).fetchall()
            for original, replacement in ((one, rows[1]), (two, rows[0])):
                db.execute(
                    "UPDATE entries SET nonce=?, ciphertext=? "
                    "WHERE session_id=? AND token=?",
                    (*replacement, original.session_id, original.token),
                )
        for original in (one, two):
            with pytest.raises(VaultEntryError):
                store.read_mapping(original.session_id, original.token, secret)


def test_invalid_stored_type_fails_with_safe_error(tmp_path):
    secret = key()
    original = mapping()
    with VaultStore(tmp_path / "vault.db") as store:
        store.insert_session(session())
        store.insert_mappings([original], secret)
        with store.transaction() as db:
            db.execute(
                "UPDATE entries SET entity_type = ?", ("synthetic-invalid-type",)
            )
        with pytest.raises(VaultEntryError, match="authentication failed"):
            store.read_mapping(original.session_id, original.token, secret)


def test_encrypted_batch_conflict_preserves_first_spelling_and_rolls_back(tmp_path):
    secret = key()
    first = mapping()
    with VaultStore(tmp_path / "vault.db") as store:
        store.insert_session(session())
        store.insert_mappings([first], secret)
        with pytest.raises(sqlite3.IntegrityError):
            store.insert_mappings(
                [
                    mapping(token="[PERSON_NEW]", entity_digest=b"e" * 32),
                    mapping(original_value=SecretStr("Synthetic Variant")),
                ],
                secret,
            )
        assert store.read_mapping(first.session_id, first.token, secret) == first
        assert store.read_mapping(first.session_id, "[PERSON_NEW]", secret) is None


def test_encryption_failure_rolls_back_partial_batch(tmp_path, monkeypatch):
    from shield import vault

    secret = key()
    one = mapping()
    two = mapping(token="[PERSON_NEW]", entity_digest=b"e" * 32)
    random_bytes = vault.os.urandom
    calls = 0

    def fail_second_nonce(size):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("synthetic nonce generation failure")
        return random_bytes(size)

    with VaultStore(tmp_path / "vault.db") as store:
        store.insert_session(session())
        monkeypatch.setattr(vault.os, "urandom", fail_second_nonce)
        with pytest.raises(VaultEntryError, match="encryption failed"):
            store.insert_mappings([one, two], secret)
        assert store.read_mapping(one.session_id, one.token, secret) is None
        assert store.read_mapping(two.session_id, two.token, secret) is None


def test_full_digest_tampering_on_disk_fails_authentication(tmp_path):
    secret = key()
    original = mapping()
    with VaultStore(tmp_path / "vault.db") as store:
        store.insert_session(session())
        store.insert_mappings([original], secret)
        with store.transaction() as db:
            db.execute("UPDATE entries SET entity_digest = ?", (b"e" * 32,))
        with pytest.raises(VaultEntryError, match="authentication failed"):
            store.read_mapping(original.session_id, original.token, secret)
