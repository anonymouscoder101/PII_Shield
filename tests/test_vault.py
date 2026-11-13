"""SQLite storage boundaries using synthetic, already-encrypted row values."""

import os
import sqlite3
import stat
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import ValidationError

from shield.contracts import EntityType
from shield.vault import (
    SCHEMA_VERSION,
    EntryRow,
    PersistentSessionRow,
    VaultSchemaError,
    VaultStore,
    entry_aad,
)


def session(session_id="synthetic-session"):
    return PersistentSessionRow(
        session_id=session_id,
        sk_nonce=b"n" * 12,
        sk_ct=b"k" * 48,
        created_at=100,
        expires_at=200,
    )


def entry(token="[PERSON_ABCD]", digest=b"d" * 32, session_id="synthetic-session"):
    return EntryRow(
        session_id=session_id,
        token=token,
        entity_type=EntityType.PERSON,
        entity_digest=digest,
        nonce=b"n" * 12,
        ciphertext=b"c" * 32,
    )


def counts(path):
    with sqlite3.connect(path) as db:
        return tuple(
            db.execute(f"SELECT count(*) FROM {name}").fetchone()[0]
            for name in ("sessions", "entries")
        )


def test_explicit_open_creates_versioned_reopenable_schema(tmp_path):
    path = tmp_path / "private" / "vault.db"
    store = VaultStore(path)
    assert not path.parent.exists()
    with store:
        store.insert_session(session(), entries=[entry()])
    with sqlite3.connect(path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        assert db.execute("SELECT count(*) FROM vault_meta").fetchone()[0] == 0
    with VaultStore(path):
        assert counts(path) == (1, 1)
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


@pytest.mark.parametrize("version", [0, SCHEMA_VERSION + 1])
def test_reject_incompatible_database_without_rewriting_it(tmp_path, version):
    path = tmp_path / "vault.db"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE existing (value TEXT)")
        db.execute("INSERT INTO existing VALUES (?)", ("synthetic",))
        db.execute(f"PRAGMA user_version = {version}")
    with pytest.raises(VaultSchemaError, match="schema"):
        with VaultStore(path):
            pass
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT value FROM existing").fetchone() == ("synthetic",)
        assert db.execute("PRAGMA user_version").fetchone()[0] == version


def test_foreign_keys_and_cascading_deletion(tmp_path):
    path = tmp_path / "vault.db"
    with VaultStore(path) as store:
        with pytest.raises(sqlite3.IntegrityError):
            store.insert_entries([entry()])
        store.insert_session(session(), entries=[entry()])
        with store.transaction() as db:
            assert db.execute("PRAGMA foreign_keys").fetchone() == (1,)
            db.execute(
                "DELETE FROM sessions WHERE session_id = ?", (session().session_id,)
            )
        assert counts(path) == (0, 0)


@pytest.mark.parametrize("conflict", [entry(), entry(token="[PERSON_OTHER]")])
def test_batch_conflict_rolls_back_every_insert(tmp_path, conflict):
    path = tmp_path / "vault.db"
    with VaultStore(path) as store:
        store.insert_session(session(), entries=[entry()])
        with pytest.raises(sqlite3.IntegrityError):
            store.insert_entries([entry("[PERSON_NEW]", b"e" * 32), conflict])
        assert counts(path) == (1, 1)


def test_session_and_entries_insert_is_one_transaction(tmp_path):
    path = tmp_path / "vault.db"
    with VaultStore(path) as store:
        with pytest.raises(sqlite3.IntegrityError):
            store.insert_session(session(), entries=[entry(), entry()])
        assert counts(path) == (0, 0)
        store.insert_session(session(), entries=[entry()])
        store.insert_session(session("second"), entries=[entry(session_id="second")])
        assert counts(path) == (2, 2)


def test_cancellation_rolls_back_and_connection_remains_usable(tmp_path):
    import asyncio

    path = tmp_path / "vault.db"
    with VaultStore(path) as store:
        with pytest.raises(asyncio.CancelledError):
            with store.transaction() as db:
                db.execute(
                    "INSERT INTO sessions VALUES (?, ?, ?, ?, ?)",
                    ("cancelled", b"n" * 12, b"k" * 48, 100, 200),
                )
                raise asyncio.CancelledError
        assert counts(path) == (0, 0)
        store.insert_session(session())
        assert counts(path) == (1, 0)


@pytest.mark.parametrize("digest", [b"", b"x" * 31, b"x" * 33, "x" * 32])
def test_digest_constraint_in_python_and_sql(tmp_path, digest):
    with pytest.raises(ValidationError):
        entry(digest=digest)
    with VaultStore(tmp_path / "vault.db") as store:
        store.insert_session(session())
        with pytest.raises(sqlite3.IntegrityError):
            with store.transaction() as db:
                db.execute(
                    "INSERT INTO entries VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "synthetic-session",
                        "[PERSON_X]",
                        "PERSON",
                        digest,
                        b"n" * 12,
                        b"c" * 32,
                    ),
                )


def test_aad_binds_all_identity_fields_without_delimiter_ambiguity():
    row = entry()
    aad = entry_aad(row)
    assert aad == entry_aad(row)
    key, nonce = AESGCM.generate_key(256), b"n" * 12
    cipher = AESGCM(key)
    ct = cipher.encrypt(nonce, b"Synthetic Person", aad)
    assert cipher.decrypt(nonce, ct, aad) == b"Synthetic Person"
    for changes in (
        {"session_id": "other"},
        {"token": "[PERSON_OTHER]"},
        {"entity_type": EntityType.SECRET},
        {"entity_digest": b"e" * 32},
    ):
        with pytest.raises(InvalidTag):
            cipher.decrypt(nonce, ct, entry_aad(row.model_copy(update=changes)))
    with pytest.raises(InvalidTag):
        cipher.decrypt(nonce, ct, entry_aad(row, schema_version=SCHEMA_VERSION + 1))
    assert entry_aad(
        row.model_copy(update={"session_id": "a|b", "token": "c"})
    ) != entry_aad(row.model_copy(update={"session_id": "a", "token": "b|c"}))
    assert row.entity_digest.hex().encode() in aad
    assert "ciphertext" not in repr(row)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission guarantees")
def test_existing_database_permissions_are_restricted(tmp_path):
    path = tmp_path / "vault.db"
    with VaultStore(path):
        pass
    path.chmod(0o666)
    with VaultStore(path):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlinks")
def test_reject_symlink_without_changing_target(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"synthetic untouched data")
    link = tmp_path / "vault.db"
    link.symlink_to(target)
    with pytest.raises(OSError):
        with VaultStore(link):
            pass
    assert target.read_bytes() == b"synthetic untouched data"


def test_default_app_never_creates_vault_artifacts(tmp_path):
    from shield.app import create_app
    from shield.config import ShieldConfig, VaultConfig

    path = tmp_path / "absent" / "vault.db"
    create_app(config=ShieldConfig(vault=VaultConfig(path=path)))
    assert not path.parent.exists()


def test_schema_drift_is_rejected(tmp_path):
    path = tmp_path / "vault.db"
    with VaultStore(path):
        pass
    with sqlite3.connect(path) as db:
        db.execute("ALTER TABLE entries ADD COLUMN unexpected TEXT")
    with pytest.raises(VaultSchemaError, match="schema"):
        with VaultStore(path):
            pass


def test_iteration_failure_rolls_back_partial_batch(tmp_path):
    path = tmp_path / "vault.db"

    def interrupted():
        yield entry()
        raise RuntimeError("synthetic interruption")

    with VaultStore(path) as store:
        store.insert_session(session())
        with pytest.raises(RuntimeError, match="interruption"):
            store.insert_entries(interrupted())
        assert counts(path) == (1, 0)


def test_ciphertext_round_trip_and_journal_permissions(tmp_path):
    path = tmp_path / "vault.db"
    raw = b"Synthetic Person Confidential Test Only"
    row = entry()
    cipher = AESGCM(AESGCM.generate_key(256))
    row = row.model_copy(
        update={"ciphertext": cipher.encrypt(row.nonce, raw, entry_aad(row))}
    )
    with VaultStore(path) as store:
        store.insert_session(session(), entries=[row])
        with store.transaction() as db:
            nonce, ct = db.execute("SELECT nonce, ciphertext FROM entries").fetchone()
            assert cipher.decrypt(nonce, ct, entry_aad(row)) == raw
            db.execute("UPDATE entries SET entity_digest = ?", (b"e" * 32,))
            digest = db.execute("SELECT entity_digest FROM entries").fetchone()[0]
            with pytest.raises(InvalidTag):
                cipher.decrypt(
                    nonce,
                    ct,
                    entry_aad(row.model_copy(update={"entity_digest": digest})),
                )
            journal = Path(str(path) + "-journal")
            assert journal.exists()
            if os.name == "posix":
                assert stat.S_IMODE(journal.stat().st_mode) == 0o600
            for artifact in tmp_path.iterdir():
                assert raw not in artifact.read_bytes()
    for artifact in tmp_path.iterdir():
        assert raw not in artifact.read_bytes()


def test_closed_store_and_nested_transactions_fail_clearly(tmp_path):
    store = VaultStore(tmp_path / "vault.db")
    with pytest.raises(RuntimeError, match="closed"):
        store.insert_session(session())
    with store:
        with store.transaction():
            with pytest.raises(RuntimeError, match="nested"):
                with store.transaction():
                    pass
    with pytest.raises(RuntimeError, match="closed"):
        store.insert_entries([entry()])


def test_unexpected_trigger_is_rejected_before_inserts(tmp_path):
    path = tmp_path / "vault.db"
    with VaultStore(path):
        pass
    with sqlite3.connect(path) as db:
        db.execute("""CREATE TRIGGER discard_entry AFTER INSERT ON entries
                      BEGIN DELETE FROM entries WHERE session_id = NEW.session_id
                      AND token = NEW.token; END""")
    with pytest.raises(VaultSchemaError, match="schema"):
        with VaultStore(path):
            pass
    assert counts(path) == (0, 0)
