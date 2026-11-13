"""Synthetic identity allocation, forced suffix collisions, and first spelling."""

from concurrent.futures import ThreadPoolExecutor

import pytest
from pydantic import SecretStr

from shield.config import Argon2Config, VaultConfig
from shield.contracts import EntityType
from shield.persistent import PersistentSessions
from shield.pseudonym import TokenCollisionError, derive_token, format_token
from shield.session import ephemeral_session


def settings(tmp_path):
    return VaultConfig(
        path=tmp_path / "vault.db",
        argon2=Argon2Config(memory_kib=32, time_cost=1, parallelism=1),
    )


def force_digest(monkeypatch, digest):
    # Replace only the digest derivation; actual allocation and crypto stay real.
    from shield import pseudonym

    original = derive_token

    def forced(entity, value, key, **kwargs):
        result = original(entity, value, key, **kwargs)
        return result.model_copy(
            update={"entity_digest": digest, "token": format_token(entity, digest)}
        )

    monkeypatch.setattr(pseudonym, "derive_token", forced)


def test_ephemeral_reuses_full_identity_and_preserves_first_spelling(
    tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    with ephemeral_session() as state:
        first = state.allocate(EntityType.PERSON, SecretStr("  José Smith "))
        second = state.allocate(EntityType.PERSON, SecretStr("JOSE\u0301 SMITH"))
        assert (
            second.token == first.token and second.entity_digest == first.entity_digest
        )
        assert not first.reused and second.reused
        assert len(state.mappings) == 1
        assert (
            state.mappings[first.token].original_value.get_secret_value()
            == "  José Smith "
        )
    assert not state.mappings
    assert not list(tmp_path.iterdir())


def test_secret_case_variants_have_distinct_identity():
    with ephemeral_session() as state:
        first = state.allocate(EntityType.SECRET, SecretStr("Synthetic"))
        second = state.allocate(EntityType.SECRET, SecretStr("synthetic"))
        assert first.entity_digest != second.entity_digest
        assert first.token != second.token


def test_forced_prefix_collisions_extend_deterministically_without_overwrite(
    monkeypatch,
):
    with ephemeral_session() as state:
        values = []
        for i, length in enumerate((4, 6, 8, 12, 16, 20, 24, 28, 32)):
            force_digest(monkeypatch, bytes(31) + bytes([i]))
            value = state.allocate(EntityType.PERSON, SecretStr(f"Synthetic {i}"))
            assert value.token == format_token(
                EntityType.PERSON, value.entity_digest, suffix_length=length
            )
            assert value.collision_count == i
            values.append(value)
        for i, value in enumerate(values):
            assert (
                state.mappings[value.token].original_value.get_secret_value()
                == f"Synthetic {i}"
            )
        with pytest.raises(TokenCollisionError):
            force_digest(monkeypatch, bytes(31) + b"\xff")
            state.allocate(EntityType.PERSON, SecretStr("Synthetic exhausted"))
        assert len(state.mappings) == 9
        # Full-digest lookup must reuse the original token rather than extend again.
        force_digest(monkeypatch, bytes(31) + b"\x02")
        reused = state.allocate(
            EntityType.PERSON, SecretStr("different synthetic spelling")
        )
        assert reused.reused and reused.token == values[2].token


def test_ephemeral_concurrent_allocations_create_one_mapping():
    with ephemeral_session() as state, ThreadPoolExecutor(max_workers=8) as pool:
        results = list(
            pool.map(
                lambda _: state.allocate(EntityType.PERSON, SecretStr("Synthetic")),
                range(24),
            )
        )
        assert len({value.token for value in results}) == 1
        assert sum(not value.reused for value in results) == 1
        assert len(state.mappings) == 1


def test_persistent_reuse_avoids_decryption_and_survives_restart(tmp_path, monkeypatch):
    from shield import vault

    with PersistentSessions.open(settings(tmp_path), SecretStr("synthetic")) as service:
        record = service.create()
        with service.use(record.session_id) as active:
            first = active.allocate(EntityType.PERSON, SecretStr(" Alice  Smith "))

            def forbidden(*args, **kwargs):
                pytest.fail("identity lookup must not decrypt an original value")

            with monkeypatch.context() as patch:
                patch.setattr(vault, "decrypt_entry", forbidden)
                repeated = active.allocate(EntityType.PERSON, SecretStr("ALICE SMITH"))
            assert repeated.reused and repeated.token == first.token
            assert (
                active.read_mapping(first.token).original_value.get_secret_value()
                == " Alice  Smith "
            )
    with PersistentSessions.open(settings(tmp_path), SecretStr("synthetic")) as service:
        with service.use(record.session_id) as active:
            repeated = active.allocate(EntityType.PERSON, SecretStr("alice smith"))
            assert repeated.reused and repeated.token == first.token
            assert (
                active.read_mapping(first.token).original_value.get_secret_value()
                == " Alice  Smith "
            )


def test_persistent_collision_keeps_both_values_and_reuses_extended_token(
    tmp_path, monkeypatch
):
    with PersistentSessions.open(settings(tmp_path), SecretStr("synthetic")) as service:
        record = service.create()
        with service.use(record.session_id) as active:
            force_digest(monkeypatch, bytes(32))
            first = active.allocate(EntityType.PERSON, SecretStr("Synthetic first"))
            force_digest(monkeypatch, bytes(31) + b"\x01")
            second = active.allocate(EntityType.PERSON, SecretStr("Synthetic second"))
            assert second.token == format_token(
                EntityType.PERSON, second.entity_digest, suffix_length=6
            )
            assert second.collision_count == 1
            repeated = active.allocate(
                EntityType.PERSON, SecretStr("Synthetic variant")
            )
            assert repeated.reused and repeated.token == second.token
            assert (
                active.read_mapping(first.token).original_value.get_secret_value()
                == "Synthetic first"
            )
            assert (
                active.read_mapping(second.token).original_value.get_secret_value()
                == "Synthetic second"
            )


def test_raw_vault_concurrent_allocations_are_one_transaction_each(tmp_path):
    from shield.session import generate_hmac_key
    from shield.vault import PersistentSessionRow, VaultStore

    config = settings(tmp_path)
    hmac_key = generate_hmac_key()
    with VaultStore(config.path) as store:
        vault_key = store.initialize(SecretStr("synthetic"), params=config.argon2)
        store.insert_session(
            PersistentSessionRow(
                session_id="synthetic",
                sk_nonce=b"n" * 12,
                sk_ct=b"c" * 48,
                created_at=1,
                expires_at=2,
            )
        )

    def allocate(_):
        with VaultStore(config.path) as store:
            return store.allocate_token(
                "synthetic",
                EntityType.PERSON,
                SecretStr("Synthetic"),
                hmac_key,
                vault_key,
            )

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(allocate, range(18)))
    assert len({item.token for item in results}) == 1
    assert sum(not item.reused for item in results) == 1


def test_persistent_failure_rolls_back_without_reserving_suffix(tmp_path, monkeypatch):
    from shield import vault
    from shield.pseudonym import PseudonymError

    with PersistentSessions.open(settings(tmp_path), SecretStr("synthetic")) as service:
        record = service.create()
        with service.use(record.session_id) as active:

            def failed(*args, **kwargs):
                raise RuntimeError("synthetic encryption failure")

            with monkeypatch.context() as patch:
                patch.setattr(vault, "encrypt_entry", failed)
                with pytest.raises(PseudonymError):
                    active.allocate(EntityType.PERSON, SecretStr("Synthetic"))
            allocated = active.allocate(EntityType.PERSON, SecretStr("Synthetic"))
            assert not allocated.reused and allocated.collision_count == 0
            assert (
                active.read_mapping(allocated.token).original_value.get_secret_value()
                == "Synthetic"
            )


def test_external_memory_mapping_changes_rebuild_digest_index():
    from shield.contracts import TokenMapping
    from shield.pseudonym import PseudonymError

    with ephemeral_session() as state:
        allocated = state.allocate(EntityType.PERSON, SecretStr("Synthetic"))
        state.mappings.clear()
        renewed = state.allocate(EntityType.PERSON, SecretStr("Synthetic"))
        assert not renewed.reused and renewed.token == allocated.token
        del state.mappings[renewed.token]
        state.mappings[renewed.token] = TokenMapping(
            session_id=state.session_id,
            token=renewed.token,
            entity_type=EntityType.PERSON,
            entity_digest=renewed.entity_digest,
            original_value=SecretStr("first imported spelling"),
        )
        assert state.allocate(EntityType.PERSON, SecretStr("SYNTHETIC")).reused
        state.mappings[renewed.token] = None
        with pytest.raises(PseudonymError):
            state.allocate(EntityType.PERSON, SecretStr("Synthetic"))


def test_persistent_exhaustion_does_not_insert_an_extra_row(tmp_path, monkeypatch):
    import sqlite3

    with PersistentSessions.open(settings(tmp_path), SecretStr("synthetic")) as service:
        record = service.create()
        with service.use(record.session_id) as active:
            for i in range(9):
                force_digest(monkeypatch, bytes(31) + bytes([i]))
                active.allocate(EntityType.PERSON, SecretStr(f"Synthetic {i}"))
            force_digest(monkeypatch, bytes(31) + b"\xff")
            with pytest.raises(TokenCollisionError):
                active.allocate(EntityType.PERSON, SecretStr("Synthetic exhausted"))
        with sqlite3.connect(service.config.path) as db:
            assert db.execute("SELECT count(*) FROM entries").fetchone() == (9,)


def test_closed_scopes_cannot_allocate(tmp_path):
    with ephemeral_session() as state:
        pass
    with pytest.raises(RuntimeError, match="closed"):
        state.allocate(EntityType.PERSON, SecretStr("Synthetic"))
    with PersistentSessions.open(settings(tmp_path), SecretStr("synthetic")) as service:
        record = service.create()
        with service.use(record.session_id) as active:
            pass
        with pytest.raises(RuntimeError, match="closed"):
            active.allocate(EntityType.PERSON, SecretStr("Synthetic"))


def test_persistent_allocation_does_not_put_plaintext_on_disk(tmp_path):
    with PersistentSessions.open(settings(tmp_path), SecretStr("synthetic")) as service:
        record = service.create()
        with service.use(record.session_id) as active:
            value = SecretStr("Synthetic Confidential Allocation Value")
            result = active.allocate(EntityType.SECRET, value)
            assert "entity_digest" not in result.model_dump()
            assert value.get_secret_value() not in repr(result)
            for artifact in tmp_path.iterdir():
                assert value.get_secret_value().encode() not in artifact.read_bytes()
                assert active.key.get_secret_value() not in artifact.read_bytes()


def test_wrong_type_for_existing_full_digest_is_rejected(tmp_path, monkeypatch):
    import sqlite3

    from shield.pseudonym import PseudonymError

    with PersistentSessions.open(settings(tmp_path), SecretStr("synthetic")) as service:
        record = service.create()
        with service.use(record.session_id) as active:
            active.allocate(EntityType.PERSON, SecretStr("Synthetic"))
            with sqlite3.connect(service.config.path) as db:
                db.execute("UPDATE entries SET entity_type='SECRET'")
            with pytest.raises(PseudonymError):
                active.allocate(EntityType.PERSON, SecretStr("Synthetic"))
