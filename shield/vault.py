"""Opt-in SQLite storage for encrypted persistent-session rows.

Explicit initialization/unlock derives keys. Mapping inserts encrypt original
values before SQL binding; mapping reads authenticate ciphertext before returning
values. Session lifetimes and API access are handled by later services.
Constructing a store does no I/O; only explicitly entering it opens the database.
"""

import json
import os
import sqlite3
import stat
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated, Self

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import Field, SecretBytes, SecretStr, model_validator

from shield import pseudonym
from shield.config import Argon2Config
from shield.contracts import (
    Contract,
    EntityType,
    NonEmptyString,
    SessionKind,
    SessionRecord,
    TokenMapping,
)
from shield.vault_crypto import (
    VaultInitializationError,
    VaultUnlockError,
    initialize_header,
    unlock_header,
)

SCHEMA_VERSION = 1
Nonce = Annotated[bytes, Field(min_length=12, max_length=12, repr=False)]
Ciphertext = Annotated[bytes, Field(min_length=16, repr=False)]


class PersistentSessionRow(Contract):
    """Persistent metadata and an already-wrapped 32-byte HMAC key.

    Timestamps are integer Unix seconds. The 48-byte wrapped key includes a
    16-byte GCM authentication tag. No plaintext key is accepted by this API.
    """

    session_id: NonEmptyString
    sk_nonce: Nonce
    sk_ct: Annotated[bytes, Field(min_length=48, max_length=48, repr=False)]
    created_at: Annotated[int, Field(ge=0)]
    expires_at: Annotated[int, Field(gt=0)]

    @model_validator(mode="after")
    def valid_lifetime(self) -> Self:
        if self.expires_at <= self.created_at:
            raise ValueError("expiry must follow creation")
        return self


class EntryRow(Contract):
    """Encrypted entry plus public lookup metadata; digest is full HMAC-SHA256."""

    session_id: NonEmptyString
    token: NonEmptyString
    entity_type: EntityType
    entity_digest: Annotated[
        bytes, Field(min_length=32, max_length=32, repr=False, exclude=True)
    ]
    nonce: Nonce
    ciphertext: Ciphertext


def entry_aad(
    row: EntryRow | TokenMapping, *, schema_version: int = SCHEMA_VERSION
) -> bytes:
    """Canonical UTF-8 JSON array; boundaries cannot collide on embedded delimiters.

    The domain and version are part of the authenticated bytes. Hex encodes all
    32 digest bytes without truncation. Encryption/decryption must use this exact
    encoding; constructing AAD alone does not authenticate a stored row.
    """
    return json.dumps(
        [
            "pii-shield/entry",
            schema_version,
            row.session_id,
            row.token,
            row.entity_type.value,
            row.entity_digest.hex(),
        ],
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")


class VaultEntryError(ValueError):
    """Static entry failure without values, keys, digests or crypto exceptions."""


def _vault_cipher(key: SecretBytes) -> AESGCM:
    raw = key.get_secret_value()
    if len(raw) != 32:
        raise ValueError("vault key must have 32 bytes")
    return AESGCM(raw)


def encrypt_entry(mapping: TokenMapping, key: SecretBytes) -> EntryRow:
    """Encrypt the exact first spelling with a fresh random 96-bit nonce.

    The full identity is authenticated, but remains plaintext lookup metadata.
    This function performs no I/O and retains neither key nor original value.
    """
    try:
        cipher = _vault_cipher(key)
        nonce = os.urandom(12)
        ciphertext = cipher.encrypt(
            nonce,
            mapping.original_value.get_secret_value().encode("utf-8"),
            entry_aad(mapping),
        )
        return EntryRow(
            session_id=mapping.session_id,
            token=mapping.token,
            entity_type=mapping.entity_type,
            entity_digest=mapping.entity_digest,
            nonce=nonce,
            ciphertext=ciphertext,
        )
    except ValueError, OSError:
        raise VaultEntryError("Vault entry encryption failed.") from None


def decrypt_entry(row: EntryRow, key: SecretBytes) -> TokenMapping:
    """Release a value only after AES-GCM authenticates its entire row identity."""
    try:
        value = _vault_cipher(key).decrypt(row.nonce, row.ciphertext, entry_aad(row))
        return TokenMapping(
            session_id=row.session_id,
            token=row.token,
            entity_type=row.entity_type,
            entity_digest=row.entity_digest,
            original_value=SecretStr(value.decode("utf-8")),
        )
    except ValueError, InvalidTag:
        raise VaultEntryError("Vault entry authentication failed.") from None


class VaultSessionKeyError(ValueError):
    """Static wrapped-key failure, without exposing key bytes or crypto errors."""


def _session_times(row: PersistentSessionRow | SessionRecord) -> tuple[int, int]:
    if isinstance(row, SessionRecord):
        if row.kind != SessionKind.PERSISTENT or row.expires_at is None:
            raise ValueError("persistent session required")
        return int(row.created_at.timestamp()), int(row.expires_at.timestamp())
    return row.created_at, row.expires_at


def session_key_aad(
    row: PersistentSessionRow | SessionRecord, *, schema_version: int = SCHEMA_VERSION
) -> bytes:
    """Bind wrapped HMAC keys to their session and lifetime in a distinct domain."""
    created_at, expires_at = _session_times(row)
    return json.dumps(
        [
            "pii-shield/session-key",
            schema_version,
            row.session_id,
            created_at,
            expires_at,
        ],
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")


def wrap_session_key(
    record: SessionRecord, key: SecretBytes, vault_key: SecretBytes
) -> PersistentSessionRow:
    """Wrap only explicitly persistent keys; this helper performs no writes."""
    try:
        created_at, expires_at = _session_times(record)
        raw = key.get_secret_value()
        if len(raw) != 32:
            raise ValueError("session key must have 32 bytes")
        cipher = _vault_cipher(vault_key)
        nonce = os.urandom(12)
        ct = cipher.encrypt(nonce, raw, session_key_aad(record))
        return PersistentSessionRow(
            session_id=record.session_id,
            sk_nonce=nonce,
            sk_ct=ct,
            created_at=created_at,
            expires_at=expires_at,
        )
    except ValueError, OSError:
        raise VaultSessionKeyError("Session key wrapping failed.") from None


def unwrap_session_key(
    row: PersistentSessionRow, vault_key: SecretBytes
) -> SecretBytes:
    """Authenticate wrapped key identity before releasing the 32-byte HMAC key.

    Authentication binds lifetime metadata; expiry enforcement is the session
    service's responsibility. This function neither caches keys nor opens SQLite.
    """
    try:
        raw = _vault_cipher(vault_key).decrypt(
            row.sk_nonce, row.sk_ct, session_key_aad(row)
        )
        if len(raw) != 32:
            raise ValueError("session key must have 32 bytes")
        return SecretBytes(raw)
    except ValueError, InvalidTag:
        raise VaultSessionKeyError("Session key authentication failed.") from None


class VaultSchemaError(RuntimeError):
    """Unknown or inconsistent storage layout; no automatic destructive migration."""


# STRICT prevents a 32-character TEXT value masquerading as a 32-byte digest.
_SCHEMA = (
    """CREATE TABLE vault_meta (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        salt BLOB NOT NULL,
        kdf_params TEXT NOT NULL,
        verifier_nonce BLOB NOT NULL CHECK (length(verifier_nonce) = 12),
        verifier_ct BLOB NOT NULL CHECK (length(verifier_ct) >= 16),
        schema_version INTEGER NOT NULL CHECK (schema_version = 1)
    ) STRICT""",
    """CREATE TABLE sessions (
        session_id TEXT PRIMARY KEY NOT NULL CHECK (length(session_id) > 0),
        sk_nonce BLOB NOT NULL CHECK (length(sk_nonce) = 12),
        sk_ct BLOB NOT NULL CHECK (length(sk_ct) = 48),
        created_at INTEGER NOT NULL CHECK (created_at >= 0),
        expires_at INTEGER NOT NULL CHECK (expires_at > created_at)
    ) STRICT""",
    """CREATE TABLE entries (
        session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
        token TEXT NOT NULL CHECK (length(token) > 0),
        entity_type TEXT NOT NULL CHECK (length(entity_type) > 0),
        entity_digest BLOB NOT NULL CHECK (length(entity_digest) = 32),
        nonce BLOB NOT NULL CHECK (length(nonce) = 12),
        ciphertext BLOB NOT NULL CHECK (length(ciphertext) >= 16),
        PRIMARY KEY (session_id, token),
        UNIQUE (session_id, entity_digest)
    ) STRICT""",
)


class VaultStore:
    """Explicit, synchronous, single-connection persistence boundary.

    Use one context on one thread. Transactions are short, non-nestable and must
    contain no awaits or network work. Session coordination is a later layer.
    SQLite exceptions are internal: do not log them or expose them in API errors.
    """

    def __init__(self, path: Path):
        self.path = Path(path).absolute()
        self._db: sqlite3.Connection | None = None

    def __enter__(self) -> Self:
        if self._db is not None:
            raise RuntimeError("vault store is already open")
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        # Create with restrictive permissions from the first byte, irrespective
        # of umask. Reject symlinks and nonregular files where OS flags support it.
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.path, flags, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError("vault must be a regular file")
            if os.name == "posix":
                os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        # Existing SQLite artifacts may have been created by another program.
        # Harden before SQLite can read/recover them; never follow symlinks.
        for suffix in ("-journal", "-wal", "-shm"):
            sidecar = Path(str(self.path) + suffix)
            try:
                fd = os.open(sidecar, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
            except FileNotFoundError:
                continue
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise OSError("vault artifact must be a regular file")
                if os.name == "posix":
                    os.fchmod(fd, 0o600)
            finally:
                os.close(fd)
        db = sqlite3.connect(self.path, isolation_level=None)
        self._db = db
        try:
            db.execute("PRAGMA foreign_keys = ON")
            if db.execute("PRAGMA foreign_keys").fetchone() != (1,):
                raise RuntimeError("SQLite foreign key enforcement unavailable")
            with self.transaction():
                version = db.execute("PRAGMA user_version").fetchone()[0]
                tables = db.execute(
                    "SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
                ).fetchall()
                if version == 0 and not tables:
                    for statement in _SCHEMA:
                        db.execute(statement)
                    db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                elif version != SCHEMA_VERSION:
                    raise VaultSchemaError("unsupported vault schema version")
                else:
                    # Matching version alone cannot bless unrelated tables. No
                    # migrations are implemented; refuse drift instead of repair.
                    actual = dict(
                        db.execute(
                            "SELECT name, sql FROM sqlite_master "
                            "WHERE name NOT LIKE 'sqlite_%'"
                        )
                    )
                    expected = dict(
                        (statement.split()[2], statement) for statement in _SCHEMA
                    )
                    if actual != expected:
                        raise VaultSchemaError("inconsistent vault schema")
                    versions = db.execute(
                        "SELECT schema_version FROM vault_meta"
                    ).fetchall()
                    if any(v != (SCHEMA_VERSION,) for v in versions):
                        raise VaultSchemaError("inconsistent vault schema version")
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._db is not None:
            self._db.close()
            self._db = None

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Commit a whole unit or roll back on errors, including cancellation."""
        db = self._db
        if db is None:
            raise RuntimeError("vault store is closed")
        if db.in_transaction:
            raise RuntimeError("nested vault transactions are unsupported")
        db.execute("BEGIN IMMEDIATE")
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise

    @staticmethod
    def _insert_entries(db: sqlite3.Connection, entries: Iterable[EntryRow]) -> None:
        db.executemany(
            "INSERT INTO entries "
            "(session_id, token, entity_type, entity_digest, nonce, ciphertext) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                (
                    row.session_id,
                    row.token,
                    row.entity_type.value,
                    row.entity_digest,
                    row.nonce,
                    row.ciphertext,
                )
                for row in entries
            ),
        )

    def insert_session(
        self, row: PersistentSessionRow, *, entries: Iterable[EntryRow] = ()
    ) -> None:
        """Atomically insert a persistent session and any initial encrypted entries."""
        with self.transaction() as db:
            db.execute(
                "INSERT INTO sessions "
                "(session_id, sk_nonce, sk_ct, created_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    row.session_id,
                    row.sk_nonce,
                    row.sk_ct,
                    row.created_at,
                    row.expires_at,
                ),
            )
            self._insert_entries(db, entries)

    def insert_entries(self, entries: Iterable[EntryRow]) -> None:
        """Atomically insert a batch; identity/token conflicts never overwrite rows."""
        with self.transaction() as db:
            self._insert_entries(db, entries)

    def initialize(
        self, passphrase: SecretStr, *, params: Argon2Config | None = None
    ) -> SecretBytes:
        """Initialize an empty vault once; never replace keys or existing metadata.

        Metadata and verifier commit together. The returned key is in memory only;
        no key or unlock readiness is retained by this low-level store.
        """
        with self.transaction() as db:
            if any(
                db.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone()
                for table in ("vault_meta", "sessions", "entries")
            ):
                raise VaultInitializationError(
                    "Vault is already initialized or nonempty."
                )
            header, key = initialize_header(
                passphrase,
                params if params is not None else Argon2Config(),
                SCHEMA_VERSION,
            )
            db.execute(
                "INSERT INTO vault_meta "
                "(id, salt, kdf_params, verifier_nonce, verifier_ct, schema_version) "
                "VALUES (1, ?, ?, ?, ?, ?)",
                (
                    header.salt,
                    header.kdf_params.model_dump_json(),
                    header.verifier_nonce,
                    header.verifier_ct,
                    header.schema_version,
                ),
            )
        return key

    def unlock(self, passphrase: SecretStr) -> SecretBytes:
        """Authenticate with stored KDF parameters, without changing the header."""
        with self.transaction() as db:
            row = db.execute(
                "SELECT salt, kdf_params, verifier_nonce, verifier_ct, schema_version "
                "FROM vault_meta WHERE id = 1"
            ).fetchone()
            if row is None:
                raise VaultUnlockError("Vault unlock failed.")
            key = unlock_header(row, passphrase, SCHEMA_VERSION)
        return key

    def insert_mappings(
        self, mappings: Iterable[TokenMapping], key: SecretBytes
    ) -> None:
        """Encrypt and commit a complete batch; no plaintext is bound to SQLite.

        The caller supplies an authenticated vault key and owns session access.
        Any encryption, iteration or insert failure rolls back the whole batch.
        """
        self.insert_entries(encrypt_entry(mapping, key) for mapping in mappings)

    def read_mapping(
        self, session_id: str, token: str, key: SecretBytes
    ) -> TokenMapping | None:
        """Read only the requested session/token, authenticating before returning.

        A missing mapping is None; a corrupt row raises a static error. This
        low-level operation does not enforce session expiry or API readiness.
        """
        with self.transaction() as db:
            values = db.execute(
                "SELECT session_id, token, entity_type, entity_digest, "
                "nonce, ciphertext "
                "FROM entries WHERE session_id = ? AND token = ?",
                (session_id, token),
            ).fetchone()
            if values is None:
                return None
            try:
                sid, stored_token, entity_type, digest, nonce, ciphertext = values
                row = EntryRow(
                    session_id=sid,
                    token=stored_token,
                    entity_type=EntityType(entity_type),
                    entity_digest=digest,
                    nonce=nonce,
                    ciphertext=ciphertext,
                )
            except ValueError:
                raise VaultEntryError("Vault entry authentication failed.") from None
            result = decrypt_entry(row, key)
        return result

    def allocate_token(
        self,
        session_id: str,
        entity_type: EntityType,
        value: SecretStr,
        session_key: SecretBytes,
        vault_key: SecretBytes,
    ) -> pseudonym.TokenAllocation:
        """Select by full digest, resolve suffix, encrypt and insert in one transaction.

        Metadata-only reuse does not authenticate/decrypt an entry value; trusted
        restoration uses read_mapping for authenticated plaintext access.
        The caller owns session authorization and its active request lease.
        """
        try:
            derived = pseudonym.derive_token(entity_type, value, session_key)
            with self.transaction() as db:
                values = db.execute(
                    "SELECT token, entity_type, entity_digest FROM entries "
                    "WHERE session_id = ? AND entity_digest = ?",
                    (session_id, derived.entity_digest),
                ).fetchone()
                metadata = (
                    None
                    if values is None
                    else (values[0], EntityType(values[1]), values[2])
                )

                def occupied(token):
                    row = db.execute(
                        "SELECT entity_digest FROM entries "
                        "WHERE session_id=? AND token=?",
                        (session_id, token),
                    ).fetchone()
                    return None if row is None else row[0]

                allocated = pseudonym._select_token(derived, metadata, occupied)
                if not allocated.reused:
                    mapping = TokenMapping(
                        session_id=session_id,
                        token=allocated.token,
                        entity_type=entity_type,
                        entity_digest=allocated.entity_digest,
                        original_value=value,
                    )
                    self._insert_entries(db, [encrypt_entry(mapping, vault_key)])
            return allocated
        except pseudonym.PseudonymError:
            raise
        except Exception:
            raise pseudonym.PseudonymError("Token allocation failed.") from None
