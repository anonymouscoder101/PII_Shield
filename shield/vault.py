"""Opt-in SQLite storage for encrypted persistent-session rows.

This layer accepts ciphertext, never TokenMapping/original values or raw keys.
It does not unlock a vault, encrypt values, or manage session lifetimes. Those
services must authenticate stored rows with ``entry_aad`` before using values.
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

from pydantic import Field, model_validator

from shield.contracts import Contract, EntityType, NonEmptyString

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


def entry_aad(row: EntryRow, *, schema_version: int = SCHEMA_VERSION) -> bytes:
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
