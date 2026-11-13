"""Opt-in persistent session lifecycle; no persistent HMAC-key cache.

SQLite operations are synchronous and short. Active-request coordination is a
separate layer; callers must not yet use this service for upstream proxy work.
"""

import math
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import uuid4

from pydantic import SecretBytes, SecretStr

from shield.config import VaultConfig
from shield.contracts import ErrorCode, SessionKind, SessionRecord, TokenMapping
from shield.session import generate_hmac_key
from shield.vault import (
    PersistentSessionRow,
    VaultSessionKeyError,
    VaultStore,
    unwrap_session_key,
    wrap_session_key,
)


class SessionAccessError(ValueError):
    """Privacy-safe session failure; API handlers translate its category."""

    def __init__(self, code: ErrorCode):
        self.code = code
        super().__init__(code.value)


class VaultStartupError(ValueError):
    """No passphrase, key, path or underlying exception is exposed at startup."""


@dataclass(slots=True, repr=False)
class PersistentSessionState:
    record: SessionRecord
    _key: SecretBytes | None = field(repr=False)
    mappings: dict[str, TokenMapping] = field(default_factory=dict, repr=False)

    @property
    def session_id(self) -> str:
        return self.record.session_id

    @property
    def key(self) -> SecretBytes:
        if self._key is None:
            raise RuntimeError("persistent session scope is closed")
        return self._key

    def close(self) -> None:
        self.mappings.clear()
        self._key = None


class PersistentSessions:
    def __init__(self, config: VaultConfig, clock: Callable[[], datetime]):
        self.config = config
        self.clock = clock
        self._vault_key: SecretBytes | None = None

    @classmethod
    def open(
        cls,
        config: VaultConfig,
        passphrase: SecretStr,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> PersistentSessions:
        """Initialize a genuinely empty vault or authenticate existing metadata."""
        service = cls(config, clock)
        try:
            with VaultStore(config.path) as store:
                with store.transaction() as db:
                    initialized = (
                        db.execute("SELECT 1 FROM vault_meta").fetchone() is not None
                    )
                service._vault_key = (
                    store.unlock(passphrase)
                    if initialized
                    else store.initialize(passphrase, params=config.argon2)
                )
            service.prune_expired()
        except Exception:
            service.close()
            raise VaultStartupError("Vault startup failed.") from None
        return service

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    @property
    def is_unlocked(self) -> bool:
        return self._vault_key is not None

    @property
    def _key(self) -> SecretBytes:
        if self._vault_key is None:
            raise SessionAccessError(ErrorCode.VAULT_LOCKED)
        return self._vault_key

    def close(self) -> None:
        # No connection or HMAC cache survives an operation. Releasing references
        # cannot erase other references, process memory, swap or old disk copies.
        self._vault_key = None

    def create(self) -> SessionRecord:
        key = self._key
        created = int(self.clock().timestamp())
        expires = created + max(1, math.ceil(self.config.session_ttl_hours * 3600))
        record = SessionRecord(
            session_id=uuid4().hex,
            kind=SessionKind.PERSISTENT,
            created_at=datetime.fromtimestamp(created, UTC),
            expires_at=datetime.fromtimestamp(expires, UTC),
        )
        row = wrap_session_key(record, generate_hmac_key(), key)
        with VaultStore(self.config.path) as store:
            store.insert_session(row)
        return record

    def _load(
        self, session_id: str, *, delete: bool = False
    ) -> tuple[SessionRecord, SecretBytes]:
        key = self._key
        expired = False
        with VaultStore(self.config.path) as store:
            with store.transaction() as db:
                values = db.execute(
                    "SELECT session_id, sk_nonce, sk_ct, created_at, expires_at "
                    "FROM sessions WHERE session_id = ?",
                    (session_id,),
                ).fetchone()
                if values is None:
                    raise SessionAccessError(ErrorCode.SESSION_NOT_FOUND)
                try:
                    sid, nonce, ct, created, expires = values
                    row = PersistentSessionRow(
                        session_id=sid,
                        sk_nonce=nonce,
                        sk_ct=ct,
                        created_at=created,
                        expires_at=expires,
                    )
                    hmac_key = unwrap_session_key(row, key)
                    record = SessionRecord(
                        session_id=sid,
                        kind=SessionKind.PERSISTENT,
                        created_at=datetime.fromtimestamp(created, UTC),
                        expires_at=datetime.fromtimestamp(expires, UTC),
                    )
                except ValueError, OverflowError, OSError, VaultSessionKeyError:
                    raise SessionAccessError(ErrorCode.INTERNAL_ERROR) from None
                # Authenticate lifetime metadata BEFORE deciding to delete.
                expired = record.is_expired(self.clock())
                if expired or delete:
                    db.execute(
                        "DELETE FROM sessions WHERE session_id = ?", (session_id,)
                    )
        if expired:
            # Raise after commit so cascade cleanup is retained.
            raise SessionAccessError(ErrorCode.SESSION_EXPIRED)
        return record, hmac_key

    def lookup(self, session_id: str) -> SessionRecord:
        return self._load(session_id)[0]

    @contextmanager
    def use(self, session_id: str) -> Iterator[PersistentSessionState]:
        record, key = self._load(session_id)
        state = PersistentSessionState(record, key)
        try:
            yield state
        finally:
            state.close()

    def delete(self, session_id: str) -> None:
        self._load(session_id, delete=True)

    def prune_expired(self) -> None:
        _ = self._key
        with VaultStore(self.config.path) as store:
            with store.transaction() as db:
                ids = [row[0] for row in db.execute("SELECT session_id FROM sessions")]
        for session_id in ids:
            try:
                self.lookup(session_id)
            except SessionAccessError as exc:
                if exc.code != ErrorCode.SESSION_EXPIRED:
                    raise

    def insert_mappings(self, mappings: Iterable[TokenMapping]) -> None:
        _ = self._key
        mappings = list(mappings)
        for session_id in {mapping.session_id for mapping in mappings}:
            self.lookup(session_id)
        with VaultStore(self.config.path) as store:
            store.insert_mappings(mappings, self._key)

    def read_mapping(self, session_id: str, token: str) -> TokenMapping | None:
        self.lookup(session_id)
        with VaultStore(self.config.path) as store:
            return store.read_mapping(session_id, token, self._key)
