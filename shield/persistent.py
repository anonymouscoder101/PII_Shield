"""Opt-in persistent session lifecycle; no persistent HMAC-key cache.

Each session has an exclusive, nonblocking request lease. Admission pins its
lifetime through restoration; competing operations fail with session_busy.
"""

import math
from collections.abc import Awaitable, Callable, Iterable, Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from threading import Lock
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
from shield.vault_owner import VaultOwnership


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
    _service: PersistentSessions = field(repr=False)
    _sending: bool = field(default=False, repr=False)
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

    def commit_mappings(self) -> None:
        """Commit pending mappings before any send, retaining them on failure."""
        _ = self.key
        pending = list(self.mappings.items())
        if any(
            token != mapping.token or mapping.session_id != self.session_id
            for token, mapping in pending
        ):
            raise SessionAccessError(ErrorCode.INVALID_REQUEST)
        if pending:
            with VaultStore(self._service.config.path) as store:
                store.insert_mappings(
                    (mapping for _, mapping in pending), self._service._key
                )
            self.mappings.clear()

    def read_mapping(self, token: str) -> TokenMapping | None:
        _ = self.key
        with VaultStore(self._service.config.path) as store:
            return store.read_mapping(self.session_id, token, self._service._key)

    async def send[T](self, callback: Callable[[], Awaitable[T]]) -> T:
        """Invoke a send only after commit succeeds; caller retains scope to restore."""
        if self._sending:
            raise SessionAccessError(ErrorCode.SESSION_BUSY)
        self._sending = True
        try:
            self.commit_mappings()
            return await callback()
        finally:
            self._sending = False


class PersistentSessions:
    def __init__(self, config: VaultConfig, clock: Callable[[], datetime]):
        self.config = config
        self.clock = clock
        self._vault_key: SecretBytes | None = None
        self._closing = False
        self._registry_lock = Lock()
        self._active: set[str | None] = set()
        self._ownership: VaultOwnership | None = None

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
            service._ownership = VaultOwnership(config.path)
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
        except BaseException:
            service.close()
            raise
        return service

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    @property
    def is_unlocked(self) -> bool:
        return self._vault_key is not None and not self._closing

    @property
    def _key(self) -> SecretBytes:
        if self._vault_key is None:
            raise SessionAccessError(ErrorCode.VAULT_LOCKED)
        return self._vault_key

    def _release_resources(self) -> None:
        self._vault_key = None
        if self._ownership is not None:
            self._ownership.close()
            self._ownership = None

    def close(self) -> None:
        with self._registry_lock:
            self._closing = True
            if not self._active:
                self._release_resources()

    @contextmanager
    def _guard(self, session_id: str | None) -> Iterator[None]:
        # Never wait while holding the event loop. A thread lock protects only
        # registry edits; there is no SQLite or network work under this lock.
        with self._registry_lock:
            if self._closing or self._vault_key is None:
                raise SessionAccessError(ErrorCode.VAULT_LOCKED)
            if session_id in self._active:
                raise SessionAccessError(ErrorCode.SESSION_BUSY)
            self._active.add(session_id)
        try:
            yield
        finally:
            with self._registry_lock:
                self._active.remove(session_id)
                if self._closing and not self._active:
                    self._release_resources()

    def create(self) -> SessionRecord:
        session_id = uuid4().hex
        with self._guard(session_id):
            created = int(self.clock().timestamp())
            expires = created + max(1, math.ceil(self.config.session_ttl_hours * 3600))
            record = SessionRecord(
                session_id=session_id,
                kind=SessionKind.PERSISTENT,
                created_at=datetime.fromtimestamp(created, UTC),
                expires_at=datetime.fromtimestamp(expires, UTC),
            )
            row = wrap_session_key(record, generate_hmac_key(), self._key)
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
        with self._guard(session_id):
            return self._load(session_id)[0]

    @contextmanager
    def use(self, session_id: str) -> Iterator[PersistentSessionState]:
        with self._guard(session_id):
            record, key = self._load(session_id)
            state = PersistentSessionState(record, key, self)
            try:
                yield state
            finally:
                state.close()

    def delete(self, session_id: str) -> None:
        with self._guard(session_id):
            self._load(session_id, delete=True)

    def prune_expired(self) -> None:
        with self._guard(None):
            with VaultStore(self.config.path) as store:
                with store.transaction() as db:
                    ids = [
                        row[0] for row in db.execute("SELECT session_id FROM sessions")
                    ]
        for session_id in ids:
            try:
                self.lookup(session_id)
            except SessionAccessError as exc:
                if exc.code not in (
                    ErrorCode.SESSION_EXPIRED,
                    ErrorCode.SESSION_NOT_FOUND,
                    ErrorCode.SESSION_BUSY,
                ):
                    raise

    def insert_mappings(self, mappings: Iterable[TokenMapping]) -> None:
        mappings = list(mappings)
        ids = sorted({mapping.session_id for mapping in mappings})
        with ExitStack() as scopes:
            # Acquire every affected session before validating or writing. A
            # failure releases earlier guards and leaves the whole batch unwritten.
            for session_id in ids or [None]:
                scopes.enter_context(self._guard(session_id))
            for session_id in ids:
                self._load(session_id)
            with VaultStore(self.config.path) as store:
                store.insert_mappings(mappings, self._key)

    def read_mapping(self, session_id: str, token: str) -> TokenMapping | None:
        with self._guard(session_id):
            self._load(session_id)
            with VaultStore(self.config.path) as store:
                return store.read_mapping(session_id, token, self._key)


class VaultStartupHandoff:
    """Publish a worker result or close it if its async caller has cancelled.

    Worker-side cleanup does not depend on a running asyncio loop receiving the
    abandoned thread result. The lock covers only the handoff, never KDF work.
    """

    def __init__(self) -> None:
        self._lock = Lock()
        self._cancelled = False
        self._service: PersistentSessions | None = None

    def open(self, config: VaultConfig, passphrase: SecretStr) -> None:
        service = PersistentSessions.open(config, passphrase)
        with self._lock:
            if not self._cancelled:
                self._service = service
                return
        service.close()

    def take(self) -> PersistentSessions:
        with self._lock:
            service = self._service
            self._service = None
        if service is None:
            raise VaultStartupError("Vault startup failed.")
        return service

    def cancel(self) -> None:
        with self._lock:
            self._cancelled = True
            service = self._service
            self._service = None
        if service is not None:
            service.close()
