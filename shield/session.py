"""Request-local ephemeral keys and mappings; no SQLite dependencies or I/O."""

import os
from collections.abc import Iterator
from contextlib import contextmanager
from threading import RLock
from uuid import uuid4

from pydantic import SecretBytes, SecretStr

from shield import pseudonym
from shield.contracts import EntityType, TokenMapping
from shield.memory_mappings import MemoryMappings


class SessionKeyError(ValueError):
    """Static failure to generate session key material."""


def generate_hmac_key() -> SecretBytes:
    """Draw a new 256-bit HMAC key, independent of the vault and all other keys."""
    try:
        return SecretBytes(os.urandom(32))
    except OSError:
        raise SessionKeyError("Session key generation failed.") from None


class EphemeralSession:
    """One request's memory-only state, without serialization or persistence hooks.

    The ID is internal, never returned for client reuse. Closing releases this
    object's references; Python/host memory cannot provide secure erasure.
    """

    __slots__ = (
        "session_id",
        "_key",
        "mappings",
        "_lock",
        "_by_digest",
        "_indexed_version",
    )

    def __init__(self) -> None:
        self._key: SecretBytes | None = generate_hmac_key()
        self.session_id = uuid4().hex
        self._lock = RLock()
        self.mappings = MemoryMappings(self._lock)
        self._by_digest: dict[bytes, str] = {}
        self._indexed_version = self.mappings.version

    @property
    def key(self) -> SecretBytes:
        if self._key is None:
            raise RuntimeError("ephemeral session is closed")
        return self._key

    def close(self) -> None:
        with self._lock:
            self.mappings.clear()
            self._by_digest.clear()
            self._indexed_version = self.mappings.version
            self._key = None

    def has_token(self, token: str) -> bool:
        """Check exact ownership and metadata, without reading an original value."""
        with self._lock:
            _ = self.key
            mapping = self.mappings.get(token)
            if mapping is None:
                return False
            if (
                not isinstance(mapping, TokenMapping)
                or mapping.session_id != self.session_id
                or mapping.token != token
            ):
                raise pseudonym.PseudonymError("Token identity metadata is invalid.")
            pseudonym.validate_token_identity(
                mapping.entity_type, mapping.entity_digest, token
            )
            return True

    def read_mapping(self, token: str) -> TokenMapping | None:
        """Read only an exact, validated mapping owned by this open session."""
        with self._lock:
            if not self.has_token(token):
                return None
            return self.mappings[token]

    def allocate(
        self, entity_type: EntityType, value: SecretStr
    ) -> pseudonym.TokenAllocation:
        """Atomic full-digest reuse/lookup/insert, without comparing original values."""
        with self._lock:
            key = self.key
            try:
                derived = pseudonym.derive_token(entity_type, value, key)
                if self._indexed_version != self.mappings.version:
                    index = {}
                    for token, mapping in self.mappings.items():
                        if (
                            not isinstance(mapping, TokenMapping)
                            or mapping.session_id != self.session_id
                            or token != mapping.token
                            or len(mapping.entity_digest) != 32
                        ):
                            raise pseudonym.PseudonymError(
                                "Token identity metadata is invalid."
                            )
                        if mapping.entity_digest in index:
                            raise pseudonym.PseudonymError("Duplicate entity identity.")
                        index[mapping.entity_digest] = token
                    self._by_digest = index
                    self._indexed_version = self.mappings.version
                existing_token = self._by_digest.get(derived.entity_digest)
                existing = (
                    self.mappings[existing_token]
                    if existing_token is not None
                    else None
                )
                metadata = (
                    None
                    if existing is None
                    else (existing.token, existing.entity_type, existing.entity_digest)
                )

                def occupied(token):
                    mapping = self.mappings.get(token)
                    return None if mapping is None else mapping.entity_digest

                allocated = pseudonym._select_token(derived, metadata, occupied)
                if not allocated.reused:
                    self.mappings[allocated.token] = TokenMapping(
                        session_id=self.session_id,
                        token=allocated.token,
                        entity_type=entity_type,
                        entity_digest=allocated.entity_digest,
                        original_value=value,
                    )
                self._by_digest[allocated.entity_digest] = allocated.token
                self._indexed_version = self.mappings.version
                return allocated
            except pseudonym.PseudonymError:
                raise
            except Exception:
                raise pseudonym.PseudonymError("Token allocation failed.") from None


@contextmanager
def ephemeral_session() -> Iterator[EphemeralSession]:
    """Release request-local state on success, failure, timeout or cancellation."""
    state = EphemeralSession()
    try:
        yield state
    finally:
        state.close()
