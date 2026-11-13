"""Request-local ephemeral keys and mappings; no SQLite dependencies or I/O."""

import os
from collections.abc import Iterator
from contextlib import contextmanager
from uuid import uuid4

from pydantic import SecretBytes

from shield.contracts import TokenMapping


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

    __slots__ = ("session_id", "_key", "mappings")

    def __init__(self) -> None:
        self._key: SecretBytes | None = generate_hmac_key()
        self.session_id = uuid4().hex
        self.mappings: dict[str, TokenMapping] = {}

    @property
    def key(self) -> SecretBytes:
        if self._key is None:
            raise RuntimeError("ephemeral session is closed")
        return self._key

    def close(self) -> None:
        self.mappings.clear()
        self._key = None


@contextmanager
def ephemeral_session() -> Iterator[EphemeralSession]:
    """Release request-local state on success, failure, timeout or cancellation."""
    state = EphemeralSession()
    try:
        yield state
    finally:
        state.close()
