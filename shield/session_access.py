"""Session selection checks; authenticated lookup follows in the route service."""

from typing import Protocol

from fastapi import Request

from shield.contracts import ErrorCode
from shield.errors import ShieldError


class VaultReadiness(Protocol):
    @property
    def is_unlocked(self) -> bool: ...


def require_unlocked_vault(request: Request) -> None:
    """A collected passphrase is not evidence of an authenticated vault unlock."""
    vault: VaultReadiness | None = request.app.state.vault
    if (
        not request.app.state.config.sessions.persistent_enabled
        or vault is None
        or not vault.is_unlocked
    ):
        raise ShieldError(ErrorCode.VAULT_LOCKED)


def require_session_access(request: Request) -> None:
    """No header selects ephemeral operation, with no vault readiness lookup."""
    session_ids = request.headers.getlist("x-shield-session")
    if not session_ids:
        return
    if len(session_ids) != 1 or not session_ids[0].strip():
        raise ShieldError(ErrorCode.INVALID_REQUEST)
    require_unlocked_vault(request)
