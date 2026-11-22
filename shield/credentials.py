"""Read runtime secrets without placing them in configuration or serialized state."""

import getpass
import os
import warnings

from pydantic import Field, SecretStr

from shield.config import ShieldConfig
from shield.contracts import Contract


class CredentialError(ValueError):
    """Safe startup error; never include a secret or an underlying exception."""


class RuntimeCredentials(Contract):
    api_key: SecretStr | None = Field(default=None, repr=False, exclude=True)
    vault_passphrase: SecretStr | None = Field(default=None, repr=False, exclude=True)


def prompt_vault_passphrase() -> SecretStr:
    """Abort if getpass cannot disable echo; never fall back to echoed input."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            value = getpass.getpass("Vault passphrase: ")
    except getpass.GetPassWarning, EOFError, OSError:
        raise CredentialError(
            "Cannot read a vault passphrase without echo; use an interactive terminal."
        ) from None
    if not value.strip():
        raise CredentialError("Vault passphrase must not be empty.")
    return SecretStr(value)


def load_credentials(config: ShieldConfig) -> RuntimeCredentials:
    """An absent provider key is allowed for unauthenticated local upstreams.

    The configured upstream enforces its provider authentication requirements.
    Persistent-session opt-in collects a passphrase for authenticated lifespan startup.
    """
    value = os.environ.get(config.upstream.api_key_env)
    if value is not None and (not value or any(char.isspace() for char in value)):
        raise CredentialError("Provider key environment variable has an invalid value.")
    return RuntimeCredentials(
        api_key=SecretStr(value) if value is not None else None,
        vault_passphrase=(
            prompt_vault_passphrase() if config.sessions.persistent_enabled else None
        ),
    )
