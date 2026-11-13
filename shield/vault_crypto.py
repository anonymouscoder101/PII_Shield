"""Vault header cryptography; no secrets are logged or written by this module."""

import hmac
import json
import os
from typing import Annotated, Literal

from argon2.exceptions import HashingError
from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import Field, SecretBytes, SecretStr, ValidationError

from shield.config import Argon2Config
from shield.contracts import Contract

_VERIFIER = b"pii-shield vault unlock verifier v1"


class VaultInitializationError(ValueError):
    """Static, secret-free failure; an existing vault is never overwritten."""


class VaultUnlockError(ValueError):
    """Wrong passphrase and invalid/corrupt header share one safe failure."""


class KDFParameters(Argon2Config):
    """Persisted algorithm identity and bounded costs, validated before allocation.

    Upper bounds limit work requested by a modified database. Changing these
    limits is an explicit local policy change, not an automatic stored override.
    """

    algorithm: Literal["argon2id"] = "argon2id"
    version: Literal[19] = 19
    hash_len: Literal[32] = 32
    memory_kib: Annotated[int, Field(ge=8, le=1048576)] = 65536
    time_cost: Annotated[int, Field(ge=1, le=10)] = 3
    parallelism: Annotated[int, Field(ge=1, le=16)] = 4


class VaultHeader(Contract):
    salt: Annotated[bytes, Field(min_length=16, max_length=16)]
    kdf_params: KDFParameters
    verifier_nonce: Annotated[bytes, Field(min_length=12, max_length=12)]
    verifier_ct: Annotated[
        bytes,
        Field(
            min_length=len(_VERIFIER) + 16, max_length=len(_VERIFIER) + 16, repr=False
        ),
    ]
    schema_version: Annotated[int, Field(ge=1)]


def verifier_aad(salt: bytes, params: KDFParameters, schema_version: int) -> bytes:
    """Distinct verifier domain, with authenticated schema, salt and KDF policy."""
    return json.dumps(
        ["pii-shield/verifier", schema_version, salt.hex(), params.model_dump()],
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")


def _derive(passphrase: SecretStr, salt: bytes, params: KDFParameters) -> bytes:
    raw = passphrase.get_secret_value()
    if not raw.strip():
        raise ValueError("empty passphrase")
    return hash_secret_raw(
        secret=raw.encode("utf-8"),
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_kib,
        parallelism=params.parallelism,
        hash_len=params.hash_len,
        type=Type.ID,
        version=params.version,
    )


def initialize_header(
    passphrase: SecretStr, params: Argon2Config, schema_version: int
) -> tuple[VaultHeader, SecretBytes]:
    """Generate a fresh salt, nonce, key and authenticated fixed verifier."""
    try:
        policy = KDFParameters.model_validate(params.model_dump())
        salt = os.urandom(16)
        key = _derive(passphrase, salt, policy)
        nonce = os.urandom(12)
        ct = AESGCM(key).encrypt(
            nonce, _VERIFIER, verifier_aad(salt, policy, schema_version)
        )
        header = VaultHeader(
            salt=salt,
            kdf_params=policy,
            verifier_nonce=nonce,
            verifier_ct=ct,
            schema_version=schema_version,
        )
        return header, SecretBytes(key)
    except ValueError, HashingError, OSError:
        raise VaultInitializationError("Vault initialization failed.") from None


def unlock_header(
    row: tuple, passphrase: SecretStr, schema_version: int
) -> SecretBytes:
    """Validate stored costs before Argon2; release key only after authentication."""
    try:
        salt, serialized_params, nonce, ct, version = row
        if version != schema_version:
            raise ValueError("unsupported schema version")
        # Bound parser input too; corrupted headers cannot request unbounded JSON.
        if not isinstance(serialized_params, str) or len(serialized_params) > 1024:
            raise ValueError("invalid KDF metadata")
        params = KDFParameters.model_validate_json(serialized_params)
        if params.model_fields_set != set(KDFParameters.model_fields):
            raise ValueError("incomplete KDF metadata")
        header = VaultHeader(
            salt=salt,
            kdf_params=params,
            verifier_nonce=nonce,
            verifier_ct=ct,
            schema_version=version,
        )
        key = _derive(passphrase, header.salt, params)
        value = AESGCM(key).decrypt(
            header.verifier_nonce,
            header.verifier_ct,
            verifier_aad(header.salt, params, version),
        )
        if not hmac.compare_digest(value, _VERIFIER):
            raise ValueError("invalid verifier")
        return SecretBytes(key)
    except ValueError, ValidationError, HashingError, InvalidTag:
        raise VaultUnlockError("Vault unlock failed.") from None
