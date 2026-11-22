"""Type-specific normalization and candidate HMAC tokens; no registration or I/O."""

import base64
import hashlib
import hmac
import ipaddress
import re
import unicodedata
from types import MappingProxyType
from typing import Annotated

from pydantic import Field, SecretBytes, SecretStr

from shield.contracts import OPAQUE_ENTITY_TYPES, Contract, EntityType, NonEmptyString

MAX_SUFFIX_LENGTH = 32
TOKEN_LABELS = MappingProxyType(
    {
        EntityType.PERSON: "PERSON",
        EntityType.EMAIL_ADDRESS: "EMAIL",
        EntityType.PHONE_NUMBER: "PHONE",
        EntityType.CREDIT_CARD: "CARD",
        EntityType.US_SSN: "SSN",
        EntityType.LOCATION: "LOCATION",
        EntityType.ADDRESS: "ADDRESS",
        EntityType.IP_ADDRESS: "IP",
        EntityType.DATE_OF_BIRTH: "DOB",
        EntityType.API_KEY: "APIKEY",
        EntityType.SECRET: "SECRET",
        EntityType.EMPLOYEE_ID: "EMPLOYEE",
        EntityType.CONTEXTUAL: "CONTEXTUAL",
    }
)
_TEXT_TYPES = frozenset(
    {
        EntityType.PERSON,
        EntityType.LOCATION,
        EntityType.ADDRESS,
        EntityType.DATE_OF_BIRTH,
        EntityType.CONTEXTUAL,
    }
)
_EXTENSION = re.compile(r"(?:;ext=|ext(?:ension)?\.?|x|#)\s*(\d+)\s*$", re.IGNORECASE)


class PseudonymError(ValueError):
    """Static failure without entity text, normalized values or key material."""


class TokenDerivation(Contract):
    """Candidate display token and full identity; no original/normalized text.

    A candidate is not an allocated mapping. Session allocation checks full identity
    and suffix collisions atomically before a token is used or sent upstream.
    """

    entity_type: EntityType
    label: NonEmptyString
    token: NonEmptyString
    entity_digest: Annotated[
        bytes, Field(min_length=32, max_length=32, repr=False, exclude=True)
    ]


def _digits(value: str, separators: str) -> str | None:
    digits = []
    for char in value:
        if char.isdecimal():
            digits.append(str(unicodedata.decimal(char)))
        elif char.isspace() or char in separators:
            continue
        else:
            return None
    return "".join(digits) or None


def _normalize(entity: EntityType, value: str) -> str:
    if entity in OPAQUE_ENTITY_TYPES:
        return value
    if entity in _TEXT_TYPES:
        canonical = unicodedata.normalize("NFC", value)
        return unicodedata.normalize("NFC", " ".join(canonical.casefold().split()))
    if entity in (EntityType.PHONE_NUMBER, EntityType.CREDIT_CARD, EntityType.US_SSN):
        extension = None
        body = value
        if entity == EntityType.PHONE_NUMBER:
            match = _EXTENSION.search(value)
            if match:
                body = value[: match.start()]
                extension = _digits(match.group(1), "")
        separators = "+()-./" if entity == EntityType.PHONE_NUMBER else "-."
        digits = _digits(body, separators)
        if digits is not None:
            return digits + (";ext=" + extension if extension else "")
        # A resolved overlap union may include other words. Never silently erase
        # them into another number's identity. Unsupported formats remain exact.
        return value
    if entity == EntityType.EMAIL_ADDRESS:
        if value.count("@") == 1 and not any(char.isspace() for char in value):
            local, domain = value.split("@")
            if local and domain:
                return local + "@" + unicodedata.normalize("NFC", domain.lower())
        return value
    if entity == EntityType.IP_ADDRESS:
        try:
            value_to_parse = value.strip()
            if "/" in value_to_parse:
                return ipaddress.ip_interface(value_to_parse).compressed
            return ipaddress.ip_address(value_to_parse).compressed
        except ValueError:
            return value
    raise ValueError("unsupported entity type")


def normalize_entity(entity_type: EntityType, value: SecretStr) -> SecretStr:
    """Normalize trusted values without exposing them in representations/errors."""
    try:
        if not isinstance(entity_type, EntityType) or not isinstance(value, SecretStr):
            raise ValueError("typed entity and secret value required")
        original = value.get_secret_value()
        if not isinstance(original, str) or not original:
            raise ValueError("nonempty value required")
        normalized = _normalize(entity_type, original)
        if not normalized:
            raise ValueError("nonempty normalized value required")
        return SecretStr(normalized)
    except Exception:
        raise PseudonymError("Entity normalization failed.") from None


def format_token(
    entity_type: EntityType, digest: bytes, *, suffix_length: int = 4
) -> str:
    """Format a candidate suffix from full identity, never exporting the full digest."""
    try:
        if not isinstance(entity_type, EntityType):
            raise ValueError("typed entity required")
        if not isinstance(digest, bytes) or len(digest) != 32:
            raise ValueError("full digest required")
        if (
            type(suffix_length) is not int
            or not 4 <= suffix_length <= MAX_SUFFIX_LENGTH
        ):
            raise ValueError("invalid suffix length")
        suffix = base64.b32encode(digest).decode("ascii").rstrip("=")[:suffix_length]
        return f"[{TOKEN_LABELS[entity_type]}_{suffix}]"
    except Exception:
        raise PseudonymError("Token formatting failed.") from None


def derive_token(
    entity_type: EntityType,
    value: SecretStr,
    session_key: SecretBytes,
    *,
    suffix_length: int = 4,
) -> TokenDerivation:
    """HMAC-SHA256(key, UTF8(detector type) + NUL + UTF8(normalized value)).

    Only the unpadded uppercase Base32 prefix is displayed. Retain all 32 bytes
    as the identity for session lookup and collision allocation. No secrets are
    cached, written, logged or included in the returned model dump.
    """
    try:
        if not isinstance(session_key, SecretBytes):
            raise ValueError("masked session key required")
        key = session_key.get_secret_value()
        if not isinstance(key, bytes) or len(key) != 32:
            raise ValueError("session key must have 32 bytes")
        if (
            type(suffix_length) is not int
            or not 4 <= suffix_length <= MAX_SUFFIX_LENGTH
        ):
            raise ValueError("invalid suffix length")
        normalized = normalize_entity(entity_type, value).get_secret_value()
        message = entity_type.value.encode("utf-8") + b"\0" + normalized.encode("utf-8")
        digest = hmac.new(key, message, hashlib.sha256).digest()
        label = TOKEN_LABELS[entity_type]
        return TokenDerivation(
            entity_type=entity_type,
            label=label,
            token=format_token(entity_type, digest, suffix_length=suffix_length),
            entity_digest=digest,
        )
    except Exception:
        raise PseudonymError("Pseudonym derivation failed.") from None


SUFFIX_LENGTHS = (4, 6, 8, 12, 16, 20, 24, 28, 32)


class TokenCollisionError(PseudonymError):
    """All supported suffix lengths are occupied; never overwrite a mapping."""


class TokenAllocation(TokenDerivation):
    reused: bool
    collision_count: Annotated[int, Field(ge=0)]


def _select_token(derived, existing, lookup_token) -> TokenAllocation:
    """Caller MUST hold its memory lock or SQLite write transaction throughout."""
    entity, digest = derived.entity_type, derived.entity_digest
    if existing is not None:
        token, stored_type, stored_digest = existing
        if (
            not isinstance(stored_type, EntityType)
            or not isinstance(stored_digest, bytes)
            or stored_type != entity
            or stored_digest != digest
            or token
            not in {
                format_token(entity, digest, suffix_length=length)
                for length in SUFFIX_LENGTHS
            }
        ):
            raise PseudonymError("Token identity metadata is invalid.")
        return TokenAllocation(
            entity_type=entity,
            label=TOKEN_LABELS[entity],
            token=token,
            entity_digest=digest,
            reused=True,
            collision_count=0,
        )
    for collisions, length in enumerate(SUFFIX_LENGTHS):
        token = format_token(entity, digest, suffix_length=length)
        occupied = lookup_token(token)
        if occupied is None:
            return TokenAllocation(
                entity_type=entity,
                label=TOKEN_LABELS[entity],
                token=token,
                entity_digest=digest,
                reused=False,
                collision_count=collisions,
            )
        if not isinstance(occupied, bytes) or len(occupied) != 32:
            raise PseudonymError("Token identity metadata is invalid.")
        if occupied == digest:
            return TokenAllocation(
                entity_type=entity,
                label=TOKEN_LABELS[entity],
                token=token,
                entity_digest=digest,
                reused=True,
                collision_count=collisions,
            )
    raise TokenCollisionError("Token suffix allocation exhausted.")


def validate_token_identity(entity_type: EntityType, digest: bytes, token: str) -> None:
    """Validate registered token metadata without accessing its original value."""
    if (
        not isinstance(entity_type, EntityType)
        or not isinstance(digest, bytes)
        or len(digest) != 32
        or not isinstance(token, str)
        or token
        not in {
            format_token(entity_type, digest, suffix_length=length)
            for length in SUFFIX_LENGTHS
        }
    ):
        raise PseudonymError("Token identity metadata is invalid.")
