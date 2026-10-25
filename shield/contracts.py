"""Shared domain contracts; HTTP payloads and storage rows are defined separately.

Span coordinates are half-open Python string indices: ``text[start:end]``.
They count Unicode code points, not UTF-8 bytes, UTF-16 units, or graphemes.
No contract performs detection, token generation, encryption, or session cleanup.
"""

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Self

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    computed_field,
    field_validator,
    model_validator,
)

NonEmptyString = Annotated[str, Field(min_length=1)]
Count = Annotated[int, Field(ge=0)]


class Contract(BaseModel):
    """Reject extra fields and coercion, and hide input values in validation errors.

    Frozen models prevent field reassignment; nested dictionaries are not immutable.
    Callers must not log ValidationError.errors(), which can include input values.
    """

    model_config = ConfigDict(
        extra="forbid", strict=True, frozen=True, hide_input_in_errors=True
    )


class EntityType(StrEnum):
    """Detector entity names, distinct from the eventual token labels."""

    PERSON = "PERSON"
    EMAIL_ADDRESS = "EMAIL_ADDRESS"
    PHONE_NUMBER = "PHONE_NUMBER"
    CREDIT_CARD = "CREDIT_CARD"
    US_SSN = "US_SSN"
    LOCATION = "LOCATION"
    ADDRESS = "ADDRESS"
    IP_ADDRESS = "IP_ADDRESS"
    DATE_OF_BIRTH = "DATE_OF_BIRTH"
    API_KEY = "API_KEY"
    SECRET = "SECRET"
    EMPLOYEE_ID = "EMPLOYEE_ID"


class DetectionStage(StrEnum):
    STAGE_1 = "stage1"
    STAGE_2 = "stage2"


class DetectedSpan(Contract):
    """A nonempty detection in original text, without retaining the detected value.

    Construction checks ordering; ``validate_for_text`` additionally checks bounds
    against the source string. Reviewers must map masked coordinates back before
    creating this contract. Thresholding and overlap resolution happen separately.
    """

    start: Annotated[int, Field(ge=0)]
    end: Annotated[int, Field(gt=0)]
    entity_type: EntityType
    confidence: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
    stage: DetectionStage = DetectionStage.STAGE_1

    @model_validator(mode="after")
    def ordered_offsets(self) -> Self:
        if self.end <= self.start:
            raise ValueError("span end must be greater than start")
        return self

    def validate_for_text(self, text: str) -> Self:
        """Validate source bounds without including source text in failures."""
        if self.end > len(text):
            raise ValueError("span exceeds source text bounds")
        return self


class TokenMapping(Contract):
    """An in-memory entity mapping belonging to exactly one session.

    ``entity_digest`` is the full HMAC-SHA256 identity, never a short suffix.
    ``original_value`` holds the first observed spelling of that identity. It is
    masked in representations/JSON; trusted restoration or encryption code must
    explicitly call ``original_value.get_secret_value()``. This is not a vault
    row: persist only authenticated ciphertext in the later vault implementation.
    """

    session_id: NonEmptyString
    token: NonEmptyString
    entity_type: EntityType
    entity_digest: Annotated[
        bytes, Field(min_length=32, max_length=32, repr=False, exclude=True)
    ]
    original_value: SecretStr = Field(repr=False)

    @field_validator("original_value")
    @classmethod
    def nonempty_original(cls, value: SecretStr) -> SecretStr:
        if not value.get_secret_value():
            raise ValueError("original value must not be empty")
        return value


class SessionKind(StrEnum):
    EPHEMERAL = "ephemeral"
    PERSISTENT = "persistent"


class SessionRecord(Contract):
    """Key-free metadata for internal sessions, including ephemeral request IDs.

    Only persistent IDs may be returned for client reuse. Ephemeral sessions end
    with the request and have no TTL timestamp. Keys and mappings live in separate
    runtime/storage objects; this record does not manage their lifecycle.
    """

    session_id: NonEmptyString
    kind: SessionKind
    created_at: AwareDatetime
    expires_at: AwareDatetime | None = None

    @model_validator(mode="after")
    def valid_lifetime(self) -> Self:
        if self.kind == SessionKind.EPHEMERAL:
            if self.expires_at is not None:
                raise ValueError("ephemeral sessions must not have an expiry timestamp")
        elif self.expires_at is None or self.expires_at <= self.created_at:
            raise ValueError("persistent sessions require an expiry after creation")
        return self

    def is_expired(self, at: datetime) -> bool:
        """Expiry is inclusive; ephemeral lifetime is enforced by request cleanup."""
        if at.tzinfo is None or at.utcoffset() is None:
            raise ValueError("expiry comparison requires a timezone-aware timestamp")
        return self.expires_at is not None and at >= self.expires_at


class ProtectionReport(Contract):
    """PII-free occurrence counts, not unique mapping counts or a leakage guarantee.

    Protected counts describe final resolved spans replaced across all messages.
    Allowlisted counts describe intentional disclosures and remain separate.
    Unknown tokens count response occurrences left unchanged during restoration.
    """

    protected_counts: dict[EntityType, Count] = Field(default_factory=dict)
    allowlisted_disclosure_counts: dict[EntityType, Count] = Field(default_factory=dict)
    unknown_token_count: Count = 0

    @computed_field
    @property
    def protected_count(self) -> int:
        return sum(self.protected_counts.values())

    @computed_field
    @property
    def allowlisted_disclosure_count(self) -> int:
        return sum(self.allowlisted_disclosure_counts.values())


class ErrorCode(StrEnum):
    """Stable machine-readable categories; HTTP status policy is a gateway concern."""

    INVALID_REQUEST = "invalid_request"
    REQUEST_TOO_LARGE = "request_too_large"
    VAULT_LOCKED = "vault_locked"
    SESSION_NOT_FOUND = "session_not_found"
    SESSION_EXPIRED = "session_expired"
    DETECTION_FAILED = "detection_failed"
    PROTECTION_BLOCKED = "protection_blocked"
    REVIEWER_UNAVAILABLE = "reviewer_unavailable"
    UPSTREAM_TIMEOUT = "upstream_timeout"
    UPSTREAM_ERROR = "upstream_error"
    INTERNAL_ERROR = "internal_error"
    NOT_FOUND = "not_found"
    METHOD_NOT_ALLOWED = "method_not_allowed"
    UNSUPPORTED_MEDIA_TYPE = "unsupported_media_type"
    PROTECTION_UNAVAILABLE = "protection_unavailable"


class APIErrorDetail(Contract):
    """Public error detail. Messages must be static, privacy-safe text.

    Never populate the message with source text, validation inputs, provider error
    bodies, credentials, or exception strings. Validation cannot sanitize prose.
    """

    code: ErrorCode
    message: NonEmptyString


class APIError(Contract):
    """JSON error envelope, independent of HTTP exception handling."""

    error: APIErrorDetail
