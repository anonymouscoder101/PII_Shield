"""Domain contract boundaries using synthetic values only."""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from shield.contracts import (
    APIError,
    APIErrorDetail,
    DetectedSpan,
    EntityType,
    ErrorCode,
    ProtectionReport,
    SessionKind,
    SessionRecord,
    TokenMapping,
)


def test_span_coordinates_use_python_unicode_indices():
    text = "🙂 e\u0301 李 Example"
    start = text.index("李")
    span = DetectedSpan(
        start=start, end=start + 1, entity_type=EntityType.PERSON, confidence=0.9
    )

    assert span.validate_for_text(text) is span
    assert text[span.start : span.end] == "李"
    assert start != len(text[:start].encode("utf-8"))
    assert start != len(text[:start].encode("utf-16-le")) // 2
    with pytest.raises(ValueError, match="bounds"):
        span.validate_for_text("🙂")


@pytest.mark.parametrize(
    "overrides",
    [
        {"start": -1},
        {"end": 0},
        {"end": 1},
        {"start": 3, "end": 2},
        {"start": True},
        {"start": "1"},
        {"confidence": -0.1},
        {"confidence": 1.1},
        {"confidence": float("nan")},
        {"confidence": float("inf")},
        {"text": "Synthetic Person"},
    ],
)
def test_invalid_span_metadata_is_rejected(overrides):
    values = dict(start=1, end=2, entity_type=EntityType.PERSON, confidence=0.9)
    with pytest.raises(ValidationError):
        DetectedSpan(**(values | overrides))


def test_mapping_preserves_first_spelling_without_exposing_value_or_digest():
    value = "Example.Person@example.test"
    digest = b"\xff" * 32
    mapping = TokenMapping(
        session_id="synthetic-session",
        token="[EMAIL_7K2Q]",
        entity_type=EntityType.EMAIL_ADDRESS,
        entity_digest=digest,
        original_value=value,
    )

    assert mapping.original_value.get_secret_value() == value
    assert mapping.entity_digest == digest
    assert "entity_digest" not in mapping.model_dump()
    assert value not in repr(mapping)
    assert value not in str(mapping.model_dump())
    assert value not in mapping.model_dump_json()
    assert "**********" in mapping.model_dump_json()


@pytest.mark.parametrize("size", [0, 4, 31, 33])
def test_truncated_or_oversized_entity_identity_is_rejected(size):
    with pytest.raises(ValidationError):
        TokenMapping(
            session_id="synthetic-session",
            token="[PERSON_7K2Q]",
            entity_type=EntityType.PERSON,
            entity_digest=b"x" * size,
            original_value="Synthetic Person",
        )


def test_session_lifetimes_distinguish_ephemeral_and_persistent_records():
    created = datetime(2026, 10, 14, tzinfo=UTC)
    expires = created + timedelta(hours=1)
    ephemeral = SessionRecord(
        session_id="request-local", kind=SessionKind.EPHEMERAL, created_at=created
    )
    persistent = SessionRecord(
        session_id="reusable",
        kind=SessionKind.PERSISTENT,
        created_at=created,
        expires_at=expires,
    )

    assert not ephemeral.is_expired(expires)
    assert not persistent.is_expired(expires - timedelta(microseconds=1))
    assert persistent.is_expired(expires)
    with pytest.raises(ValueError, match="timezone-aware"):
        persistent.is_expired(datetime(2026, 10, 14))

    for kind, expiry in [
        (SessionKind.EPHEMERAL, expires),
        (SessionKind.PERSISTENT, None),
        (SessionKind.PERSISTENT, created),
        (SessionKind.PERSISTENT, created - timedelta(seconds=1)),
    ]:
        with pytest.raises(ValidationError):
            SessionRecord(
                session_id="invalid", kind=kind, created_at=created, expires_at=expiry
            )
    with pytest.raises(ValidationError):
        SessionRecord(
            session_id="naive",
            kind=SessionKind.EPHEMERAL,
            created_at=created.replace(tzinfo=None),
        )


def test_report_separates_protected_occurrences_from_allowlisted_disclosures():
    report = ProtectionReport(
        protected_counts={EntityType.PERSON: 3, EntityType.EMAIL_ADDRESS: 1},
        allowlisted_disclosure_counts={EntityType.PERSON: 2},
        unknown_token_count=1,
    )

    assert report.protected_count == 4
    assert report.allowlisted_disclosure_count == 2
    assert report.model_dump(mode="json")["protected_counts"] == {
        "PERSON": 3,
        "EMAIL_ADDRESS": 1,
    }
    with pytest.raises(ValidationError):
        ProtectionReport(protected_counts={EntityType.PERSON: -1})
    with pytest.raises(ValidationError):
        ProtectionReport(allowlisted_disclosure_counts={EntityType.PERSON: True})
    with pytest.raises(ValidationError):
        ProtectionReport(unknown_token_count="1")


def test_error_envelope_rejects_extra_data_at_each_level():
    detail = APIErrorDetail(
        code=ErrorCode.INVALID_REQUEST, message="Request validation failed."
    )
    error = APIError(error=detail)
    assert error.model_dump(mode="json") == {
        "error": {
            "code": "invalid_request",
            "message": "Request validation failed.",
        }
    }
    with pytest.raises(ValidationError):
        APIError(error=detail, request_body="synthetic body")
    with pytest.raises(ValidationError):
        APIError.model_validate_json(
            '{"error":{"code":"invalid_request","message":"Invalid request.",'
            '"provider_body":"synthetic body"}}'
        )


def test_validation_exception_text_hides_rejected_inputs():
    value = "synthetic-sensitive-input"
    with pytest.raises(ValidationError) as caught:
        DetectedSpan(start=value, end=2, entity_type=EntityType.PERSON, confidence=0.9)
    assert value not in str(caught.value)
