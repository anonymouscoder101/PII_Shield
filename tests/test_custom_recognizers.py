"""Synthetic custom recognizers and configurable Stage 1 coverage."""

import logging
import socket

import pytest
from pydantic import ValidationError

from shield.config import ConfigurationError, DetectionConfig, load_config
from shield.contracts import EntityType
from shield.detect.stage1 import STAGE1_ENTITIES, Stage1Detector


@pytest.fixture(scope="module")
def detector():
    return Stage1Detector.load()


@pytest.mark.parametrize(
    "text,entity,value",
    [
        ("DOB: 1990-09-14", EntityType.DATE_OF_BIRTH, "1990-09-14"),
        ("date of birth = 14/09/1990", EntityType.DATE_OF_BIRTH, "14/09/1990"),
        ("Born on 14 June 1990.", EntityType.DATE_OF_BIRTH, "14 June 1990"),
        ('{"dob": "2000-02-29"}', EntityType.DATE_OF_BIRTH, "2000-02-29"),
        ("Birthdate: 09/14/1990", EntityType.DATE_OF_BIRTH, "09/14/1990"),
        ('api_key="synthetic-Key_123456"', EntityType.API_KEY, "synthetic-Key_123456"),
        (
            "Authorization: Bearer synthetic.token_1234",
            EntityType.SECRET,
            "synthetic.token_1234",
        ),
        (
            "client_secret=synthetic-client-secret",
            EntityType.SECRET,
            "synthetic-client-secret",
        ),
        (
            'password="Synthetic pass phrase"',
            EntityType.SECRET,
            "Synthetic pass phrase",
        ),
        ("password=abc", EntityType.SECRET, "abc"),
        (
            "Key sk-syntheticABC1234567890",
            EntityType.API_KEY,
            "sk-syntheticABC1234567890",
        ),
        (
            "Key ghp_syntheticABC1234567890123456",
            EntityType.API_KEY,
            "ghp_syntheticABC1234567890123456",
        ),
        ("Employee: EMP-123456", EntityType.EMPLOYEE_ID, "EMP-123456"),
    ],
)
def test_value_coordinates_exclude_labels_and_quotes(detector, text, entity, value):
    spans = detector.detect(text)
    assert any(
        span.entity_type == entity and text[span.start : span.end] == value
        for span in spans
    )
    assert all(value not in repr(span) for span in spans)


@pytest.mark.parametrize(
    "text",
    [
        "Meeting on 1990-09-14",
        "DOB: 2001-02-29",
        "DOB: 1990-13-40",
        "date of birth: unknown",
    ],
)
def test_only_labeled_calendar_dates_are_birth_dates(detector, text):
    assert not any(
        span.entity_type == EntityType.DATE_OF_BIRTH for span in detector.detect(text)
    )


def test_repeated_secrets_unicode_offsets_and_no_network_or_debug_values(
    detector, monkeypatch, caplog
):
    def forbidden(*args, **kwargs):
        pytest.fail("no network allowed")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    caplog.set_level(logging.DEBUG)
    text = '🛡️ password="Sýnthetic Secret"; password="Sýnthetic Secret"'
    spans = [
        span for span in detector.detect(text) if span.entity_type == EntityType.SECRET
    ]
    assert [text[span.start : span.end] for span in spans] == ["Sýnthetic Secret"] * 2
    assert "Sýnthetic" not in caplog.text


def test_employee_pattern_and_phone_regions_are_configurable(detector):
    config = DetectionConfig(
        employee_id_pattern=r"\bSTAFF_[0-9]{6}\b", phone_regions=["GB"]
    )
    changed = Stage1Detector(detector._analyzer.nlp_engine.nlp["en"], config=config)
    text = "STAFF_123456 EMP-123456 phone 020 7946 0958"
    spans = changed.detect(text)
    assert any(
        span.entity_type == EntityType.EMPLOYEE_ID
        and text[span.start : span.end] == "STAFF_123456"
        for span in spans
    )
    assert not any(
        span.entity_type == EntityType.EMPLOYEE_ID
        and text[span.start : span.end] == "EMP-123456"
        for span in spans
    )
    assert any(
        span.entity_type == EntityType.PHONE_NUMBER
        and text[span.start : span.end] == "020 7946 0958"
        for span in spans
    )


@pytest.mark.parametrize(
    "location,address,employee", [("none", "none", False), ("places", "street", True)]
)
def test_policy_controls_advertised_and_detected_entities(
    detector, location, address, employee
):
    changed = Stage1Detector(
        detector._analyzer.nlp_engine.nlp["en"],
        config=DetectionConfig(
            location_policy=location,
            address_policy=address,
            employee_id_enabled=employee,
        ),
    )
    expected = set(STAGE1_ENTITIES)
    if location == "none":
        expected.remove(EntityType.LOCATION)
    if address == "none":
        expected.remove(EntityType.ADDRESS)
    if not employee:
        expected.remove(EntityType.EMPLOYEE_ID)
    assert set(changed.capabilities) == expected
    assert {
        span.entity_type
        for span in changed.detect("EMP-123456 lives at 123 Example Street in London.")
    } <= expected
    ner_config = changed._analyzer.nlp_engine.ner_model_configuration
    mapping = ner_config.model_to_presidio_entity_mapping
    assert ("FAC" in mapping) == (location == "all")


@pytest.mark.parametrize(
    "values",
    [
        {"phone_regions": []},
        {"phone_regions": ["ZZ"]},
        {"phone_regions": ["us"]},
        {"phone_regions": ["US", "US"]},
        {"employee_id_pattern": "("},
        {"employee_id_pattern": ".*"},
        {"location_policy": "everything"},
        {"address_policy": "all"},
    ],
)
def test_invalid_policy_configuration_is_rejected(values):
    with pytest.raises(ValidationError):
        DetectionConfig(**values)


def test_configuration_loads_without_model_and_hides_bad_pattern(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        "detection:\n  phone_regions: [US, GB]\n  location_policy: places\n"
        "  address_policy: none\n  employee_id_pattern: 'STAFF_[0-9]{6}'\n"
    )
    config = load_config(path).detection
    assert config.phone_regions == ["US", "GB"]
    assert config.address_policy == "none"
    path.write_text("detection: {employee_id_pattern: '(synthetic-sensitive'}")
    with pytest.raises(ConfigurationError) as exc:
        load_config(path)
    assert "synthetic-sensitive" not in str(exc.value)


def test_zero_width_employee_match_fails_instead_of_silently_missing(detector):
    from shield.detect.stage1 import Stage1DetectionError

    changed = Stage1Detector(
        detector._analyzer.nlp_engine.nlp["en"],
        config=DetectionConfig(employee_id_pattern=r"(?=EMP)"),
    )
    with pytest.raises(Stage1DetectionError):
        changed.detect("EMP-123456")


@pytest.mark.parametrize(
    "value", ["abc'def", "abc,def", "abc;def", "abc`def", 'abc"def', "abc=def"]
)
def test_bare_secret_punctuation_is_not_truncated(detector, value):
    text = f"password={value}"
    assert any(
        span.entity_type == EntityType.SECRET and text[span.start : span.end] == value
        for span in detector.detect(text)
    )


def test_example_employee_pattern_matches_baseline_identifier():
    from pathlib import Path

    import regex

    config = load_config(Path(__file__).resolve().parents[1] / "shield.example.yaml")
    assert (
        regex.fullmatch(config.detection.employee_id_pattern, "EMP-123456") is not None
    )


@pytest.mark.parametrize(
    "text,value",
    [
        ("password='Synthetic pass phrase'", "Synthetic pass phrase"),
        ("api_key=`synthetic key with spaces`", "synthetic key with spaces"),
        ('password="synthetic\\"secret"', 'synthetic\\"secret'),
    ],
)
def test_quoted_secrets_preserve_spaces_and_escapes(detector, text, value):
    assert any(
        span.entity_type in (EntityType.SECRET, EntityType.API_KEY)
        and text[span.start : span.end] == value
        for span in detector.detect(text)
    )
