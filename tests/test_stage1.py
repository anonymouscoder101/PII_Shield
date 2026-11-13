"""Stage 1 integration uses the pinned local model and synthetic text only."""

import logging
import socket
from importlib.metadata import PackageNotFoundError

import pytest
import spacy
from presidio_analyzer import RecognizerResult

from shield.contracts import DetectionStage, EntityType
from shield.detect.stage1 import (
    MODEL_NAME,
    MODEL_VERSION,
    STAGE1_ENTITIES,
    DetectorUnavailable,
    Stage1DetectionError,
    Stage1Detector,
)


@pytest.fixture(scope="module")
def detector():
    return Stage1Detector.load()


def test_model_and_all_recognizers_are_present(detector):
    assert detector.model_name == MODEL_NAME
    assert detector.model_version == MODEL_VERSION
    assert set(detector.capabilities) == set(STAGE1_ENTITIES)
    assert all(names for names in detector.capabilities.values())
    assert detector.capabilities[EntityType.ADDRESS] == (
        "ShieldStreetAddressRecognizer",
    )
    assert "PERSON" in detector.ner_labels
    assert {"DATE_OF_BIRTH", "API_KEY", "SECRET", "EMPLOYEE_ID"} <= {
        entity.value for entity in detector.capabilities
    }


@pytest.mark.parametrize(
    "text,entity,value",
    [
        (
            "Email synthetic.person@example.test today.",
            EntityType.EMAIL_ADDRESS,
            "synthetic.person@example.test",
        ),
        ("Phone: +1 202-555-0147.", EntityType.PHONE_NUMBER, "+1 202-555-0147"),
        (
            "Test card 4111 1111 1111 1111.",
            EntityType.CREDIT_CARD,
            "4111 1111 1111 1111",
        ),
        ("Synthetic SSN 219-09-9999.", EntityType.US_SSN, "219-09-9999"),
        ("IP 192.0.2.14.", EntityType.IP_ADDRESS, "192.0.2.14"),
        ("IP 2001:db8::42.", EntityType.IP_ADDRESS, "2001:db8::42"),
        ("Meet Alice Smith tomorrow.", EntityType.PERSON, "Alice Smith"),
        ("Travel to London tomorrow.", EntityType.LOCATION, "London"),
        ("Address: 123 Example Street.", EntityType.ADDRESS, "123 Example Street"),
    ],
)
def test_synthetic_entity_cases(detector, text, entity, value):
    spans = detector.detect(text)
    assert any(
        span.entity_type == entity and text[span.start : span.end] == value
        for span in spans
    )
    assert all(span.stage == DetectionStage.STAGE_1 for span in spans)
    assert all(0 <= span.start < span.end <= len(text) for span in spans)
    assert spans == sorted(
        spans,
        key=lambda span: (
            span.start,
            span.end,
            span.entity_type.value,
            -span.confidence,
        ),
    )


def test_unicode_repetition_and_no_source_values_in_spans(detector):
    text = "🛡️ e\u0301: synthetic@example.test and synthetic@example.test"
    spans = [
        span
        for span in detector.detect(text)
        if span.entity_type == EntityType.EMAIL_ADDRESS
    ]
    assert len(spans) == 2
    assert [text[span.start : span.end] for span in spans] == [
        "synthetic@example.test"
    ] * 2
    assert all("synthetic@example.test" not in repr(span) for span in spans)


def test_empty_and_clean_text(detector):
    assert detector.detect("") == []
    assert detector.detect("Please summarize these general ideas.") == []


def test_detection_does_not_use_network_or_leak_debug_context(
    detector, monkeypatch, caplog
):
    def forbidden(*args, **kwargs):
        pytest.fail("detection must be local")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    caplog.set_level(logging.DEBUG)
    text = "Synthetic confidential context: email synthetic@example.test"
    assert any(
        span.entity_type == EntityType.EMAIL_ADDRESS for span in detector.detect(text)
    )
    assert "synthetic@example.test" not in caplog.text
    assert "confidential" not in caplog.text


def test_missing_model_does_not_download(monkeypatch):
    from shield.detect import stage1

    def missing(name):
        raise PackageNotFoundError(name)

    def forbidden(*args, **kwargs):
        pytest.fail("must not load or download a missing model")

    monkeypatch.setattr(stage1, "version", missing)
    monkeypatch.setattr(spacy, "load", forbidden)
    with pytest.raises(DetectorUnavailable, match="Stage 1 model is unavailable"):
        Stage1Detector.load()


def test_wrong_model_version_fails_without_loading(monkeypatch):
    from shield.detect import stage1

    monkeypatch.setattr(stage1, "version", lambda name: "0.0.0")
    with pytest.raises(DetectorUnavailable):
        Stage1Detector.load()


def test_pipeline_without_ner_fails():
    with pytest.raises(DetectorUnavailable):
        Stage1Detector(spacy.blank("en"))


def test_missing_recognizer_is_not_silently_ignored(detector, monkeypatch):
    from presidio_analyzer import Pattern, PatternRecognizer

    from shield.detect import stage1

    monkeypatch.setattr(
        stage1,
        "IpRecognizer",
        lambda: PatternRecognizer(
            supported_entity="UNSUPPORTED",
            patterns=[Pattern("synthetic", "x", 0.5)],
            name="MissingIpRecognizer",
        ),
    )
    with pytest.raises(DetectorUnavailable):
        Stage1Detector(detector._analyzer.nlp_engine.nlp["en"])


@pytest.mark.parametrize(
    "result",
    [
        RecognizerResult("PERSON", 0, 999, 0.8),
        RecognizerResult("PERSON", 0, 2, float("nan")),
        RecognizerResult("UNSUPPORTED", 0, 2, 0.8),
    ],
)
def test_invalid_detector_output_fails_safely(detector, monkeypatch, result):
    monkeypatch.setattr(detector._analyzer, "analyze", lambda **kwargs: [result])
    with pytest.raises(Stage1DetectionError) as exc:
        detector.detect("Synthetic private input")
    assert "private" not in str(exc.value)


def test_detector_failure_never_echoes_source(detector, monkeypatch, caplog):
    def failure(**kwargs):
        raise RuntimeError(kwargs["text"])

    monkeypatch.setattr(detector._analyzer, "analyze", failure)
    with pytest.raises(Stage1DetectionError) as exc:
        detector.detect("Synthetic confidential input")
    assert str(exc.value) == "Stage 1 detection failed."
    assert "confidential" not in caplog.text


def test_missing_required_ner_labels_fail():
    nlp = spacy.blank("en")
    nlp.add_pipe("ner").add_label("PERSON")
    with pytest.raises(DetectorUnavailable):
        Stage1Detector(nlp)


def test_regex_timeout_fails_instead_of_returning_partial_detections(
    detector, monkeypatch
):
    from shield.detect import stage1

    recognizer = next(
        rec
        for rec in detector._analyzer.registry.recognizers
        if rec.name == "ShieldEmailRecognizer"
    )
    pattern = recognizer.patterns[0]

    class TimeoutRegex:
        def finditer(self, *args, **kwargs):
            raise TimeoutError("Synthetic sensitive text")

    monkeypatch.setattr(pattern, "compiled_regex", stage1._StrictRegex(TimeoutRegex()))
    with pytest.raises(Stage1DetectionError):
        detector.detect("synthetic@example.test")


def test_analyze_applies_snapshot_policy_and_retains_raw_detection(detector):
    from shield.config import DetectionConfig

    changed = Stage1Detector(
        detector._analyzer.nlp_engine.nlp["en"],
        config=DetectionConfig(threshold=0.8, allowlist=["EMP-123456"]),
    )
    text = "Employee EMP-123456, password=syntheticsecret"
    assert any(
        span.entity_type == EntityType.EMPLOYEE_ID for span in changed.detect(text)
    )
    result = changed.analyze(text)
    assert all(span.entity_type != EntityType.EMPLOYEE_ID for span in result.spans)
    assert result.report.allowlisted_disclosure_counts == {EntityType.EMPLOYEE_ID: 1}
    value_start = text.index("syntheticsecret")
    assert any(
        span.start <= value_start and span.end >= len(text) for span in result.spans
    )
    strict = Stage1Detector(
        detector._analyzer.nlp_engine.nlp["en"], config=DetectionConfig(threshold=1)
    )
    assert strict.detect("EMP-123456")
    assert strict.analyze("EMP-123456").spans == ()


def test_nested_same_type_match_survives_allowlisted_outer_value(detector):
    from shield.config import DetectionConfig

    text = 'password="Bearer syntheticsecret12345"'
    outer = "Bearer syntheticsecret12345"
    inner = "syntheticsecret12345"
    changed = Stage1Detector(
        detector._analyzer.nlp_engine.nlp["en"],
        config=DetectionConfig(allowlist=[outer]),
    )
    candidates = changed.detect(text)
    assert any(
        span.entity_type == EntityType.SECRET and text[span.start : span.end] == inner
        for span in candidates
    )
    result = changed.analyze(text)
    start = text.index(inner)
    assert any(
        span.start <= start and span.end >= start + len(inner) for span in result.spans
    )
