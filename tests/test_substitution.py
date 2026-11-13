"""Synthetic span substitution and session-bound placeholder preservation."""

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import SecretStr

from shield.config import Argon2Config, DetectionConfig, VaultConfig
from shield.contracts import DetectedSpan, EntityType
from shield.detect.resolve import SpanPolicy
from shield.persistent import PersistentSessions
from shield.session import ephemeral_session
from shield.substitute import (
    TokenSubstitutionError,
    UnknownSessionToken,
    sanitize_text,
    sanitize_texts,
    substitute_spans,
)


def span(start, end, entity=EntityType.PERSON):
    return DetectedSpan(start=start, end=end, entity_type=entity, confidence=0.9)


def test_right_to_left_unicode_replacements_and_first_source_spelling():
    text = "🛡️ José; JOSE\u0301; Bob."
    first, second, third = text.index("José"), text.index("JOSE"), text.index("Bob")
    with ephemeral_session() as state:
        result = substitute_spans(
            text,
            [span(third, third + 3), span(second, second + 5), span(first, first + 4)],
            state,
        )
        one, two, three = result.replacements
        assert one.token == two.token and three.token != one.token
        assert result.sanitized_text == f"🛡️ {one.token}; {one.token}; {three.token}."
        assert [item.span.start for item in result.replacements] == [
            first,
            second,
            third,
        ]
        assert state.mappings[one.token].original_value.get_secret_value() == "José"
        assert result.report.protected_count == 3
        assert "José" not in repr(result)


def test_adjacent_spans_and_surrounding_punctuation_stay_correct():
    with ephemeral_session() as state:
        result = substitute_spans("(ABCDEF)!", [span(1, 4), span(4, 7)], state)
        assert (
            result.sanitized_text
            == "(" + "".join(item.token for item in result.replacements) + ")!"
        )


def test_known_exact_tokens_are_preserved_and_not_allocated_again():
    with ephemeral_session() as state:
        known = state.allocate(EntityType.PERSON, SecretStr("Synthetic Alice")).token
        text = f"Previously {known}; then {known}."
        start = text.index(known)
        result = substitute_spans(text, [span(start + 1, start + 5)], state)
        assert result.sanitized_text == text
        assert result.preserved_token_count == 2
        assert result.replacements == ()
        assert len(state.mappings) == 1
        assert result.report.protected_count == 0


def test_unknown_canonical_token_fails_before_allocating_anything():
    with ephemeral_session() as state:
        with pytest.raises(UnknownSessionToken) as exc:
            substitute_spans("Alice [PERSON_ABCD]", [span(0, 5)], state)
        assert "[PERSON_ABCD]" not in str(exc.value)
        assert not state.mappings


def test_other_session_token_is_not_a_known_token():
    with ephemeral_session() as one, ephemeral_session() as two:
        token = one.allocate(EntityType.PERSON, SecretStr("Synthetic")).token
        with pytest.raises(UnknownSessionToken):
            substitute_spans(token, [], two)


def test_noncanonical_lookalike_is_not_exempt_from_normal_detection():
    text = "[person_abcd]"
    with ephemeral_session() as state:
        result = substitute_spans(text, [span(0, len(text), EntityType.SECRET)], state)
        assert result.sanitized_text == result.replacements[0].token
        assert result.preserved_token_count == 0


@pytest.mark.parametrize(
    "values",
    [
        [span(0, 4), span(2, 5)],
        [span(0, 100)],
        [span(0, 1).model_copy(update={"start": -1})],
    ],
)
def test_invalid_or_overlapping_spans_fail_before_allocation(values):
    with ephemeral_session() as state:
        with pytest.raises(TokenSubstitutionError):
            substitute_spans("Alice", values, state)
        assert not state.mappings


def test_crossing_known_token_boundary_fails_without_destroying_it():
    with ephemeral_session() as state:
        token = state.allocate(EntityType.PERSON, SecretStr("Synthetic")).token
        text = "Alice " + token
        with pytest.raises(TokenSubstitutionError):
            substitute_spans(text, [span(0, len(text))], state)
        assert len(state.mappings) == 1


class FakeDetector:
    def __init__(self, config=None):
        self.policy = SpanPolicy(config)
        self.inputs = []

    def detect(self, text):
        self.inputs.append(text)
        start = text.find("Alice")
        return [] if start < 0 else [span(start, start + 5)]


def test_sanitize_masks_known_tokens_for_detector_but_uses_original_coordinates():
    with ephemeral_session() as state:
        token = state.allocate(EntityType.PERSON, SecretStr("Synthetic")).token
        text = f"🛡️ {token}: Alice"
        detector = FakeDetector()
        result = sanitize_text(text, state, detector)
        assert detector.inputs == ["🛡️ " + " " * len(token) + ": Alice", text]
        assert result.replacements[0].span.start == text.index("Alice")
        assert result.sanitized_text == f"🛡️ {token}: {result.replacements[0].token}"
        assert result.preserved_token_count == 1


def test_sanitize_applies_allowlist_without_allocating_exempt_values():
    with ephemeral_session() as state:
        result = sanitize_text(
            "Alice", state, FakeDetector(DetectionConfig(allowlist=["Alice"]))
        )
        assert result.sanitized_text == "Alice"
        assert result.report.allowlisted_disclosure_count == 1
        assert not state.mappings


def test_batch_preflight_prevents_later_literal_from_becoming_accidentally_known():
    from shield.pseudonym import derive_token

    with ephemeral_session() as state:
        would_be_token = derive_token(
            EntityType.PERSON, SecretStr("Alice"), state.key
        ).token
        with pytest.raises(UnknownSessionToken):
            sanitize_texts(["Alice", would_be_token], state, FakeDetector())
        assert not state.mappings


def test_persistent_history_tokens_survive_restart_without_decrypting(
    tmp_path, monkeypatch
):
    from shield import vault

    config = VaultConfig(
        path=tmp_path / "vault.db",
        argon2=Argon2Config(memory_kib=32, time_cost=1, parallelism=1),
    )
    with PersistentSessions.open(config, SecretStr("synthetic")) as service:
        record = service.create()
        with service.use(record.session_id) as active:
            token = active.allocate(
                EntityType.PERSON, SecretStr("Synthetic Alice")
            ).token
    with PersistentSessions.open(config, SecretStr("synthetic")) as service:
        with service.use(record.session_id) as active:

            def forbidden(*args, **kwargs):
                pytest.fail("token preservation must not need plaintext")

            monkeypatch.setattr(vault, "decrypt_entry", forbidden)
            result = sanitize_text("Previously " + token, active, FakeDetector())
            assert result.sanitized_text == "Previously " + token
            assert result.preserved_token_count == 1


def test_empty_text_and_closed_scope_handling():
    with ephemeral_session() as state:
        assert substitute_spans("", [], state).sanitized_text == ""
    with pytest.raises(TokenSubstitutionError):
        substitute_spans("", [], state)


@pytest.mark.parametrize("allow", [False, True])
def test_crossing_candidates_are_filtered_by_policy_before_boundary_rejection(allow):
    with ephemeral_session() as state:
        token = state.allocate(EntityType.PERSON, SecretStr("Synthetic")).token
        text = "Alice " + token

        class Crossing:
            policy = SpanPolicy(DetectionConfig(allowlist=[text] if allow else []))

            def detect(self, masked):
                return [
                    DetectedSpan(
                        start=0,
                        end=len(masked),
                        entity_type=EntityType.PERSON,
                        confidence=0.9 if allow else 0.1,
                    )
                ]

        result = sanitize_text(text, state, Crossing())
        assert result.sanitized_text == text
        assert result.report.allowlisted_disclosure_count == int(allow)
        assert result.below_threshold_count == int(not allow)


def test_allocation_failure_is_static_and_returns_no_partial_text(monkeypatch):
    from shield.session import EphemeralSession

    def failed(*args, **kwargs):
        raise RuntimeError("Synthetic sensitive failure")

    with ephemeral_session() as state:
        monkeypatch.setattr(EphemeralSession, "allocate", failed)
        with pytest.raises(TokenSubstitutionError) as exc:
            substitute_spans("Alice", [span(0, 5)], state)
        assert str(exc.value) == "Token substitution failed."


def test_unknown_token_is_rejected_even_if_a_candidate_would_cover_it():
    with ephemeral_session() as state:
        text = "[SECRET_ABCD]"
        with pytest.raises(UnknownSessionToken):
            substitute_spans(text, [span(0, len(text), EntityType.SECRET)], state)
        assert not state.mappings


def test_sanitize_uses_real_detector_and_preserves_known_history():
    from shield.detect.stage1 import Stage1Detector

    detector = Stage1Detector.load()
    with ephemeral_session() as state:
        known = state.allocate(EntityType.PERSON, SecretStr("Synthetic Person")).token
        text = f"Previously {known}. Email synthetic.person@example.test."
        result = sanitize_text(text, state, detector)
        assert known in result.sanitized_text
        assert "synthetic.person@example.test" not in result.sanitized_text
        assert result.preserved_token_count == 1
        assert any(
            item.span.entity_type == EntityType.EMAIL_ADDRESS
            for item in result.replacements
        )


@given(
    st.lists(
        st.text(
            alphabet=st.characters(
                blacklist_categories=("Cs",), blacklist_characters="[]"
            ),
            min_size=1,
            max_size=6,
        ),
        min_size=2,
        max_size=8,
    )
)
def test_substitution_preserves_every_unselected_unicode_segment(segments):
    text = "".join(segments)
    spans, offset = [], 0
    for index, part in enumerate(segments):
        if index % 2:
            spans.append(span(offset, offset + len(part), EntityType.SECRET))
        offset += len(part)
    with ephemeral_session() as state:
        result = substitute_spans(text, reversed(spans), state)
        replacements = iter(result.replacements)
        expected = "".join(
            next(replacements).token if index % 2 else part
            for index, part in enumerate(segments)
        )
        assert result.sanitized_text == expected
        assert len(result.replacements) == len(spans)


def test_known_token_inside_secret_cannot_split_off_an_unprotected_suffix():
    from shield.detect.stage1 import Stage1Detector

    detector = Stage1Detector.load()
    with ephemeral_session() as state:
        token = state.allocate(EntityType.PERSON, SecretStr("Synthetic Person")).token
        text = f"password=syntheticprefix123{token}syntheticsuffix456"
        assert any(
            span.entity_type == EntityType.SECRET and span.end == len(text)
            for span in detector.detect(text)
        )
        with pytest.raises(TokenSubstitutionError):
            sanitize_text(text, state, detector)
        assert len(state.mappings) == 1
