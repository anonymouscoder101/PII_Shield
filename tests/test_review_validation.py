"""Strict local reviewer JSON, original-coordinate additions and merged plans."""

import json
import re

import pytest
from pydantic import SecretStr

from shield.config import DetectionConfig
from shield.contracts import DetectedSpan, DetectionStage, EntityType
from shield.detect.contextual import ContextualReview
from shield.detect.resolve import SpanPolicy
from shield.session import ephemeral_session
from shield.substitute import sanitize_text


class Detector:
    policy = SpanPolicy()

    def detect(self, text):
        return [
            DetectedSpan(
                start=m.start(),
                end=m.end(),
                entity_type=EntityType.PERSON,
                confidence=0.9,
            )
            for m in re.finditer("Alice|Christopher Example", text)
        ]


def review(text, output, state):
    result = sanitize_text(text, state, Detector())
    return ContextualReview(
        stage1=result,
        source_map=result.source_map,
        raw_output=SecretStr(
            output(result.sanitized_text) if callable(output) else output
        ),
    )


def candidate(masked, quoted, **extra):
    start = masked.index(quoted)
    return {
        "entity_type": "CONTEXTUAL",
        "text": quoted,
        "start": start,
        "end": start + len(quoted),
        "confidence": 0.95,
    } | extra


def test_exact_quotes_map_after_multiple_replacements_and_merge():
    from shield.detect.review_validation import validate_review

    text = "🛡️ Alice and Christopher Example know the only cardiologist."
    with ephemeral_session() as state:
        result = review(
            text,
            lambda masked: json.dumps(
                {"spans": [candidate(masked, "the only cardiologist")]}
            ),
            state,
        )
        validated = validate_review(SecretStr(text), result, SpanPolicy())
        assert len(validated.additions) == 1 and len(validated.resolved.spans) == 3
        (span,) = validated.additions
        assert text[span.start : span.end] == "the only cardiologist"
        assert span.stage == DetectionStage.STAGE_2
        assert span.entity_type == EntityType.CONTEXTUAL
        assert validated.resolved.report.protected_count == 3
        assert "cardiologist" not in repr(validated) + str(validated.model_dump())
        assert len(state.mappings) == 2  # validation never allocates additions


@pytest.mark.parametrize(
    "payload",
    [
        "not JSON private-reason",
        "[]",
        "{}",
        '{"spans":[],"remove":true}',
        '{"spans":[],"spans":[]}',
        '{"spans":[{"entity_type":"ALIEN","text":"x","start":0,"end":1,"confidence":1}]}',
        '{"spans":[{"entity_type":"PERSON","text":"x","start":true,"end":1,"confidence":1}]}',
        '{"spans":[{"entity_type":"PERSON","text":"x","start":"0","end":1,"confidence":1}]}',
        '{"spans":[{"entity_type":"PERSON","text":"x","start":0,"end":1}]}',
        '{"spans":[{"entity_type":"PERSON","text":"x","start":0,"end":1,"confidence":NaN}]}',
    ],
)
def test_schema_failures_are_static_and_never_partial(payload):
    from shield.detect.review_validation import ReviewerOutputError, validate_review

    with ephemeral_session() as state:
        result = review("Alice works here", payload, state)
        with pytest.raises(ReviewerOutputError) as error:
            validate_review(SecretStr("Alice works here"), result, SpanPolicy())
        assert str(error.value) == "Local reviewer output is invalid."


def test_invalid_candidates_are_discarded_without_searching_for_quotes():
    from shield.detect.review_validation import validate_review

    text = "Alice met a neighbor twice: neighbor."

    def output(masked):
        good = candidate(masked, "neighbor")
        token = masked[: masked.index(" met")]
        invalid = [
            good | {"start": -1},
            good | {"end": 999},
            good | {"end": good["start"]},
            good | {"text": "wrong quote"},
            good | {"start": 0, "end": 1, "text": masked[:1]},
            candidate(masked, token + " met"),
        ]
        return json.dumps({"spans": invalid + [good]})

    with ephemeral_session() as state:
        validated = validate_review(
            SecretStr(text), review(text, output, state), SpanPolicy()
        )
        assert validated.rejected_count == 6
        assert len(validated.additions) == 1
        assert validated.additions[0].start == text.index("neighbor")


def test_threshold_allowlist_duplicates_and_overlaps_share_policy():
    from shield.detect.review_validation import validate_review

    text = "Alice knows a rare local specialty."

    def output(masked):
        whole = candidate(masked, "rare local specialty")
        inside = candidate(masked, "local specialty", confidence=0.8)
        low = candidate(masked, "knows", confidence=0.1)
        allowed = candidate(masked, "a rare", confidence=0.9)
        return json.dumps({"spans": [whole, whole, inside, low, allowed]})

    with ephemeral_session() as state:
        validated = validate_review(
            SecretStr(text),
            review(text, output, state),
            SpanPolicy(DetectionConfig(allowlist=["a rare"])),
        )
        assert len(validated.additions) == 1
        assert validated.resolved.below_threshold_count == 1
        assert validated.resolved.report.allowlisted_disclosure_count == 1
        assert len(validated.resolved.spans) == 2


def test_wrong_original_snapshot_is_not_accepted():
    from shield.detect.review_validation import ReviewerOutputError, validate_review

    with ephemeral_session() as state:
        result = review(
            "Alice knows neighbor",
            lambda m: json.dumps({"spans": [candidate(m, "neighbor")]}),
            state,
        )
        with pytest.raises(ReviewerOutputError):
            validate_review(SecretStr("Alice knows stranger"), result, SpanPolicy())


async def test_masked_handoff_through_validated_batch_plans():
    from shield.detect.contextual import review_and_resolve_texts

    seen = []

    class Reviewer:
        async def review(self, text):
            masked = text.get_secret_value()
            seen.append(masked)
            return SecretStr(json.dumps({"spans": [candidate(masked, "neighbor")]}))

    texts = ("Alice met neighbor", "Christopher Example met neighbor")
    with ephemeral_session() as state:
        plans = await review_and_resolve_texts(
            iter(texts), state, Detector(), Reviewer()
        )
        assert len(plans) == 2 and len(seen) == 2
        for source, plan in zip(texts, plans, strict=True):
            assert len(plan.resolved.spans) == 2
            assert source[plan.additions[0].start : plan.additions[0].end] == "neighbor"
        assert all(
            "Alice" not in text and "Christopher Example" not in text for text in seen
        )


def test_contextual_entities_persist_and_restore_with_existing_vault_schema(tmp_path):
    from shield.config import Argon2Config, VaultConfig
    from shield.persistent import PersistentSessions
    from shield.rehydrate import rehydrate_text

    config = VaultConfig(
        path=tmp_path / "vault.db",
        argon2=Argon2Config(memory_kib=32, time_cost=1, parallelism=1),
    )
    with PersistentSessions.open(config, SecretStr("synthetic")) as service:
        sid = service.create().session_id
        with service.use(sid) as state:
            token = state.allocate(
                EntityType.CONTEXTUAL, SecretStr("The only cardiologist")
            ).token
            assert token.startswith("[CONTEXTUAL_")
    with PersistentSessions.open(config, SecretStr("synthetic")) as service:
        with service.use(sid) as state:
            assert rehydrate_text(token.lower(), state).text == "The only cardiologist"
            assert (
                state.allocate(
                    EntityType.CONTEXTUAL, SecretStr(" THE ONLY CARDIOLOGIST ")
                ).token
                == token
            )
