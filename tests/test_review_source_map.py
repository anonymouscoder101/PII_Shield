"""Stage 1-only masked handoff and exact source coordinates with Unicode."""

import re

import pytest
from pydantic import SecretStr

from shield.config import DetectionConfig
from shield.contracts import DetectedSpan, EntityType
from shield.detect.resolve import SpanPolicy
from shield.session import ephemeral_session
from shield.substitute import UnknownSessionToken, sanitize_text


class Detector:
    policy = SpanPolicy(DetectionConfig())

    def detect(self, text):
        return [
            DetectedSpan(
                start=m.start(),
                end=m.end(),
                entity_type=EntityType.PERSON,
                confidence=0.99,
            )
            for m in re.finditer("Alice|Christopher Example", text)
        ]


def test_map_handles_expansion_contraction_and_unicode():
    text = "🛡️ Alice met Christopher Example at café."
    with ephemeral_session() as state:
        result = sanitize_text(text, state, Detector())
        mapping = result.source_map
        assert mapping.original_length == len(text)
        assert mapping.masked_length == len(result.sanitized_text)
        for word in ("🛡️", "met", "café"):
            start = result.sanitized_text.index(word)
            assert mapping.to_original(start, start + len(word)) == (
                text.index(word),
                text.index(word) + len(word),
            )
        for replacement in result.replacements:
            start = result.sanitized_text.index(replacement.token)
            assert mapping.to_original(start, start + len(replacement.token)) is None
            assert mapping.to_original(start + 1, start + 3) is None
        assert mapping.to_original(0, len(result.sanitized_text)) is None
        assert "source_map" not in result.model_dump()


def test_preexisting_tokens_and_repeated_tokens_are_unmappable():
    with ephemeral_session() as state:
        token = state.allocate(EntityType.PERSON, SecretStr("Alice")).token
        text = f"{token} then Alice then Alice."
        result = sanitize_text(text, state, Detector())
        assert result.sanitized_text.count(token) == 3
        for match in re.finditer(re.escape(token), result.sanitized_text):
            assert result.source_map.to_original(*match.span()) is None
        assert result.source_map.to_original(len(token), len(token) + 6) == (
            len(token),
            len(token) + 6,
        )


@pytest.mark.parametrize(
    "bounds", [(-1, 1), (0, 0), (2, 1), (0, 999), (True, 2), (0, 1.0)]
)
def test_invalid_ranges_fail_without_source_text(bounds):
    from shield.source_map import SourceMapError

    with ephemeral_session() as state:
        mapping = sanitize_text("synthetic", state, Detector()).source_map
        with pytest.raises(SourceMapError, match="Source mapping failed"):
            mapping.to_original(*bounds)


async def test_reviewer_receives_only_masked_batch_and_results_stay_untrusted():
    from shield.detect.contextual import review_texts

    seen = []

    class Reviewer:
        async def review(self, text):
            assert isinstance(text, SecretStr)
            seen.append(text.get_secret_value())
            return SecretStr("unvalidated private reviewer reason")

    texts = ("Alice went first.", "Christopher Example followed.")
    with ephemeral_session() as state:
        results = await review_texts(texts, state, Detector(), Reviewer())
        assert len(results) == 2 and len(state.mappings) == 2
        assert all(
            "Alice" not in text and "Christopher Example" not in text for text in seen
        )
        for result, masked in zip(results, seen, strict=True):
            assert result.stage1.sanitized_text == masked
            assert result.source_map.masked_length == len(masked)
            assert (
                result.raw_output.get_secret_value()
                == "unvalidated private reviewer reason"
            )
            assert "private reviewer" not in repr(result) + str(result.model_dump())
            assert result.stage1.report.protected_count == 1


async def test_batch_preflight_before_any_reviewer_call():
    from shield.detect.contextual import review_texts

    class Reviewer:
        async def review(self, text):
            pytest.fail("Reviewer called before full batch preflight")

    with ephemeral_session() as state:
        with pytest.raises(UnknownSessionToken):
            await review_texts(
                ("Alice", "[PERSON_ABCD]"), state, Detector(), Reviewer()
            )
        assert not state.mappings


async def test_reviewer_failure_is_static_and_stops_batch():
    from shield.detect.contextual import review_texts
    from shield.detect.stage2 import ReviewerUnavailable

    calls = []

    class Reviewer:
        async def review(self, text):
            calls.append(True)
            raise ValueError("private reviewer reason")

    with ephemeral_session() as state:
        with pytest.raises(ReviewerUnavailable) as error:
            await review_texts(("Alice", "ordinary"), state, Detector(), Reviewer())
        assert str(error.value) == "Local reviewer is unavailable." and len(calls) == 1


def test_empty_identity_equal_length_and_adjacent_masks():
    from shield.source_map import build_source_map

    assert build_source_map(0, ()).pieces == ()
    identity = build_source_map(3, ())
    assert identity.to_original(0, 3) == (0, 3)
    masked = build_source_map(5, ((0, 2, 2), (2, 4, 2)))
    assert masked.to_original(0, 2) is None
    assert masked.to_original(1, 4) is None
    assert masked.to_original(4, 5) == (4, 5)


@pytest.mark.parametrize(
    "replacements",
    [
        ((0, 3, 4), (2, 4, 5)),
        ((-1, 1, 2),),
        ((0, 6, 2),),
        ((1, 1, 2),),
        ((0, 1, 0),),
        ((0, True, 2),),
    ],
)
def test_invalid_replacement_maps_are_rejected(replacements):
    from shield.source_map import SourceMapError, build_source_map

    with pytest.raises(SourceMapError):
        build_source_map(5, replacements)


async def test_review_cancellation_never_submits_remaining_messages():
    import asyncio

    from shield.detect.contextual import review_texts

    entered = asyncio.Event()
    calls = []

    class Reviewer:
        async def review(self, text):
            calls.append(True)
            entered.set()
            await asyncio.Event().wait()

    with ephemeral_session() as state:
        task = asyncio.create_task(
            review_texts(
                ("Alice", "Christopher Example"), state, Detector(), Reviewer()
            )
        )
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert calls == [True]
