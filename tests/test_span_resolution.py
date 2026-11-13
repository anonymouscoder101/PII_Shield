"""Pure policy tests over synthetic source coordinates, independent of NLP models."""

from itertools import permutations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from shield.config import DetectionConfig
from shield.contracts import DetectedSpan, DetectionStage, EntityType
from shield.detect.resolve import SpanPolicy, SpanResolutionError


def span(start, end, entity=EntityType.PERSON, score=0.8, stage=DetectionStage.STAGE_1):
    return DetectedSpan(
        start=start, end=end, entity_type=entity, confidence=score, stage=stage
    )


def test_transitive_overlap_unions_bounds_and_uses_highest_confidence_type():
    result = SpanPolicy().resolve(
        "abcdefghijkl",
        [
            span(0, 4),
            span(3, 8, EntityType.SECRET, 0.95),
            span(7, 10, EntityType.LOCATION, 0.7),
        ],
    )
    assert result.spans == (span(0, 10, EntityType.SECRET, 0.95),)
    assert result.report.protected_counts == {EntityType.SECRET: 1}


def test_adjacent_spans_stay_separate_and_ordered():
    result = SpanPolicy().resolve("abcdef", [span(3, 6), span(0, 3)])
    assert result.spans == (span(0, 3), span(3, 6))


def test_low_confidence_bridge_and_outer_span_cannot_enlarge_redaction():
    result = SpanPolicy(DetectionConfig(threshold=0.5)).resolve(
        "abcdefghijkl",
        [
            span(1, 3),
            span(7, 9),
            span(0, 12, EntityType.SECRET, 0.49),
            span(2, 8, EntityType.LOCATION, 0.49),
        ],
    )
    assert result.spans == (span(1, 3), span(7, 9))
    assert result.below_threshold_count == 2


def test_allowlisted_bridge_is_filtered_before_merging():
    result = SpanPolicy(DetectionConfig(allowlist=["cdefgh"])).resolve(
        "abcdefghij", [span(0, 3), span(2, 8, EntityType.LOCATION), span(7, 10)]
    )
    assert result.spans == (span(0, 3), span(7, 10))
    assert result.allowlisted_spans == (span(2, 8, EntityType.LOCATION),)
    # Only part remains visible, but this is still an intentional disclosure occurrence.
    assert result.report.allowlisted_disclosure_counts == {EntityType.LOCATION: 1}


@pytest.mark.parametrize("value", ["Alice", "ALICE", "alice"])
def test_allowlist_is_case_sensitive_and_matches_complete_candidate(value):
    result = SpanPolicy(DetectionConfig(allowlist=["Alice"])).resolve(
        value, [span(0, len(value))]
    )
    assert bool(result.allowlisted_spans) == (value == "Alice")
    assert bool(result.spans) == (value != "Alice")
    longer = SpanPolicy(DetectionConfig(allowlist=["Alice"])).resolve(
        "Alice Smith", [span(0, 11)]
    )
    assert len(longer.spans) == 1


def test_unicode_and_repeated_allowlisted_terms_keep_original_coordinates():
    text = "🛡️ José and José"
    start = text.index("José")
    second = text.rindex("José")
    result = SpanPolicy(DetectionConfig(allowlist=["José"])).resolve(
        text, [span(start, start + 4), span(second, second + 4)]
    )
    assert [text[item.start : item.end] for item in result.allowlisted_spans] == [
        "José",
        "José",
    ]
    assert result.report.allowlisted_disclosure_count == 2
    assert not result.spans
    assert "José" not in repr(result)
    combining = "Jose\u0301"
    assert (
        len(
            SpanPolicy(DetectionConfig(allowlist=["José"]))
            .resolve(combining, [span(0, len(combining))])
            .spans
        )
        == 1
    )


def test_allowlisted_candidate_fully_masked_by_other_spans_is_not_disclosure():
    result = SpanPolicy(DetectionConfig(allowlist=["abcdef"])).resolve(
        "abcdef", [span(0, 6, EntityType.LOCATION), span(0, 3), span(3, 6)]
    )
    assert len(result.allowlisted_spans) == 1
    assert result.report.allowlisted_disclosure_count == 0
    assert result.report.protected_count == 2


def test_threshold_is_inclusive_and_overrides_mode_default():
    assert (
        SpanPolicy(DetectionConfig(mode="fast"))
        .resolve("abc", [span(0, 3, score=0.59)])
        .spans
        == ()
    )
    assert (
        len(
            SpanPolicy(DetectionConfig(mode="fast", threshold=0.59))
            .resolve("abc", [span(0, 3, score=0.59)])
            .spans
        )
        == 1
    )
    assert (
        len(
            SpanPolicy(DetectionConfig(threshold=0))
            .resolve("abc", [span(0, 3, score=0)])
            .spans
        )
        == 1
    )
    assert (
        len(
            SpanPolicy(DetectionConfig(threshold=1))
            .resolve("abc", [span(0, 3, score=1)])
            .spans
        )
        == 1
    )


def test_below_threshold_allowlisted_candidate_is_not_reported_as_disclosure():
    result = SpanPolicy(DetectionConfig(allowlist=["abc"])).resolve(
        "abc", [span(0, 3, score=0.1)]
    )
    assert result.allowlisted_spans == ()
    assert result.below_threshold_count == 1
    assert result.report.allowlisted_disclosure_count == 0


def test_nested_identical_and_tied_candidates_have_permutation_invariant_output():
    candidates = [
        span(0, 8, EntityType.PERSON, 0.9),
        span(2, 4, EntityType.SECRET, 0.9),
        span(2, 4, EntityType.API_KEY, 0.9),
        span(0, 8, EntityType.PERSON, 0.9, DetectionStage.STAGE_2),
    ]
    outcomes = [
        SpanPolicy().resolve("abcdefgh", values) for values in permutations(candidates)
    ]
    assert all(result == outcomes[0] for result in outcomes)
    assert outcomes[0].spans == (span(0, 8, EntityType.API_KEY, 0.9),)


@pytest.mark.parametrize(
    "changes",
    [
        {"start": -1},
        {"start": True},
        {"end": 100},
        {"end": 0},
        {"confidence": float("nan")},
        {"confidence": 1.1},
        {"entity_type": "PERSON"},
        {"stage": "stage1"},
    ],
)
def test_forged_or_out_of_bounds_spans_fail_even_below_threshold(changes):
    invalid = span(0, 1, score=0.1).model_copy(update=changes)
    with pytest.raises(SpanResolutionError) as exc:
        SpanPolicy().resolve("Synthetic private value", [invalid])
    assert str(exc.value) == "Span resolution failed."


def test_invalid_candidates_and_iteration_failures_do_not_echo_inputs():
    def failing():
        yield span(0, 1)
        raise RuntimeError("Synthetic private value")

    for values in ([{"start": "Synthetic private value"}], failing()):
        with pytest.raises(SpanResolutionError) as exc:
            SpanPolicy().resolve("Synthetic private value", values)
        assert "private" not in str(exc.value)


def test_policy_snapshots_allowlist_and_handles_empty_source():
    config = DetectionConfig(allowlist=["abc"])
    policy = SpanPolicy(config)
    config.allowlist.clear()
    assert policy.resolve("abc", [span(0, 3)]).report.allowlisted_disclosure_count == 1
    assert policy.resolve("", []).spans == ()


def test_allowlisted_coincident_types_count_as_one_resolved_disclosure():
    result = SpanPolicy(DetectionConfig(allowlist=["abc"])).resolve(
        "abc", [span(0, 3, EntityType.SECRET, 0.8), span(0, 3, EntityType.API_KEY, 0.9)]
    )
    assert len(result.allowlisted_spans) == 2
    assert result.report.allowlisted_disclosure_counts == {EntityType.API_KEY: 1}


def test_duplicate_stages_do_not_double_count_an_allowlisted_occurrence():
    result = SpanPolicy(DetectionConfig(allowlist=["abc"])).resolve(
        "abc",
        [
            span(0, 3, score=0.7),
            span(0, 3, score=0.9, stage=DetectionStage.STAGE_2),
            span(0, 3, score=0.7),
        ],
    )
    assert result.allowlisted_spans == (
        span(0, 3, score=0.9, stage=DetectionStage.STAGE_2),
    )
    assert result.report.allowlisted_disclosure_count == 1


@pytest.mark.parametrize(
    "changes",
    [
        {"threshold": float("nan")},
        {"threshold": True},
        {"threshold": 1.1},
        {"allowlist": "abc"},
        {"allowlist": [" "]},
    ],
)
def test_forged_policy_configuration_is_rejected(changes):
    with pytest.raises(SpanResolutionError):
        SpanPolicy(DetectionConfig().model_copy(update=changes))


@given(
    st.lists(
        st.tuples(
            st.integers(0, 19),
            st.integers(1, 10),
            st.sampled_from(
                [EntityType.PERSON, EntityType.SECRET, EntityType.LOCATION]
            ),
            st.sampled_from([0.2, 0.5, 0.8, 0.9]),
        ),
        max_size=20,
    )
)
def test_resolution_preserves_filtered_coverage_and_is_order_independent(rows):
    candidates = [
        span(start, start + length, entity, score)
        for start, length, entity, score in rows
    ]
    policy = SpanPolicy()
    result = policy.resolve("x" * 30, candidates)
    expected = {
        offset
        for candidate in candidates
        if candidate.confidence >= 0.5
        for offset in range(candidate.start, candidate.end)
    }
    actual = {offset for item in result.spans for offset in range(item.start, item.end)}
    assert actual == expected
    assert all(
        left.end <= right.start
        for left, right in zip(result.spans, result.spans[1:], strict=False)
    )
    assert result == policy.resolve("x" * 30, reversed(candidates))
    assert result.report.protected_count == len(result.spans)
