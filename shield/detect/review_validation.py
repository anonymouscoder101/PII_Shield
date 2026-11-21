"""Validate untrusted local JSON and merge additions in original coordinates."""

import json
from itertools import pairwise
from typing import Annotated

from pydantic import Field, SecretStr

from shield.contracts import Contract, Count, DetectedSpan, DetectionStage, EntityType
from shield.detect.contextual import ContextualReview
from shield.detect.resolve import ResolvedDetections, SpanPolicy, _merge, _report
from shield.detect.review_limits import (
    DEFAULT_MAX_OUTPUT_BYTES,
    ReviewerOutputLimit,
    check_output,
)
from shield.source_map import SourceMap, SourceMapError


class ReviewerOutputError(ValueError):
    def __init__(self):
        super().__init__("Local reviewer output is invalid.")


class ReviewerSpan(Contract):
    entity_type: EntityType
    text: SecretStr = Field(repr=False, exclude=True)
    start: int
    end: int
    confidence: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
    reason: SecretStr | None = Field(default=None, repr=False, exclude=True)


class ReviewerPayload(Contract):
    spans: list[ReviewerSpan]


class ValidatedReview(Contract):
    additions: tuple[DetectedSpan, ...]
    resolved: ResolvedDetections
    rejected_count: Count


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ReviewerOutputError()
        result[key] = value
    return result


def _constant(value):
    raise ReviewerOutputError()


def merge_additions(
    stage1: tuple[DetectedSpan, ...], additions: tuple[DetectedSpan, ...]
) -> tuple[DetectedSpan, ...]:
    """Keep the accepted baseline authoritative; reviewer spans can only add.

    Never merge across a Stage 1 boundary or change its metadata. Placeholder
    validation normally prevents overlaps; reject them here independently too.
    """
    try:

        def checked(spans, stage):
            values = []
            for span in spans:
                if not isinstance(span, DetectedSpan) or span.stage != stage:
                    raise ReviewerOutputError()
                values.append(
                    DetectedSpan(
                        start=span.start,
                        end=span.end,
                        entity_type=span.entity_type,
                        confidence=span.confidence,
                        stage=span.stage,
                    )
                )
            return tuple(sorted(values, key=lambda item: (item.start, item.end)))

        baseline = checked(stage1, DetectionStage.STAGE_1)
        if any(left.end > right.start for left, right in pairwise(baseline)):
            raise ReviewerOutputError()
        extra = _merge(list(checked(additions, DetectionStage.STAGE_2)))
        index = 0
        for span in extra:
            while index < len(baseline) and baseline[index].end <= span.start:
                index += 1
            if index < len(baseline) and baseline[index].start < span.end:
                raise ReviewerOutputError()
        return tuple(sorted(baseline + extra, key=lambda item: (item.start, item.end)))
    except Exception:
        raise ReviewerOutputError() from None


def validate_review(
    original_text: SecretStr,
    review: ContextualReview,
    policy: SpanPolicy,
    *,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
) -> ValidatedReview:
    """Schema failure aborts review; invalid/ambiguous individual ranges discard.

    No quote search or offset correction is attempted. Stage 1 spans are already
    accepted and never subjected to reviewer threshold/allowlist decisions again.
    This function allocates no mappings and returns no quoted text or reasons.
    """
    try:
        if not isinstance(original_text, SecretStr):
            raise ReviewerOutputError()
        original = original_text.get_secret_value()
        first = review.stage1
        masked = first.sanitized_text
        source = review.source_map
        # Revalidate coordinate metadata and bind it to this immutable snapshot.
        source = SourceMap(source.original_length, source.masked_length, source.pieces)
        if (
            source != first.source_map
            or source.original_length != len(original)
            or source.masked_length != len(masked)
        ):
            raise ReviewerOutputError()
        for piece in source.pieces:
            if (
                not piece.masked
                and original[piece.original_start : piece.original_end]
                != masked[piece.masked_start : piece.masked_end]
            ):
                raise ReviewerOutputError()
        raw = check_output(review.raw_output, max_output_bytes)
        # The JSON parser rejects duplicate keys and nonstandard numeric constants;
        # JSON-mode Pydantic validation preserves strict enum/string semantics.
        json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant)
        payload = ReviewerPayload.model_validate_json(raw)
        mapped, rejected = [], 0
        for candidate in payload.spans:
            start, end = candidate.start, candidate.end
            quoted = candidate.text.get_secret_value()
            try:
                interval = source.to_original(start, end)
            except SourceMapError:
                interval = None
            if (
                interval is None
                or masked[start:end] != quoted
                or original[interval[0] : interval[1]] != quoted
            ):
                rejected += 1
                continue
            mapped.append(
                DetectedSpan(
                    start=interval[0],
                    end=interval[1],
                    entity_type=candidate.entity_type,
                    confidence=candidate.confidence,
                    stage=DetectionStage.STAGE_2,
                )
            )
        contextual = policy.resolve(original, mapped)
        baseline = tuple(item.span for item in first.replacements)
        merged = merge_additions(baseline, contextual.spans)
        allowed = first.allowlisted_spans + contextual.allowlisted_spans
        return ValidatedReview(
            additions=contextual.spans,
            rejected_count=rejected,
            resolved=ResolvedDetections(
                spans=merged,
                allowlisted_spans=allowed,
                below_threshold_count=first.below_threshold_count
                + contextual.below_threshold_count,
                report=_report(merged, allowed),
            ),
        )
    except ReviewerOutputLimit:
        raise
    except Exception:
        raise ReviewerOutputError() from None
