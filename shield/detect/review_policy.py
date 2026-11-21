"""Atomic contextual-batch policy. Only explicit fail_open returns a fallback."""

import asyncio

from pydantic import Field, SecretBytes, SecretStr

from shield.config import DetectionConfig
from shield.contracts import Contract, ErrorCode, Stage2Outcome
from shield.detect.contextual import ContextualReview
from shield.detect.resolve import ResolvedDetections
from shield.detect.review_limits import ReviewerOutputLimit, check_output
from shield.detect.review_validation import (
    ReviewerOutputError,
    ValidatedReview,
    validate_review,
)
from shield.errors import ShieldError
from shield.metrics import record_stage2
from shield.persistent import SessionAccessError
from shield.substitute import SubstitutionResult, sanitize_texts


class ReviewBatch(Contract):
    stage1: tuple[SubstitutionResult, ...] = Field(repr=False, exclude=True)
    plans: tuple[ValidatedReview, ...]
    outcome: Stage2Outcome


def _baseline(first):
    return ValidatedReview(
        additions=(),
        rejected_count=0,
        resolved=ResolvedDetections(
            spans=tuple(item.span for item in first.replacements),
            allowlisted_spans=first.allowlisted_spans,
            below_threshold_count=first.below_threshold_count,
            report=first.report,
        ),
    )


def _ensure_open(session):
    try:
        if not isinstance(session.key, SecretBytes):
            raise ShieldError(ErrorCode.INTERNAL_ERROR)
    except SessionAccessError:
        raise
    except Exception:
        raise ShieldError(ErrorCode.INTERNAL_ERROR) from None


async def review_with_policy(
    texts, session, detector, reviewer, config: DetectionConfig
) -> ReviewBatch:
    """Bound the entire contextual batch after Stage 1, including validation.

    Stage 1/storage failures never enter fail_open. A failed contextual batch
    discards every partial addition. Cancellation always propagates.
    """
    sources = tuple(texts)
    first = sanitize_texts(sources, session, detector)
    loop = asyncio.get_running_loop()
    deadline = loop.time() + config.stage2_timeout_s
    plans, used = [], 0
    try:
        async with asyncio.timeout_at(deadline):
            for original, result in zip(sources, first, strict=True):
                if loop.time() >= deadline:
                    raise TimeoutError()
                _ensure_open(session)
                remaining = config.stage2_max_output_bytes - used
                if remaining <= 0:
                    raise ReviewerOutputLimit()
                output = await reviewer.review(SecretStr(result.sanitized_text))
                _ensure_open(session)
                raw = check_output(output, remaining)
                used += len(raw.encode("utf-8"))
                if loop.time() >= deadline:
                    raise TimeoutError()
                plan = validate_review(
                    SecretStr(original),
                    ContextualReview(
                        stage1=result,
                        source_map=result.source_map,
                        raw_output=output,
                    ),
                    detector.policy,
                    max_output_bytes=remaining,
                )
                _ensure_open(session)
                plans.append(plan)
                if loop.time() >= deadline:
                    raise TimeoutError()
    except ShieldError, SessionAccessError:
        raise
    except Exception as error:
        failure = (
            "output_limit"
            if isinstance(error, ReviewerOutputLimit)
            else "invalid_output"
            if isinstance(error, ReviewerOutputError)
            else "timeout"
            if isinstance(error, TimeoutError)
            else "unavailable"
        )
        _ensure_open(session)
        fallback = config.on_stage2_failure == "fail_open"
        outcome = Stage2Outcome(
            status="stage1_fallback" if fallback else "failed", failure=failure
        )
        record_stage2(outcome)
        if not fallback:
            raise ShieldError(ErrorCode.REVIEWER_UNAVAILABLE) from None
        return ReviewBatch(
            stage1=first,
            plans=tuple(_baseline(item) for item in first),
            outcome=outcome,
        )
    _ensure_open(session)
    outcome = Stage2Outcome(status="complete")
    record_stage2(outcome)
    return ReviewBatch(stage1=first, plans=tuple(plans), outcome=outcome)
