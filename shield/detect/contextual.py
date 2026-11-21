"""Stage 1 masked handoff; review output is not yet eligible for redaction."""

from collections.abc import Iterable

from pydantic import Field, SecretBytes, SecretStr

from shield.contracts import Contract
from shield.detect.stage2 import Reviewer, ReviewerUnavailable
from shield.source_map import SourceMap
from shield.substitute import (
    CandidateDetector,
    SubstitutionResult,
    TokenSession,
    sanitize_texts,
)


class ContextualReview(Contract):
    stage1: SubstitutionResult = Field(repr=False, exclude=True)
    source_map: SourceMap = Field(exclude=True)
    raw_output: SecretStr = Field(repr=False, exclude=True)


async def review_texts(
    texts: Iterable[str],
    session: TokenSession,
    detector: CandidateDetector,
    reviewer: Reviewer,
) -> tuple[ContextualReview, ...]:
    """Preflight/sanitize the full batch, then send only Stage 1 masked strings.

    The caller owns the session, loaded detector and reviewer through this call.
    Raw output stays secret/untrusted; no reviewer additions or policy decisions
    are made here. Application mode routing follows after validation exists.
    """
    results = sanitize_texts(texts, session, detector)
    reviewed = []
    for result in results:
        try:
            if not isinstance(session.key, SecretBytes):
                raise ReviewerUnavailable()
            output = await reviewer.review(SecretStr(result.sanitized_text))
            if not isinstance(output, SecretStr):
                raise ReviewerUnavailable()
        except Exception:
            raise ReviewerUnavailable() from None
        reviewed.append(
            ContextualReview(
                stage1=result, source_map=result.source_map, raw_output=output
            )
        )
    return tuple(reviewed)


async def review_and_resolve_texts(
    texts: Iterable[str],
    session: TokenSession,
    detector: CandidateDetector,
    reviewer: Reviewer,
):
    """Return validated merged plans; application routing/substitution follow later."""
    from shield.detect.review_validation import validate_review

    sources = tuple(texts)
    reviews = await review_texts(sources, session, detector, reviewer)
    return tuple(
        validate_review(SecretStr(original), review, detector.policy)
        for original, review in zip(sources, reviews, strict=True)
    )
