"""Replace original-coordinate spans while preserving exact active-session tokens."""

import re
from bisect import bisect_right
from collections import Counter
from collections.abc import Iterable
from typing import Protocol

from pydantic import Field, SecretBytes, SecretStr

from shield.contracts import Contract, Count, DetectedSpan, EntityType, ProtectionReport
from shield.detect.resolve import SpanPolicy
from shield.pseudonym import TOKEN_LABELS, TokenAllocation, validate_token_identity
from shield.source_map import SourceMap, build_source_map

_TOKEN = re.compile(
    r"\[(?:"
    + "|".join(re.escape(label) for label in TOKEN_LABELS.values())
    + r")_[A-Z2-7]{4,32}\]"
)


class TokenSession(Protocol):
    @property
    def key(self) -> SecretBytes: ...
    def has_token(self, token: str) -> bool: ...
    def allocate(
        self, entity_type: EntityType, value: SecretStr
    ) -> TokenAllocation: ...


class CandidateDetector(Protocol):
    policy: SpanPolicy

    def detect(self, text: str) -> list[DetectedSpan]: ...


class TokenSubstitutionError(ValueError):
    """Static error without source, token, session ID, or allocation exception text."""


class UnknownSessionToken(TokenSubstitutionError):
    def __init__(self):
        super().__init__("Input contains an unknown session token.")


class AppliedReplacement(Contract):
    span: DetectedSpan
    token: str
    reused: bool
    collision_count: Count


class SubstitutionResult(Contract):
    sanitized_text: str = Field(repr=False)
    replacements: tuple[AppliedReplacement, ...]
    preserved_token_count: Count
    below_threshold_count: Count = 0
    report: ProtectionReport
    source_map: SourceMap = Field(exclude=True)
    allowlisted_spans: tuple[DetectedSpan, ...] = Field(default=(), exclude=True)


def _known_ranges(text: str, session: TokenSession) -> list[tuple[int, int]]:
    if not isinstance(text, str):
        raise TokenSubstitutionError("Token substitution failed.")
    known = {}
    ranges = []
    for match in _TOKEN.finditer(text):
        token = match.group()
        if token not in known:
            known[token] = session.has_token(token)
        if not known[token]:
            raise UnknownSessionToken()
        ranges.append(match.span())
    return ranges


def _checked(text: str, spans: Iterable[DetectedSpan]) -> list[DetectedSpan]:
    result = []
    for span in spans:
        if not isinstance(span, DetectedSpan):
            raise TokenSubstitutionError("Token substitution failed.")
        result.append(
            DetectedSpan(
                start=span.start,
                end=span.end,
                entity_type=span.entity_type,
                confidence=span.confidence,
                stage=span.stage,
            ).validate_for_text(text)
        )
    return sorted(result, key=lambda span: (span.start, span.end))


def _relation(
    span: DetectedSpan, ranges: list[tuple[int, int]], starts: list[int]
) -> str:
    index = bisect_right(starts, span.start) - 1
    if index >= 0 and span.start < ranges[index][1]:
        return "inside" if span.end <= ranges[index][1] else "crossing"
    next_index = index + 1
    return (
        "crossing"
        if next_index < len(ranges) and ranges[next_index][0] < span.end
        else "outside"
    )


def _render(text: str, replacements) -> str:
    # Process source intervals from right to left without repeated whole-string
    # copies. Every slice refers to the original Python-string coordinates.
    chunks = []
    cursor = len(text)
    for start, end, value in reversed(replacements):
        chunks.extend((text[end:cursor], value))
        cursor = start
    chunks.append(text[:cursor])
    return "".join(reversed(chunks))


def _apply(
    text, spans, ranges, session, *, report=None, below=0, allowed=()
) -> SubstitutionResult:
    starts = [start for start, _ in ranges]
    selected = []
    previous_end = 0
    for span in spans:
        relation = _relation(span, ranges, starts)
        if relation == "inside":
            continue
        if relation == "crossing" or span.start < previous_end:
            raise TokenSubstitutionError("Token substitution failed.")
        previous_end = span.end
        selected.append(span)
    replacements = []
    # Allocate in SOURCE order so repeated normalized values keep the first
    # spelling, even though rendering below runs in the opposite direction.
    for span in selected:
        allocated = session.allocate(
            span.entity_type, SecretStr(text[span.start : span.end])
        )
        if allocated.entity_type != span.entity_type:
            raise TokenSubstitutionError("Token substitution failed.")
        validate_token_identity(
            allocated.entity_type, allocated.entity_digest, allocated.token
        )
        if not session.has_token(allocated.token):
            raise TokenSubstitutionError("Token substitution failed.")
        replacements.append(
            AppliedReplacement(
                span=span,
                token=allocated.token,
                reused=allocated.reused,
                collision_count=allocated.collision_count,
            )
        )
    output = _render(
        text, [(item.span.start, item.span.end, item.token) for item in replacements]
    )
    return SubstitutionResult(
        sanitized_text=output,
        source_map=build_source_map(
            len(text),
            [(item.span.start, item.span.end, len(item.token)) for item in replacements]
            + [(start, end, end - start) for start, end in ranges],
        ),
        replacements=tuple(replacements),
        preserved_token_count=len(ranges),
        below_threshold_count=below,
        allowlisted_spans=allowed,
        report=report
        if report is not None
        else ProtectionReport(
            protected_counts=dict(
                Counter(item.span.entity_type for item in replacements)
            )
        ),
    )


def substitute_spans(
    text: str, spans: Iterable[DetectedSpan], session: TokenSession
) -> SubstitutionResult:
    """Apply validated, disjoint resolved spans. Unknown input tokens fail first."""
    try:
        if not isinstance(session.key, SecretBytes):
            raise TokenSubstitutionError("Token substitution failed.")
        ranges = _known_ranges(text, session)
        return _apply(text, _checked(text, spans), ranges, session)
    except UnknownSessionToken:
        raise
    except Exception:
        raise TokenSubstitutionError("Token substitution failed.") from None


def _resolve_text(text, ranges, detector):
    masked = _render(text, [(start, end, " " * (end - start)) for start, end in ranges])
    candidates = _checked(text, detector.detect(masked))
    if ranges:
        # Blanking a placeholder can split a credential or change NER
        # boundaries. Retain original-text evidence so an accepted
        # crossing span cannot disappear and expose an outside suffix.
        candidates.extend(_checked(text, detector.detect(text)))
    starts = [start for start, _ in ranges]
    candidates = [
        span for span in candidates if _relation(span, ranges, starts) != "inside"
    ]
    resolved = detector.policy.resolve(text, candidates)
    return resolved


def sanitize_texts(
    texts: Iterable[str], session: TokenSession, detector: CandidateDetector
) -> tuple[SubstitutionResult, ...]:
    """Preflight all message texts before allocation; then detect/resolve/substitute.

    Exact known placeholders are masked with spaces for NLP, retaining source
    offsets. Wholly-contained detections are ignored; accepted crossing spans
    fail rather than erase the placeholder or leak an outside part of the span.
    """
    try:
        if not isinstance(session.key, SecretBytes):
            raise TokenSubstitutionError("Token substitution failed.")
        sources = tuple(texts)
        ranges_by_text = [_known_ranges(text, session) for text in sources]
        results = []
        for text, ranges in zip(sources, ranges_by_text, strict=True):
            resolved = _resolve_text(text, ranges, detector)
            results.append(
                _apply(
                    text,
                    resolved.spans,
                    ranges,
                    session,
                    report=resolved.report,
                    allowed=resolved.allowlisted_spans,
                    below=resolved.below_threshold_count,
                )
            )
        return tuple(results)
    except UnknownSessionToken:
        raise
    except Exception:
        raise TokenSubstitutionError("Token substitution failed.") from None


def sanitize_text(
    text: str, session: TokenSession, detector: CandidateDetector
) -> SubstitutionResult:
    return sanitize_texts((text,), session, detector)[0]
