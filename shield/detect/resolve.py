"""Shared, source-free confidence/allowlist decisions and overlap resolution."""

import math
from bisect import bisect_right
from collections import Counter
from collections.abc import Iterable

from shield.config import DetectionConfig
from shield.contracts import (
    OPAQUE_ENTITY_TYPES,
    Contract,
    Count,
    DetectedSpan,
    ProtectionReport,
)


class SpanResolutionError(ValueError):
    """Static policy/input failure; never include source text or candidate values."""


class ResolvedDetections(Contract):
    """Disjoint redactions, allowlist decisions, and PII-free occurrence counts.

    Allowlisted candidates can be masked by overlapping accepted redactions.
    The report counts overlap groups with at least one character left visible.
    """

    spans: tuple[DetectedSpan, ...]
    allowlisted_spans: tuple[DetectedSpan, ...]
    below_threshold_count: Count
    report: ProtectionReport


def _winner_key(span: DetectedSpan) -> tuple:
    return (
        # A name-like credential must never inherit lossy name normalization.
        # Threshold/allowlist filtering has already accepted this evidence.
        span.entity_type not in OPAQUE_ENTITY_TYPES,
        -span.confidence,
        span.entity_type.value,
        span.start,
        span.end,
        span.stage.value,
    )


def _position_key(span: DetectedSpan) -> tuple:
    return (
        span.start,
        span.end,
        span.entity_type.value,
        -span.confidence,
        span.stage.value,
    )


def _merge(spans: list[DetectedSpan]) -> tuple[DetectedSpan, ...]:
    if not spans:
        return ()
    ordered = sorted(spans, key=_position_key)
    result = []
    start, end, winner = ordered[0].start, ordered[0].end, ordered[0]

    def resolved() -> DetectedSpan:
        return DetectedSpan(
            start=start,
            end=end,
            entity_type=winner.entity_type,
            confidence=winner.confidence,
            stage=winner.stage,
        )

    for candidate in ordered[1:]:
        if candidate.start < end:
            end = max(end, candidate.end)
            if _winner_key(candidate) < _winner_key(winner):
                winner = candidate
        else:
            result.append(resolved())
            start, end, winner = candidate.start, candidate.end, candidate
    result.append(resolved())
    return tuple(result)


def _report(
    spans: tuple[DetectedSpan, ...], allowed: tuple[DetectedSpan, ...]
) -> ProtectionReport:
    # Coalesce adjacent intervals ONLY for disclosure coverage. Redaction spans
    # remain distinct; two adjacent redactions can fully hide an allowed span.
    runs: list[tuple[int, int]] = []
    for span in spans:
        if runs and span.start == runs[-1][1]:
            runs[-1] = (runs[-1][0], span.end)
        else:
            runs.append((span.start, span.end))
    starts = [start for start, _ in runs]
    visible = []
    for candidate in allowed:
        index = bisect_right(starts, candidate.start) - 1
        fully_masked = index >= 0 and runs[index][1] >= candidate.end
        if not fully_masked:
            visible.append(candidate)
    return ProtectionReport(
        protected_counts=dict(Counter(span.entity_type for span in spans)),
        allowlisted_disclosure_counts=dict(
            Counter(span.entity_type for span in _merge(visible))
        ),
    )


class SpanPolicy:
    """Snapshot policy once for reuse by detection and the pre-send guard.

    The allowlist compares exact whole candidate values, with no normalization,
    case folding, whitespace trimming, substring search or regex interpretation.
    No input source text or extracted values are retained after resolution.
    """

    def __init__(self, config: DetectionConfig | None = None):
        settings = config if config is not None else DetectionConfig()
        try:
            threshold = settings.effective_threshold
            if (
                isinstance(threshold, bool)
                or not isinstance(threshold, (int, float))
                or not math.isfinite(threshold)
                or not 0 <= threshold <= 1
            ):
                raise ValueError("invalid threshold")
            if not isinstance(settings.allowlist, list) or any(
                not isinstance(value, str) or not value.strip()
                for value in settings.allowlist
            ):
                raise ValueError("invalid allowlist")
            self._threshold = threshold
            self._allowlist = frozenset(settings.allowlist)
        except Exception:
            raise SpanResolutionError("Span resolution failed.") from None

    @property
    def threshold(self) -> float:
        return self._threshold

    def resolve(
        self, text: str, candidates: Iterable[DetectedSpan]
    ) -> ResolvedDetections:
        try:
            if not isinstance(text, str):
                raise ValueError("string source required")
            unique = {}
            for candidate in candidates:
                if not isinstance(candidate, DetectedSpan):
                    raise ValueError("typed candidate required")
                # Reconstruct explicitly: model_copy/model_construct can bypass
                # validation. model_dump on forged data can warn with raw inputs.
                checked = DetectedSpan(
                    start=candidate.start,
                    end=candidate.end,
                    entity_type=candidate.entity_type,
                    confidence=candidate.confidence,
                    stage=candidate.stage,
                ).validate_for_text(text)
                identity = (checked.start, checked.end, checked.entity_type)
                previous = unique.get(identity)
                if previous is None or _winner_key(checked) < _winner_key(previous):
                    unique[identity] = checked
            accepted, allowed = [], []
            below = 0
            for candidate in sorted(unique.values(), key=_position_key):
                if candidate.confidence < self._threshold:
                    below += 1
                elif text[candidate.start : candidate.end] in self._allowlist:
                    allowed.append(candidate)
                else:
                    accepted.append(candidate)
            merged = _merge(accepted)
            allowed = tuple(allowed)
            return ResolvedDetections(
                spans=merged,
                allowlisted_spans=allowed,
                below_threshold_count=below,
                report=_report(merged, allowed),
            )
        except Exception:
            raise SpanResolutionError("Span resolution failed.") from None
