"""Read-only Stage 1 scan of decoded string values in outgoing JSON bytes."""

import json
from collections import Counter

from pydantic import Field, SecretBytes, computed_field

from shield.contracts import Contract, Count, DetectedSpan, EntityType
from shield.substitute import (
    CandidateDetector,
    TokenSession,
    TokenSubstitutionError,
    UnknownSessionToken,
    _known_ranges,
    _resolve_text,
)


class GuardReport(Contract):
    """Counts only: remaining accepted spans, intentional disclosures and misses."""

    remaining_counts: dict[EntityType, Count]
    allowlisted_disclosure_counts: dict[EntityType, Count]
    below_threshold_count: Count
    non_message_allowlisted_disclosure_counts: dict[EntityType, Count]
    message_allowlisted_spans: dict[int, tuple[DetectedSpan, ...]] = Field(
        default_factory=dict, exclude=True
    )

    @computed_field
    @property
    def remaining_count(self) -> int:
        return sum(self.remaining_counts.values())


def _strings(value, path=()):
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _strings(item, (*path, key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _strings(item, (*path, index))


def scan_payload(
    payload: bytes, session: TokenSession, detector: CandidateDetector
) -> GuardReport:
    """Inspect exact serialized bytes, decoding JSON escapes before detection.

    Scan every string leaf, including model and roles as well as content. Object
    keys in the supported contract are fixed schema names. Canonical tokens must
    belong to this session. No allocations, substitutions or network I/O occur.
    The sender must use these bytes, never serialize a mutable request again.
    """
    try:
        if not isinstance(payload, bytes) or not isinstance(session.key, SecretBytes):
            raise ValueError()
        values = tuple(_strings(json.loads(payload)))
        ranges = [_known_ranges(text, session) for _, text in values]
        remaining, allowed = Counter(), Counter()
        non_message_allowed = Counter()
        message_allowed = {}
        below = 0
        for (path, text), known in zip(values, ranges, strict=True):
            resolved = _resolve_text(text, known, detector)
            remaining.update(resolved.report.protected_counts)
            allowed.update(resolved.report.allowlisted_disclosure_counts)
            if not (
                len(path) == 3
                and path[0] == "messages"
                and isinstance(path[1], int)
                and path[2] == "content"
            ):
                non_message_allowed.update(
                    resolved.report.allowlisted_disclosure_counts
                )
            else:
                message_allowed[path[1]] = resolved.allowlisted_spans
            below += resolved.below_threshold_count
        return GuardReport(
            message_allowlisted_spans=message_allowed,
            remaining_counts=dict(remaining),
            allowlisted_disclosure_counts=dict(allowed),
            below_threshold_count=below,
            non_message_allowlisted_disclosure_counts=dict(non_message_allowed),
        )
    except UnknownSessionToken:
        raise
    except Exception:
        raise TokenSubstitutionError("Outgoing protection scan failed.") from None
