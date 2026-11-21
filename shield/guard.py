"""Read-only Stage 1 scan of decoded string values in outgoing JSON bytes."""

import json
from collections import Counter

from pydantic import SecretBytes, computed_field

from shield.contracts import Contract, Count, EntityType
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

    @computed_field
    @property
    def remaining_count(self) -> int:
        return sum(self.remaining_counts.values())


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


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
        ranges = [_known_ranges(text, session) for text in values]
        remaining, allowed = Counter(), Counter()
        below = 0
        for text, known in zip(values, ranges, strict=True):
            resolved = _resolve_text(text, known, detector)
            remaining.update(resolved.report.protected_counts)
            allowed.update(resolved.report.allowlisted_disclosure_counts)
            below += resolved.below_threshold_count
        return GuardReport(
            remaining_counts=dict(remaining),
            allowlisted_disclosure_counts=dict(allowed),
            below_threshold_count=below,
        )
    except UnknownSessionToken:
        raise
    except Exception:
        raise TokenSubstitutionError("Outgoing protection scan failed.") from None
