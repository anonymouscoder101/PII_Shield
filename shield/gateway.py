"""Prepare the supported text-only conversation within an active session.

This stage performs no network I/O. It registers mappings and scans the exact
serialized payload and blocks remaining accepted PII before chat transport.
"""

from collections import Counter

from pydantic import Field

from shield.api import ChatCompletionRequest
from shield.contracts import Contract, DetectedSpan, ErrorCode, ProtectionReport
from shield.detect.resolve import _report
from shield.errors import ShieldError
from shield.guard import GuardReport, scan_payload
from shield.substitute import CandidateDetector, TokenSession, sanitize_texts


class PreparedChat(Contract):
    request: ChatCompletionRequest = Field(repr=False)
    report: ProtectionReport
    payload: bytes = Field(repr=False, exclude=True)
    guard: GuardReport


def _source_span(span, replacements):
    def position(value, end=False):
        offset = 0
        for replacement in replacements:
            source = replacement.span
            start = source.start + offset
            stop = start + len(replacement.token)
            if value <= start:
                return value - offset
            if value < stop:
                return source.end if end else source.start
            offset += len(replacement.token) - (source.end - source.start)
        return value - offset

    return DetectedSpan(
        start=position(span.start),
        end=position(span.end, True),
        entity_type=span.entity_type,
        confidence=span.confidence,
        stage=span.stage,
    )


def prepare_chat(
    request: ChatCompletionRequest, session: TokenSession, detector: CandidateDetector
) -> PreparedChat:
    """Sanitize every role, sharing token identity across the whole conversation.

    A returned assistant message is user-controlled history on the next request:
    it receives the same detection and substitution as all other roles. Batch
    preflight rejects foreign placeholders before allocating any new mapping.
    The caller owns the session through eventual sending and restoration.
    """
    results = sanitize_texts((m.content for m in request.messages), session, detector)
    return finish_chat(request, session, detector, results)


def finish_chat(request, session, detector, results) -> PreparedChat:
    """Serialize final substitutions and guard exact bytes after all stages."""
    messages = [
        message.model_copy(update={"content": result.sanitized_text})
        for message, result in zip(request.messages, results, strict=True)
    ]
    protected = Counter()
    for result in results:
        protected.update(result.report.protected_counts)
    outgoing = request.model_copy(
        update={"messages": messages, "stream": False, "stream_options": None}
    )
    payload = outgoing.model_dump_json(exclude_none=True).encode("utf-8")
    guard = scan_payload(payload, session, detector)
    if guard.remaining_count:
        raise ShieldError(ErrorCode.PROTECTION_BLOCKED)
    # Reconcile both passes in source coordinates. The shared overlap/visibility
    # policy retains partial disclosures and coalesces duplicate occurrences.
    allowlisted = Counter()
    for index, result in enumerate(results):
        guard_spans = tuple(
            _source_span(span, result.replacements)
            for span in guard.message_allowlisted_spans.get(index, ())
        )
        reconciled = _report(
            tuple(item.span for item in result.replacements),
            result.allowlisted_spans + guard_spans,
        )
        allowlisted.update(reconciled.allowlisted_disclosure_counts)
    return PreparedChat(
        request=outgoing,
        payload=payload,
        guard=guard,
        report=ProtectionReport(
            protected_counts=dict(protected),
            allowlisted_disclosure_counts=dict(allowlisted),
        ),
    )
