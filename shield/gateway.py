"""Prepare the supported text-only conversation within an active session.

This stage performs no network I/O. The serialized-payload guard and transport
must be installed before prepared conversations may leave the process.
"""

from collections import Counter

from pydantic import Field

from shield.api import ChatCompletionRequest
from shield.contracts import Contract, ProtectionReport
from shield.substitute import CandidateDetector, TokenSession, sanitize_texts


class PreparedChat(Contract):
    request: ChatCompletionRequest = Field(repr=False)
    report: ProtectionReport


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
    messages = [
        message.model_copy(update={"content": result.sanitized_text})
        for message, result in zip(request.messages, results, strict=True)
    ]
    protected = Counter()
    allowlisted = Counter()
    for result in results:
        protected.update(result.report.protected_counts)
        allowlisted.update(result.report.allowlisted_disclosure_counts)
    return PreparedChat(
        request=request.model_copy(
            update={"messages": messages, "stream": False, "stream_options": None}
        ),
        report=ProtectionReport(
            protected_counts=dict(protected),
            allowlisted_disclosure_counts=dict(allowlisted),
        ),
    )
