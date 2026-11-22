"""Worker-owned chat scopes spanning both stages, guard, fetch and restoration."""

from collections import Counter

from shield.analysis import _CancelledAnalysis
from shield.contracts import ProtectionReport
from shield.delivery import completion_response, restore_completion
from shield.gateway import finish_chat
from shield.processing import ModeJob
from shield.upstream import UpstreamClient


class ChatJob(ModeJob):
    def __init__(
        self,
        provider,
        service,
        session_id,
        config,
        credentials,
        transport,
        reviewer_provider,
    ):
        super().__init__(provider, service, session_id, reviewer_provider)
        self._config, self._credentials, self._transport = (
            config,
            credentials,
            transport,
        )

    async def _fetch(self, payload):
        async with UpstreamClient(
            self._config, self._credentials.api_key, transport=self._transport
        ) as client:
            return await client.complete(payload)

    def _process(self, request, session, detector):
        results, outcome = self.detect_texts(
            tuple(message.content for message in request.messages), session, detector
        )
        prepared = finish_chat(request, session, detector, results)
        completion = self.run_async(lambda: self._fetch(prepared.payload))
        if self._cancelled.is_set():
            raise _CancelledAnalysis()
        restored = restore_completion(completion, session)
        disclosures = Counter(prepared.report.allowlisted_disclosure_counts)
        disclosures.update(prepared.guard.non_message_allowlisted_disclosure_counts)
        return completion_response(
            restored.completion,
            report=ProtectionReport(
                protected_counts=prepared.report.protected_counts,
                allowlisted_disclosure_counts=dict(disclosures),
                unknown_token_count=restored.unknown_token_count,
            ),
            session_id=self._session_id,
            stream=request.stream,
            include_usage=bool(
                request.stream_options and request.stream_options.include_usage
            ),
            stage2=outcome,
        )
