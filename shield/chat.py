"""Worker-owned session scopes spanning preparation, async fetch and restoration."""

import asyncio
from collections import Counter
from threading import Event

from shield.analysis import AnalysisJob, _CancelledAnalysis
from shield.contracts import ProtectionReport
from shield.delivery import completion_response, restore_completion
from shield.gateway import prepare_chat
from shield.upstream import UpstreamClient


class ChatJob(AnalysisJob):
    def __init__(self, provider, service, session_id, config, credentials, transport):
        super().__init__(provider, service, session_id)
        self._loop = asyncio.get_running_loop()
        self._config = config
        self._credentials = credentials
        self._transport = transport
        self._send_future = None
        self._fetch_started = Event()
        self._fetch_drained = Event()

    def cancel(self):
        super().cancel()
        with self._lock:
            if self._send_future is not None:
                self._send_future.cancel()

    async def _fetch(self, payload):
        with self._lock:
            if self._cancelled.is_set():
                raise asyncio.CancelledError()
            self._fetch_started.set()
        try:
            async with UpstreamClient(
                self._config, self._credentials.api_key, transport=self._transport
            ) as client:
                return await client.complete(payload)
        finally:
            self._fetch_drained.set()

    def _process(self, request, session, detector):
        prepared = prepare_chat(request, session, detector)
        # Schedule only after successful guard/registration. Serialize scheduling
        # against cancellation so an abandoned worker cannot start a new fetch.
        with self._lock:
            if self._cancelled.is_set():
                raise _CancelledAnalysis()
            future = asyncio.run_coroutine_threadsafe(
                self._fetch(prepared.payload), self._loop
            )
            self._send_future = future
        try:
            completion = future.result()
        finally:
            with self._lock:
                self._send_future = None
                started = self._fetch_started.is_set()
            # A cancelled concurrent Future finishes before the actual asyncio
            # task. Retain the worker-owned lease until HTTP cleanup drains.
            # If it never started, the cancellation check prevents later sends.
            if started:
                self._fetch_drained.wait()
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
        )
