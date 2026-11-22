"""Mode processing retains worker-owned sessions while async work drains."""

import asyncio
from collections.abc import Callable
from contextlib import contextmanager
from threading import Event

from shield.analysis import AnalysisJob, _CancelledAnalysis
from shield.api import AnalyzeResponse
from shield.config import DetectionConfig
from shield.detect.review_policy import review_with_policy
from shield.detect.stage2 import OllamaReviewer, Reviewer
from shield.metrics import record_stage2
from shield.substitute import sanitize_texts, substitute_spans

ReviewerFactory = Callable[[DetectionConfig], Reviewer]


def default_reviewer(config: DetectionConfig) -> Reviewer:
    return OllamaReviewer(
        config.stage2_model,
        config.stage2_timeout_s,
        max_output_bytes=config.stage2_max_output_bytes,
    )


class _ManagedReviewer:
    def __init__(self, factory, config):
        self._factory, self._config, self._backend = factory, config, None

    async def review(self, text):
        if self._backend is None:
            self._backend = self._factory(self._config)
        return await self._backend.review(text)

    async def aclose(self):
        if self._backend is not None and hasattr(self._backend, "aclose"):
            await self._backend.aclose()


class ReviewerProvider:
    def __init__(self, config: DetectionConfig, factory: ReviewerFactory | None = None):
        self.config = config
        self.factory = factory if factory is not None else default_reviewer
        self.available = False  # Last observation, never an active health probe.
        self._drains = set()

    def retain_drain(self, operation):
        # The app owns this provider. Asyncio keeps only weak task references,
        # so request-local ownership cannot keep a stalled cleanup alive.
        task = asyncio.create_task(operation)
        self._drains.add(task)
        task.add_done_callback(self._drains.discard)

    async def review(self, sources, first, session, detector, *, retain_cleanup=None):
        try:
            result = await review_with_policy(
                sources,
                session,
                detector,
                _ManagedReviewer(self.factory, self.config),
                self.config,
                stage1=first,
                close_reviewer=True,
                retain_cleanup=retain_cleanup,
            )
        except Exception:
            self.available = False
            raise
        self.available = result.outcome.status == "complete"
        return result


class AsyncSessionJob(AnalysisJob):
    """Bridge each async operation to the application loop without losing leases."""

    def __init__(self, provider, service, session_id, cleanup_owner):
        super().__init__(provider, service, session_id)
        self._cleanup_owner = cleanup_owner
        self._loop = asyncio.get_running_loop()
        self._future = None
        self._cleanup = []

    def retain_cleanup(self, task):
        self._cleanup.append(task)

    @contextmanager
    def _session_scope(self):
        scope = super()._session_scope()
        state = scope.__enter__()
        try:
            yield state
        finally:
            # No request work may use mappings after publication. The scope
            # itself keeps the persistent lease until every async close drains.
            state.close()
            if any(not task.done() for task in self._cleanup):
                self._loop.call_soon_threadsafe(
                    self._cleanup_owner.retain_drain, self._release_scope(scope)
                )
            else:
                for task in self._cleanup:
                    if not task.cancelled():
                        task.exception()
                scope.__exit__(None, None, None)

    async def _release_scope(self, scope):
        try:
            await asyncio.gather(*self._cleanup, return_exceptions=True)
        finally:
            scope.__exit__(None, None, None)

    def cancel(self):
        super().cancel()
        with self._lock:
            if self._future is not None:
                self._future.cancel()

    async def _operation(self, factory, started, drained):
        with self._lock:
            if self._cancelled.is_set():
                raise asyncio.CancelledError()
            started.set()
        try:
            return await factory()
        finally:
            drained.set()

    def run_async(self, factory):
        started, drained = Event(), Event()
        with self._lock:
            if self._cancelled.is_set():
                raise _CancelledAnalysis()
            future = asyncio.run_coroutine_threadsafe(
                self._operation(factory, started, drained), self._loop
            )
            self._future = future
        try:
            return future.result()
        finally:
            with self._lock:
                self._future = None
                active = started.is_set()
            if active:
                drained.wait()


class ModeJob(AsyncSessionJob):
    def __init__(self, provider, service, session_id, reviewer_provider):
        super().__init__(provider, service, session_id, reviewer_provider)
        self._reviewer_provider = reviewer_provider

    def detect_texts(self, sources, session, detector):
        # Heavy NLP and all mapping allocations stay in this worker.
        first = sanitize_texts(sources, session, detector)
        if self._reviewer_provider.config.mode == "fast":
            return first, None
        batch = self.run_async(
            lambda: self._reviewer_provider.review(
                sources, first, session, detector, retain_cleanup=self.retain_cleanup
            )
        )
        if self._cancelled.is_set():
            raise _CancelledAnalysis()
        results = []
        for text, original, plan in zip(sources, first, batch.plans, strict=True):
            final = (
                substitute_spans(text, plan.resolved.spans, session)
                if plan.additions
                else original
            )
            results.append(
                final.model_copy(
                    update={
                        "report": plan.resolved.report,
                        "allowlisted_spans": plan.resolved.allowlisted_spans,
                        "below_threshold_count": plan.resolved.below_threshold_count,
                    }
                )
            )
        return tuple(results), batch.outcome


class ModeAnalysisJob(ModeJob):
    def _process(self, text, session, detector):
        results, outcome = self.detect_texts((text,), session, detector)
        (result,) = results
        if outcome is not None:
            record_stage2(outcome)
        response = AnalyzeResponse(
            sanitized_text=result.sanitized_text,
            spans=tuple(item.span for item in result.replacements),
            report=result.report,
            preserved_token_count=result.preserved_token_count,
            below_threshold_count=result.below_threshold_count,
            preview_only=self._session_id is None,
            session_id=self._session_id,
        )
        return response, outcome
