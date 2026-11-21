"""Local analysis jobs with worker-owned session scopes and cancellation cleanup."""

import asyncio
from collections.abc import Callable
from threading import Event, Lock

from starlette.concurrency import run_in_threadpool
from starlette.responses import Response
from starlette.types import Receive

from shield.api import AnalyzeResponse, ChatCompletionRequest
from shield.config import DetectionConfig
from shield.contracts import ErrorCode
from shield.errors import ShieldError
from shield.persistent import PersistentSessions, SessionAccessError
from shield.session import ephemeral_session
from shield.substitute import (
    CandidateDetector,
    TokenSubstitutionError,
    UnknownSessionToken,
    sanitize_text,
)

DetectorFactory = Callable[[DetectionConfig], CandidateDetector]


def _load_detector(config: DetectionConfig) -> CandidateDetector:
    # Import/model loading happens only in the analysis worker, never at app
    # construction or configuration loading. No model is downloaded at runtime.
    from shield.detect.stage1 import Stage1Detector

    return Stage1Detector.load(config)


class DetectorProvider:
    def __init__(self, config: DetectionConfig, factory: DetectorFactory | None = None):
        self._config = config
        self._factory = factory if factory is not None else _load_detector
        self._lock = Lock()
        self._detector: CandidateDetector | None = None

    def get(self) -> CandidateDetector:
        with self._lock:
            if self._detector is None:
                try:
                    self._detector = self._factory(self._config)
                except Exception:
                    raise ShieldError(ErrorCode.DETECTION_FAILED) from None
            return self._detector


class _CancelledAnalysis(Exception):
    pass


class _ActiveSession:
    """Prevent new mapping operations once cancellation has been observed."""

    def __init__(self, state, cancelled: Event):
        self._state = state
        self._cancelled = cancelled

    def _check(self):
        if self._cancelled.is_set():
            raise _CancelledAnalysis()

    @property
    def key(self):
        self._check()
        return self._state.key

    def has_token(self, token):
        self._check()
        return self._state.has_token(token)

    @property
    def session_id(self):
        self._check()
        return self._state.session_id

    def read_mapping(self, token):
        self._check()
        return self._state.read_mapping(token)

    def allocate(self, entity_type, value):
        self._check()
        return self._state.allocate(entity_type, value)


class AnalysisJob:
    """One worker owns its context until completion, even after HTTP cancellation.

    Cancellation releases the published state's owned references immediately.
    A persistent lease remains held by the worker until its in-flight operation
    finishes, avoiding deletion races while a cancelled thread is still running.
    """

    def __init__(
        self,
        provider: DetectorProvider,
        service: PersistentSessions | None,
        session_id: str | None,
    ):
        self._provider = provider
        self._service = service
        self._session_id = session_id
        self._cancelled = Event()
        self._lock = Lock()
        self._state = None

    def cancel(self):
        self._cancelled.set()
        with self._lock:
            state = self._state
            self._state = None
        if state is not None:
            state.close()

    def run(
        self, text: str | ChatCompletionRequest
    ) -> AnalyzeResponse | Response | None:
        if self._cancelled.is_set():
            return None
        scope = (
            ephemeral_session()
            if self._session_id is None
            else self._service.use(self._session_id)
        )
        try:
            with scope as state:
                with self._lock:
                    if self._cancelled.is_set():
                        return None
                    self._state = state
                detector = self._provider.get()
                if self._cancelled.is_set():
                    return None
                response = self._process(
                    text, _ActiveSession(state, self._cancelled), detector
                )
                if self._cancelled.is_set():
                    return None
            # Scope cleanup happens BEFORE the response leaves the worker.
            return response
        except Exception as exc:
            if self._cancelled.is_set():
                return None
            if isinstance(exc, (ShieldError, SessionAccessError)):
                raise
            if isinstance(exc, UnknownSessionToken):
                raise ShieldError(ErrorCode.INVALID_REQUEST) from None
            if isinstance(exc, TokenSubstitutionError):
                raise ShieldError(ErrorCode.DETECTION_FAILED) from None
            raise ShieldError(ErrorCode.INTERNAL_ERROR) from None
        finally:
            with self._lock:
                self._state = None

    def _process(self, text, session, detector):
        result = sanitize_text(text, session, detector)
        return AnalyzeResponse(
            sanitized_text=result.sanitized_text,
            spans=tuple(item.span for item in result.replacements),
            report=result.report,
            preserved_token_count=result.preserved_token_count,
            below_threshold_count=result.below_threshold_count,
            preview_only=self._session_id is None,
            session_id=self._session_id,
        )


async def run_analysis_job(
    job: AnalysisJob, text: str | ChatCompletionRequest, receive: Receive
) -> AnalyzeResponse | Response | None:
    """Stop work publication promptly on disconnect, cancellation or deadline.

    Cancelling the await cannot interrupt a running thread. Job cancellation
    closes its published state and the worker retains its context until drained.
    """

    async def disconnected():
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            # Body parsing has completed. Cooperate if an ASGI transport provides
            # another immediately-ready request message rather than disconnect.
            await asyncio.sleep(0)

    worker = asyncio.create_task(run_in_threadpool(job.run, text))
    watcher = asyncio.create_task(disconnected())
    try:
        done, _ = await asyncio.wait(
            (worker, watcher), return_when=asyncio.FIRST_COMPLETED
        )
        if watcher in done:
            raise ShieldError(ErrorCode.REQUEST_TIMEOUT)
        return await worker
    finally:
        # Signal before any await: an abandoned worker must not start another
        # allocation while cleanup tasks are being reaped.
        job.cancel()
        for task in (worker, watcher):
            if not task.done():
                task.cancel()
        await asyncio.gather(worker, watcher, return_exceptions=True)
