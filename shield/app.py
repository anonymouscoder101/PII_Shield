"""Protected text-only chat, local analysis and session routes."""

from contextlib import asynccontextmanager

import httpx
from fastapi import Depends, FastAPI, Request, Response
from starlette.concurrency import run_in_threadpool

from shield import __version__
from shield.analysis import (
    DetectorFactory,
    DetectorProvider,
    run_analysis_job,
)
from shield.api import (
    AnalyzeRequest,
    AnalyzeResponse,
    ChatCompletionRequest,
    ChatCompletionResponse,
    HealthResponse,
    SessionCreateRequest,
    SessionResponse,
)
from shield.chat import ChatJob
from shield.config import ShieldConfig
from shield.contracts import APIError, ErrorCode
from shield.credentials import RuntimeCredentials
from shield.errors import (
    ShieldError,
    error_response,
    install_error_handlers,
    require_json,
)
from shield.limits import RequestLimitsMiddleware
from shield.metrics import MetricsMiddleware, record_protection
from shield.persistent import SessionAccessError, VaultStartupError, VaultStartupHandoff
from shield.processing import ModeAnalysisJob, ReviewerFactory, ReviewerProvider
from shield.session_access import require_session_access, require_unlocked_vault


def create_app(
    config: ShieldConfig | None = None,
    credentials: RuntimeCredentials | None = None,
    *,
    detector_factory: DetectorFactory | None = None,
    upstream_transport: httpx.AsyncBaseTransport | None = None,
    reviewer_factory: ReviewerFactory | None = None,
) -> FastAPI:
    """Create routes without I/O; opt-in vault authentication runs during lifespan."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        service = None
        passphrase = None
        handoff = VaultStartupHandoff()
        try:
            if app.state.config.sessions.persistent_enabled:
                passphrase = app.state.credentials.vault_passphrase
                if passphrase is None:
                    raise VaultStartupError("Vault startup failed.")
                await run_in_threadpool(
                    handoff.open, app.state.config.vault, passphrase
                )
                service = handoff.take()
                app.state.vault = service
            passphrase = None
            app.state.credentials = RuntimeCredentials(
                api_key=app.state.credentials.api_key
            )
            yield
        finally:
            handoff.cancel()
            passphrase = None
            if service is not None:
                service.close()
            app.state.vault = None
            app.state.credentials = RuntimeCredentials(
                api_key=app.state.credentials.api_key
            )

    app = FastAPI(
        title="PII Shield",
        description=(
            "Local PII analysis and optional reusable sessions. "
            "Protected chat with JSON or buffered SSE delivery."
        ),
        version=__version__,
        lifespan=lifespan,
    )
    app.state.config = config if config is not None else ShieldConfig()
    app.state.credentials = (
        credentials if credentials is not None else RuntimeCredentials()
    )
    app.state.detector_provider = DetectorProvider(
        app.state.config.detection, detector_factory
    )
    app.state.reviewer_provider = ReviewerProvider(
        app.state.config.detection, reviewer_factory
    )
    app.state.vault = None  # Authenticated service is installed only during lifespan.

    @app.exception_handler(SessionAccessError)
    async def session_error(request: Request, exc: SessionAccessError):
        return error_response(exc.code)

    app.add_middleware(RequestLimitsMiddleware, config=app.state.config.server)
    install_error_handlers(app)
    app.add_middleware(MetricsMiddleware)

    @app.get(
        "/shield/health",
        response_model=HealthResponse,
        description=(
            "Local liveness and capability snapshot. Does not load models, probe "
            "upstream services, or unlock the optional vault."
        ),
    )
    async def health(response: Response) -> HealthResponse:
        enabled = app.state.config.sessions.persistent_enabled
        vault_state = "disabled"
        if enabled:
            vault = app.state.vault
            vault_state = (
                "unlocked" if vault is not None and vault.is_unlocked else "locked"
            )
        response.headers["Cache-Control"] = "no-store"
        return HealthResponse(
            persistent_sessions_enabled=enabled,
            vault_state=vault_state,
            stage1_status=app.state.detector_provider.load_status,
            # Configuring a model name is not evidence of a usable reviewer.
            # Cached observation only: health never calls the local model.
            stage2_available=app.state.reviewer_provider.available,
        )

    @app.post(
        "/v1/chat/completions",
        response_model=ChatCompletionResponse,
        dependencies=[Depends(require_json)],
        responses={
            200: {
                "description": "Protected JSON or buffered SSE response.",
                "content": {
                    "text/event-stream": {
                        "schema": {"type": "string"},
                        "description": "JSON completion chunks followed by [DONE].",
                    }
                },
            },
            "4XX": {
                "model": APIError,
                "description": "Invalid or unsupported request.",
            },
            400: {
                "model": APIError,
                "description": "Malformed JSON or invalid payload.",
            },
            415: {"model": APIError, "description": "Unsupported content type."},
            408: {"model": APIError, "description": "Request time budget exceeded."},
            413: {"model": APIError, "description": "Request body too large."},
            422: {
                "model": APIError,
                "description": "Remaining PII was blocked by the final guard.",
            },
            423: {"model": APIError, "description": "Persistent vault is locked."},
            500: {"model": APIError, "description": "Internal error."},
            502: {"model": APIError, "description": "Upstream request failed."},
            504: {"model": APIError, "description": "Upstream request timed out."},
            503: {
                "model": APIError,
                "description": "Local PII detection is unavailable.",
            },
        },
        description=(
            "Sanitizes and guards all supported roles, fetches a complete upstream "
            "response, then restores assistant text. stream=true uses buffered SSE; "
            "upstream work and restoration finish before any success headers."
        ),
    )
    async def chat_completions(
        body: ChatCompletionRequest, request: Request
    ) -> Response:
        require_session_access(request)
        session_id = request.headers.get("x-shield-session")
        service = request.app.state.vault if session_id is not None else None
        job = ChatJob(
            request.app.state.detector_provider,
            service,
            session_id,
            request.app.state.config.upstream,
            request.app.state.credentials,
            upstream_transport,
            request.app.state.reviewer_provider,
        )
        try:
            result = await run_analysis_job(job, body, request.receive)
            if result is None:
                raise ShieldError(ErrorCode.REQUEST_TIMEOUT)
            return result
        finally:
            job.cancel()

    @app.post(
        "/shield/analyze",
        response_model=AnalyzeResponse,
        response_model_exclude_none=True,
        dependencies=[Depends(require_json)],
        responses={"4XX": {"model": APIError}, 503: {"model": APIError}},
        description=(
            "Local analysis only. Default tokens are ephemeral previews; "
            "an explicit session retains mappings."
        ),
    )
    async def analyze_text(
        body: AnalyzeRequest, request: Request, response: Response
    ) -> AnalyzeResponse:
        require_session_access(request)
        session_id = request.headers.get("x-shield-session")
        service = request.app.state.vault if session_id is not None else None
        job = ModeAnalysisJob(
            request.app.state.detector_provider,
            service,
            session_id,
            request.app.state.reviewer_provider,
        )
        try:
            result = await run_analysis_job(job, body.text, request.receive)
            if result is None:
                raise ShieldError(ErrorCode.REQUEST_TIMEOUT)
        finally:
            job.cancel()
        result, outcome = result
        if outcome is not None:
            response.headers["X-Shield-Stage2"] = outcome.status
            if outcome.failure is not None:
                response.headers["X-Shield-Stage2-Failure"] = outcome.failure
        record_protection(result.report)
        response.headers["Cache-Control"] = "no-store"
        if session_id is not None:
            response.headers["X-Shield-Session"] = session_id
        return result

    @app.post(
        "/shield/sessions",
        response_model=SessionResponse,
        status_code=201,
        responses={"4XX": {"model": APIError}},
    )
    async def create_session(
        request: Request, response: Response, body: SessionCreateRequest | None = None
    ) -> SessionResponse:
        require_unlocked_vault(request)
        record = request.app.state.vault.create()
        response.headers["X-Shield-Session"] = record.session_id
        return SessionResponse(
            session_id=record.session_id,
            created_at=record.created_at,
            expires_at=record.expires_at,
        )

    @app.get(
        "/shield/sessions/{session_id}",
        response_model=SessionResponse,
        responses={"4XX": {"model": APIError}},
    )
    async def get_session(
        session_id: str, request: Request, response: Response
    ) -> SessionResponse:
        require_unlocked_vault(request)
        record = request.app.state.vault.lookup(session_id)
        response.headers["X-Shield-Session"] = record.session_id
        return SessionResponse(
            session_id=record.session_id,
            created_at=record.created_at,
            expires_at=record.expires_at,
        )

    @app.delete(
        "/shield/sessions/{session_id}",
        status_code=204,
        responses={"4XX": {"model": APIError}},
    )
    async def delete_session(session_id: str, request: Request) -> Response:
        require_unlocked_vault(request)
        request.app.state.vault.delete(session_id)
        return Response(status_code=204)

    return app


app = create_app()
