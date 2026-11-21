"""Local analysis and session routes; protected chat forwarding follows later."""

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request, Response
from starlette.concurrency import run_in_threadpool

from shield import __version__
from shield.analysis import (
    AnalysisJob,
    ChatPreparationJob,
    DetectorFactory,
    DetectorProvider,
    run_analysis_job,
)
from shield.api import (
    AnalyzeRequest,
    AnalyzeResponse,
    ChatCompletionRequest,
    ChatCompletionResponse,
    SessionCreateRequest,
    SessionResponse,
)
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
from shield.persistent import SessionAccessError, VaultStartupError, VaultStartupHandoff
from shield.session_access import require_session_access, require_unlocked_vault


def create_app(
    config: ShieldConfig | None = None,
    credentials: RuntimeCredentials | None = None,
    *,
    detector_factory: DetectorFactory | None = None,
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
            "Chat forwarding is not implemented yet."
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
    app.state.vault = None  # Authenticated service is installed only during lifespan.
    install_error_handlers(app)

    @app.exception_handler(SessionAccessError)
    async def session_error(request: Request, exc: SessionAccessError):
        return error_response(exc.code)

    app.add_middleware(RequestLimitsMiddleware, config=app.state.config.server)

    @app.post(
        "/v1/chat/completions",
        response_model=ChatCompletionResponse,
        dependencies=[Depends(require_json)],
        responses={
            200: {
                "description": "Future protected JSON or buffered SSE response.",
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
            503: {
                "model": APIError,
                "description": "Protection is not implemented yet.",
            },
        },
        description=(
            "Validates, sanitizes and guards every supported message role. Requests "
            "currently return 503; no upstream calls are made. Future stream=true "
            "responses will use buffered SSE after full restoration."
        ),
    )
    async def chat_completions(
        body: ChatCompletionRequest, request: Request
    ) -> ChatCompletionResponse:
        require_session_access(request)
        session_id = request.headers.get("x-shield-session")
        service = request.app.state.vault if session_id is not None else None
        job = ChatPreparationJob(
            request.app.state.detector_provider, service, session_id
        )
        try:
            await run_analysis_job(job, body, request.receive)
            raise ShieldError(ErrorCode.REQUEST_TIMEOUT)
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
        job = AnalysisJob(request.app.state.detector_provider, service, session_id)
        try:
            result = await run_analysis_job(job, body.text, request.receive)
            if result is None:
                raise ShieldError(ErrorCode.REQUEST_TIMEOUT)
        finally:
            job.cancel()
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
