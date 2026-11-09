"""ASGI scaffold. Protection and proxy endpoints are not implemented yet."""

from fastapi import Depends, FastAPI, Request

from shield import __version__
from shield.api import (
    ChatCompletionRequest,
    ChatCompletionResponse,
    SessionCreateRequest,
)
from shield.config import ShieldConfig
from shield.contracts import APIError, ErrorCode
from shield.credentials import RuntimeCredentials
from shield.errors import ShieldError, install_error_handlers, require_json
from shield.limits import RequestLimitsMiddleware
from shield.session_access import require_session_access, require_unlocked_vault


def create_app(
    config: ShieldConfig | None = None,
    credentials: RuntimeCredentials | None = None,
) -> FastAPI:
    """Retain validated settings for future protection components."""
    app = FastAPI(
        title="PII Shield",
        description=(
            "Foundation scaffold. PII protection endpoints are not available yet."
        ),
        version=__version__,
    )
    app.state.config = config if config is not None else ShieldConfig()
    app.state.credentials = (
        credentials if credentials is not None else RuntimeCredentials()
    )
    app.state.vault = None  # No authenticated vault implementation exists in Phase 1.
    install_error_handlers(app)
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
            423: {"model": APIError, "description": "Persistent vault is locked."},
            500: {"model": APIError, "description": "Internal error."},
            503: {
                "model": APIError,
                "description": "Protection is not implemented yet.",
            },
        },
        description=(
            "Validates the supported text-only contract. Valid requests currently "
            "return 503; no upstream calls are made. Future stream=true responses "
            "will use buffered SSE after full restoration."
        ),
    )
    async def chat_completions(
        body: ChatCompletionRequest, request: Request
    ) -> ChatCompletionResponse:
        require_session_access(request)
        raise ShieldError(ErrorCode.PROTECTION_UNAVAILABLE)

    @app.post(
        "/shield/sessions",
        responses={
            "4XX": {"model": APIError, "description": "Invalid session request."},
            423: {"model": APIError, "description": "Persistent vault is locked."},
            503: {
                "model": APIError,
                "description": "Session storage is not implemented.",
            },
        },
        description=(
            "Locked foundation stub; reusable session creation arrives in Phase 2."
        ),
    )
    async def create_session(
        request: Request, body: SessionCreateRequest | None = None
    ) -> None:
        require_unlocked_vault(request)
        raise ShieldError(ErrorCode.PROTECTION_UNAVAILABLE)

    return app


app = create_app()
