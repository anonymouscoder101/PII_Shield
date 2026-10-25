"""Local synthetic upstream. Captures live in memory and are never logged/exported.

Run with ``python -m shield.fake_upstream`` or inject the app into HTTPX using
ASGITransport. This app simulates a provider; it does not detect or restore PII.
"""

from collections.abc import Callable
from dataclasses import dataclass, field

import uvicorn
from fastapi import Depends, FastAPI, Request

from shield.api import (
    AssistantMessage,
    ChatCompletionRequest,
    ChatCompletionResponse,
    CompletionChoice,
    CompletionUsage,
)
from shield.contracts import APIError, ErrorCode
from shield.errors import ShieldError, install_error_handlers, require_json

type ResponseFactory = Callable[[ChatCompletionRequest], ChatCompletionResponse]


@dataclass(frozen=True, slots=True)
class CapturedRequest:
    """The exact request body, including JSON escaping; excludes HTTP headers."""

    body: bytes = field(repr=False)


def synthetic_response(request: ChatCompletionRequest) -> ChatCompletionResponse:
    """Return deterministic canned tokens; zero usage values are synthetic."""
    return ChatCompletionResponse(
        id="chatcmpl-fake",
        object="chat.completion",
        created=0,
        model=request.model,
        choices=[
            CompletionChoice(
                index=index,
                message=AssistantMessage(
                    role="assistant",
                    content="[PERSON_7K2Q] can be reached at [EMAIL_2M4R].",
                ),
                finish_reason="stop",
            )
            for index in range(request.n)
        ],
        usage=CompletionUsage(prompt_tokens=0, completion_tokens=0, total_tokens=0),
    )


def create_fake_upstream(
    response_factory: ResponseFactory = synthetic_response,
) -> FastAPI:
    """Create an isolated capture store and a programmable response producer.

    Supply a factory to exercise exact/variant/unknown tokens or multiple choices.
    It may raise ShieldError for controlled errors. Inspect/clear captures through
    ``app.state.captures`` from the local test process; no HTTP capture API exists.
    """
    app = FastAPI(title="PII Shield synthetic upstream", version="0.1.0")
    captures: list[CapturedRequest] = []
    app.state.captures = captures
    install_error_handlers(app)

    @app.middleware("http")
    async def capture_request(request: Request, call_next):
        if request.method == "POST" and request.url.path == "/v1/chat/completions":
            # Capture before JSON/schema validation, including malformed payloads.
            captures.append(CapturedRequest(body=await request.body()))
        return await call_next(request)

    @app.post(
        "/v1/chat/completions",
        response_model=ChatCompletionResponse,
        dependencies=[Depends(require_json)],
        responses={"4XX": {"model": APIError}, 500: {"model": APIError}},
    )
    async def complete(body: ChatCompletionRequest) -> ChatCompletionResponse:
        # The protected proxy must buffer a complete upstream JSON response even
        # for streaming clients; reject accidental upstream streaming explicitly.
        if body.stream:
            raise ShieldError(ErrorCode.INVALID_REQUEST)
        return response_factory(body)

    return app


app = create_fake_upstream()


def main() -> None:
    """Serve only localhost; access logs cannot expose request URLs or bodies."""
    uvicorn.run(app, host="127.0.0.1", port=8001, access_log=False)


if __name__ == "__main__":
    main()
