"""Bound incoming HTTP bodies and work before the first response headers."""

import asyncio

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from shield.config import ServerConfig
from shield.contracts import ErrorCode
from shield.errors import error_response


class RequestLimitsMiddleware:
    """Read at most the configured body budget before invoking application code.

    Checking actual bytes covers absent/false Content-Length and chunked uploads.
    The timeout includes upload, validation, and processing until response headers;
    it is disabled for body delivery, including buffered SSE. Cancellation
    propagates into the handler so its finally blocks can release request state.
    """

    def __init__(self, app: ASGIApp, config: ServerConfig) -> None:
        self.app = app
        self.max_bytes = config.max_request_bytes
        self.timeout_s = config.request_timeout_s

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def reject(code: ErrorCode) -> None:
            response = error_response(code)
            # Early rejections need not drain an oversized or stalled upload.
            if scope.get("http_version", "1.1").startswith("1."):
                response.headers["Connection"] = "close"
            await response(scope, receive, send)

        lengths = [
            value.strip()
            for key, value in scope["headers"]
            if key.lower() == b"content-length"
        ]
        expected = None
        if lengths:
            if len(lengths) != 1 or not lengths[0].isdigit():
                await reject(ErrorCode.INVALID_REQUEST)
                return
            try:
                expected = int(lengths[0])
            except ValueError:
                await reject(ErrorCode.INVALID_REQUEST)
                return
            if expected > self.max_bytes:
                await reject(ErrorCode.REQUEST_TOO_LARGE)
                return

        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.timeout_s
        budget = asyncio.timeout_at(deadline)
        late_headers = False
        started = False
        body_error = None

        async def bounded_send(message: Message) -> None:
            nonlocal late_headers, started
            if message["type"] == "http.response.start":
                # Synchronous work may block the event loop past the timer. Do
                # not let such a response commit success headers after expiry.
                if loop.time() >= deadline:
                    late_headers = True
                    return
                budget.reschedule(None)
                started = True
            if not late_headers:
                await send(message)

        try:
            async with budget:
                chunks = []
                size = 0
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return
                    chunk = message.get("body", b"")
                    size += len(chunk)
                    if size > self.max_bytes:
                        body_error = ErrorCode.REQUEST_TOO_LARGE
                        break
                    if chunk:
                        chunks.append(chunk)
                    if not message.get("more_body", False):
                        break
                if body_error is None and expected is not None and size != expected:
                    body_error = ErrorCode.INVALID_REQUEST
                if body_error is None and loop.time() >= deadline:
                    body_error = ErrorCode.REQUEST_TIMEOUT
                if body_error is None:
                    body = b"".join(chunks)
                    chunks.clear()
                    delivered = False

                    async def replay_receive() -> Message:
                        nonlocal delivered
                        if not delivered:
                            delivered = True
                            return {
                                "type": "http.request",
                                "body": body,
                                "more_body": False,
                            }
                        return await receive()

                    await self.app(scope, replay_receive, bounded_send)
        except TimeoutError:
            if not budget.expired():
                raise
            if not started:
                await reject(ErrorCode.REQUEST_TIMEOUT)
            return
        if body_error is not None:
            await reject(body_error)
        elif late_headers:
            await reject(ErrorCode.REQUEST_TIMEOUT)
