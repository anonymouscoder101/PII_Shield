"""Static public errors. Request/exception/provider text never enters a response."""

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError, ResponseValidationError
from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from shield.contracts import APIError, APIErrorDetail, ErrorCode

logger = logging.getLogger(__name__)

ERRORS: dict[ErrorCode, tuple[int, str]] = {
    ErrorCode.INVALID_REQUEST: (400, "Invalid or unsupported request payload."),
    ErrorCode.REQUEST_TOO_LARGE: (413, "Request exceeds the supported size limit."),
    ErrorCode.REQUEST_TIMEOUT: (408, "Request exceeded its time limit."),
    ErrorCode.VAULT_LOCKED: (423, "Persistent sessions require an unlocked vault."),
    ErrorCode.SESSION_NOT_FOUND: (404, "Session was not found."),
    ErrorCode.SESSION_EXPIRED: (410, "Session has expired."),
    ErrorCode.DETECTION_FAILED: (503, "PII detection is unavailable."),
    ErrorCode.PROTECTION_BLOCKED: (422, "Request was blocked by the protection guard."),
    ErrorCode.REVIEWER_UNAVAILABLE: (503, "Local contextual review is unavailable."),
    ErrorCode.UPSTREAM_TIMEOUT: (504, "Upstream request timed out."),
    ErrorCode.UPSTREAM_ERROR: (502, "Upstream request failed."),
    ErrorCode.INTERNAL_ERROR: (500, "Request could not be completed."),
    ErrorCode.NOT_FOUND: (404, "Endpoint was not found."),
    ErrorCode.METHOD_NOT_ALLOWED: (405, "HTTP method is not supported."),
    ErrorCode.UNSUPPORTED_MEDIA_TYPE: (
        415,
        "Request content type must be application/json.",
    ),
    ErrorCode.PROTECTION_UNAVAILABLE: (
        503,
        "Protection pipeline is not implemented yet.",
    ),
}


class ShieldError(Exception):
    """Raise a known category, without accepting arbitrary public error text."""

    def __init__(self, code: ErrorCode) -> None:
        self.code = code
        super().__init__(code.value)


def error_response(code: ErrorCode) -> JSONResponse:
    status, message = ERRORS[code]
    error = APIError(error=APIErrorDetail(code=code, message=message))
    return JSONResponse(status_code=status, content=error.model_dump(mode="json"))


async def require_json(request: Request) -> None:
    media_type = (
        request.headers.get("content-type", "").split(";", 1)[0].lower().strip()
    )
    if media_type != "application/json":
        raise ShieldError(ErrorCode.UNSUPPORTED_MEDIA_TYPE)


def install_error_handlers(app: FastAPI) -> None:
    async def validation_error(request: Request, exc: RequestValidationError):
        return error_response(ErrorCode.INVALID_REQUEST)

    async def response_validation_error(request: Request, exc: ResponseValidationError):
        logger.error("request_failed code=internal_error")
        return error_response(ErrorCode.INTERNAL_ERROR)

    async def shield_error(request: Request, exc: ShieldError):
        return error_response(exc.code)

    async def http_error(request: Request, exc: HTTPException):
        code = {
            400: ErrorCode.INVALID_REQUEST,
            404: ErrorCode.NOT_FOUND,
            405: ErrorCode.METHOD_NOT_ALLOWED,
            413: ErrorCode.REQUEST_TOO_LARGE,
            415: ErrorCode.UNSUPPORTED_MEDIA_TYPE,
        }.get(exc.status_code, ErrorCode.INTERNAL_ERROR)
        response = error_response(code)
        if exc.status_code == 405:
            # Preserve the protocol's Allow header, restricted to HTTP verbs.
            allowed = (exc.headers or {}).get("Allow", "").split(",")
            methods = [method.strip() for method in allowed]
            if methods and all(
                method in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
                for method in methods
            ):
                response.headers["Allow"] = ", ".join(methods)
        return response

    app.add_exception_handler(RequestValidationError, validation_error)
    app.add_exception_handler(ResponseValidationError, response_validation_error)
    app.add_exception_handler(ShieldError, shield_error)
    app.add_exception_handler(HTTPException, http_error)
    app.add_middleware(SafeExceptionMiddleware)


class SafeExceptionMiddleware:
    """Consume unexpected HTTP exceptions before server traceback logging.

    For an error after headers, end the body without emitting exception text. The
    protected gateway must finish upstream work/restoration before sending SSE
    headers so its normal failures can still return a complete JSON error.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started = False
        complete = False

        async def track_send(message: Message) -> None:
            nonlocal started, complete
            if message["type"] == "http.response.start":
                started = True
            elif message["type"] == "http.response.body":
                complete = not message.get("more_body", False)
            await send(message)

        try:
            await self.app(scope, receive, track_send)
        except Exception:
            # Never attach exc_info or exception strings: both can contain PII.
            logger.error("request_failed code=internal_error")
            if not started:
                await error_response(ErrorCode.INTERNAL_ERROR)(scope, receive, send)
            elif not complete:
                await send({"type": "http.response.body", "body": b""})
