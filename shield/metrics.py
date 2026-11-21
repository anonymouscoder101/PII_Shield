"""Count-only request telemetry. No free-text labels, bodies or identifiers."""

import asyncio
import json
import logging
from contextvars import ContextVar
from dataclasses import dataclass
from time import monotonic

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from shield.contracts import ErrorCode, ProtectionReport, Stage2Outcome

logger = logging.getLogger(__name__)


@dataclass(repr=False)
class _RequestMetrics:
    error_code: ErrorCode | None = None
    report: dict | None = None
    stage2: dict | None = None


_current: ContextVar[_RequestMetrics | None] = ContextVar(
    "shield_metrics", default=None
)


def record_error(code: ErrorCode) -> None:
    if not isinstance(code, ErrorCode):
        raise ValueError("Invalid metrics data.")
    current = _current.get()
    if current is not None:
        current.error_code = code


def record_protection(report: ProtectionReport) -> None:
    try:
        # Revalidate explicit fields: forged models and mutable nested maps must
        # never become free-text telemetry or validation-error log messages.
        checked = ProtectionReport(
            protected_counts=report.protected_counts,
            allowlisted_disclosure_counts=report.allowlisted_disclosure_counts,
            unknown_token_count=report.unknown_token_count,
        )
        snapshot = checked.model_dump(mode="json")
    except Exception:
        raise ValueError("Invalid metrics data.") from None
    current = _current.get()
    if current is not None:
        current.report = snapshot


def record_stage2(outcome: Stage2Outcome) -> None:
    try:
        snapshot = Stage2Outcome(
            status=outcome.status, failure=outcome.failure
        ).model_dump(mode="json")
    except Exception:
        raise ValueError("Invalid metrics data.") from None
    current = _current.get()
    if current is not None:
        current.stage2 = snapshot


def _endpoint(path: str) -> str:
    if path == "/v1/chat/completions":
        return "chat"
    if path == "/shield/analyze":
        return "analyze"
    if path == "/shield/health":
        return "health"
    if path == "/shield/sessions" or path.startswith("/shield/sessions/"):
        return "sessions"
    return "other"


class MetricsMiddleware:
    """Emit once after response delivery/cancellation, outside request limits."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        current = _RequestMetrics()
        token = _current.set(current)
        start = monotonic()
        status = None
        disconnected = cancelled = failed = False

        async def received() -> Message:
            nonlocal disconnected
            message = await receive()
            if message["type"] == "http.disconnect":
                disconnected = True
            return message

        async def sent(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        try:
            await self.app(scope, received, sent)
        except asyncio.CancelledError:
            cancelled = True
            raise
        except Exception:
            failed = True
            current.error_code = ErrorCode.INTERNAL_ERROR
            raise
        finally:
            _current.reset(token)
            outcome = (
                "disconnected"
                if disconnected
                else "cancelled"
                if cancelled
                else "error"
                if failed
                or current.error_code is not None
                or status is None
                or status >= 400
                else "success"
            )
            event = {
                "event": "request_finished",
                "endpoint": _endpoint(scope["path"]),
                "outcome": outcome,
                "status": status,
                "duration_ms": round(max(0, monotonic() - start) * 1000, 3),
                "error_code": current.error_code.value if current.error_code else None,
            }
            if status == 200 and outcome == "success" and current.report is not None:
                event["report"] = current.report
            if current.stage2 is not None:
                event["stage2"] = current.stage2
            try:
                logger.info(json.dumps(event, separators=(",", ":")))
            except Exception:
                # A broken log sink must not replace a response or leak an
                # exception containing sensitive request state through a traceback.
                pass
