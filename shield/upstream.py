"""One-attempt async Chat Completions transport; no detection or session access.

Call only after gateway preparation succeeds, while its session is still active.
The caller owns restoration and delivery; this client never returns error bodies.
"""

import asyncio
import logging
from contextvars import ContextVar

import httpx
from pydantic import SecretStr

from shield.api import ChatCompletionResponse
from shield.config import UpstreamConfig
from shield.contracts import ErrorCode
from shield.errors import ShieldError

_sending: ContextVar[bool] = ContextVar("shield_upstream_sending", default=False)


class _PrivateTransportLogs(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return not _sending.get()


# HTTPX logs URLs; httpcore DEBUG logs response headers and exception details.
# Suppress those records only within this client's context, including close.
for _name in (
    "httpx",
    "httpcore",
    "httpcore.connection",
    "httpcore.http11",
    "httpcore.http2",
    "httpcore.proxy",
    "httpcore.socks",
):
    logging.getLogger(_name).addFilter(_PrivateTransportLogs())


class UpstreamClient:
    """Async context manager with verified HTTPS and zero automatic retries.

    Completion POSTs can incur duplicate work/cost even on ambiguous failures.
    Every call makes at most one attempt, including on connection failures,
    timeouts, 429 or 5xx. No redirects or environment proxies are used.
    ``transport`` is a server-side test injection, never a request field.
    """

    def __init__(
        self,
        config: UpstreamConfig,
        api_key: SecretStr | None = None,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self._timeout = config.timeout_s
        self._url = str(config.base_url).rstrip("/") + "/chat/completions"
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if api_key is not None:
            headers["Authorization"] = "Bearer " + api_key.get_secret_value()
        self._client = httpx.AsyncClient(
            verify=True,
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(config.timeout_s),
            headers=headers,
            transport=transport,
        )

    async def __aenter__(self):
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc):
        token = _sending.set(True)
        try:
            await self._client.__aexit__(*exc)
        finally:
            _sending.reset(token)

    async def complete(self, payload: bytes) -> ChatCompletionResponse:
        """Send the exact guarded bytes and validate buffered response JSON.

        HTTPX phase timeouts and a total async deadline share timeout_s. Caller
        cancellation propagates without conversion or retry. Provider errors,
        malformed JSON and unsupported responses become static public errors.
        """
        token = _sending.set(True)
        try:
            loop = asyncio.get_running_loop()
            deadline = loop.time() + self._timeout
            async with asyncio.timeout_at(deadline):
                response = await self._client.post(self._url, content=payload)
                try:
                    if response.status_code != 200:
                        raise ShieldError(ErrorCode.UPSTREAM_ERROR)
                    result = ChatCompletionResponse.model_validate_json(
                        response.content
                    )
                finally:
                    await response.aclose()
                # Synchronous JSON validation can overrun without yielding to
                # asyncio's timeout callback. Never publish that late success.
                if loop.time() >= deadline:
                    raise TimeoutError()
                return result
        except httpx.TimeoutException, TimeoutError:
            raise ShieldError(ErrorCode.UPSTREAM_TIMEOUT) from None
        except ShieldError:
            raise
        except Exception:
            raise ShieldError(ErrorCode.UPSTREAM_ERROR) from None
        finally:
            _sending.reset(token)
