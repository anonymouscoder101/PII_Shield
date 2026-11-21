"""Count response bytes before the Ollama SDK can aggregate or parse them."""

import httpx

from shield.detect.review_limits import ReviewerOutputLimit, checked_limit


class _BoundedStream(httpx.AsyncByteStream):
    def __init__(self, stream, limit):
        self._stream, self._limit = stream, limit
        self._closed = False

    async def __aiter__(self):
        size = 0
        try:
            async for chunk in self._stream:
                size += len(chunk)
                if size > self._limit:
                    raise ReviewerOutputLimit()
                yield chunk
        finally:
            await self.aclose()

    async def aclose(self):
        if not self._closed:
            self._closed = True
            await self._stream.aclose()


class BoundedReviewTransport(httpx.AsyncBaseTransport):
    def __init__(self, limit, delegate=None):
        self._limit = checked_limit(limit)
        self._delegate = (
            delegate
            if delegate is not None
            else httpx.AsyncHTTPTransport(retries=0, trust_env=False)
        )

    async def handle_async_request(self, request):
        request.headers["accept-encoding"] = "identity"
        response = await self._delegate.handle_async_request(request)
        try:
            encoding = response.headers.get("content-encoding", "identity").lower()
            length = response.headers.get("content-length")
            if encoding != "identity" or (
                length is not None
                and (not length.isdigit() or int(length) > self._limit)
            ):
                raise ReviewerOutputLimit()
            if response.is_stream_consumed and len(response.content) > self._limit:
                raise ReviewerOutputLimit()
        except Exception:
            await response.aclose()
            raise
        response.stream = _BoundedStream(response.stream, self._limit)
        return response

    async def aclose(self):
        await self._delegate.aclose()
