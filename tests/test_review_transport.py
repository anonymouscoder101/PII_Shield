"""Reviewer response bounds apply before SDK buffering, regardless of headers."""

import httpx
import pytest


@pytest.mark.parametrize("headers", [{}, {"content-length": "1"}])
async def test_response_stream_is_stopped_and_closed_at_limit(headers):
    from shield.detect.review_limits import ReviewerOutputLimit
    from shield.detect.review_transport import BoundedReviewTransport

    seen, closed = [], []

    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):
            for part in (b"1234", b"5678", b"private-unread-reason"):
                seen.append(part)
                yield part

        async def aclose(self):
            closed.append(True)

    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, headers=headers, stream=Stream())
    )
    async with httpx.AsyncClient(
        transport=BoundedReviewTransport(6, transport)
    ) as client:
        with pytest.raises(ReviewerOutputLimit):
            await client.get("http://127.0.0.1:11434/api/chat")
    assert seen == [b"1234", b"5678"] and closed


@pytest.mark.parametrize(
    "headers", [{"content-length": "999"}, {"content-encoding": "gzip"}]
)
async def test_oversize_or_compressed_headers_fail_before_body_read(headers):
    from shield.detect.review_limits import ReviewerOutputLimit
    from shield.detect.review_transport import BoundedReviewTransport

    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):
            pytest.fail("Body should not be read")
            yield b""

    async with httpx.AsyncClient(
        transport=BoundedReviewTransport(
            6,
            httpx.MockTransport(
                lambda request: httpx.Response(200, headers=headers, stream=Stream())
            ),
        )
    ) as client:
        with pytest.raises(ReviewerOutputLimit):
            await client.get("http://127.0.0.1:11434/api/chat")
