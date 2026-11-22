"""Run a real Stage 1 JSON + buffered SSE round trip using synthetic data only.

Both HTTP boundaries use ASGITransport: no sockets, provider, Ollama, credentials,
or vault are needed. The pinned local English model must already be installed.
"""

import asyncio
import json
import sys

import httpx

from shield.api import (
    ChatCompletionChunk,
    ChatCompletionRequest,
    ChatCompletionResponse,
)
from shield.app import create_app
from shield.config import DetectionConfig, ShieldConfig
from shield.fake_upstream import create_fake_upstream

_MESSAGES = [
    {"role": "system", "content": "Synthetic email: synthetic.person@example.test."},
    {"role": "developer", "content": "Internal ID: EMP-123456."},
    {
        "role": "user",
        "content": "Meet Alice Smith tomorrow. Phone: +1 202-555-0147.",
    },
    {
        "role": "assistant",
        "content": "Reply to synthetic email: synthetic.person@example.test.",
    },
]
_SYNTHETIC_VALUES = (
    "synthetic.person@example.test",
    "EMP-123456",
    "Alice Smith",
    "+1 202-555-0147",
)


class DemoFailure(RuntimeError):
    """A checked demo invariant failed; messages never include exchange contents."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise DemoFailure(message)


def _echo_sanitized(request: ChatCompletionRequest) -> ChatCompletionResponse:
    """Echo exactly what the fake provider received, in two completion choices."""
    content = "\n".join(message.content for message in request.messages)
    return ChatCompletionResponse.model_validate(
        {
            "id": "chatcmpl-offline-demo",
            "object": "chat.completion",
            "created": 0,
            "model": request.model,
            "choices": [
                {
                    "index": index,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": reason,
                }
                for index, reason in enumerate(("stop", "length"))
            ],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        }
    )


def _check_sse(text: str, expected_content: str) -> None:
    frames = text.strip().split("\n\n")
    _require(frames[-1] == "data: [DONE]", "SSE is missing its final DONE frame.")
    _require(
        all(frame.startswith("data: ") for frame in frames), "Invalid SSE framing."
    )
    chunks = [
        ChatCompletionChunk.model_validate_json(frame.removeprefix("data: "))
        for frame in frames[:-1]
    ]
    choices = [choice for chunk in chunks for choice in chunk.choices]
    _require({choice.index for choice in choices} == {0, 1}, "Missing SSE choices.")
    for index, reason in enumerate(("stop", "length")):
        selected = [choice for choice in choices if choice.index == index]
        _require(
            "".join(choice.delta.content or "" for choice in selected)
            == expected_content,
            "SSE content was not completely restored.",
        )
        _require(
            [choice.delta.role for choice in selected if choice.delta.role]
            == ["assistant"],
            "SSE assistant role was not preserved.",
        )
        _require(
            [choice.finish_reason for choice in selected if choice.finish_reason]
            == [reason],
            "SSE finish reason was not preserved.",
        )
    _require(
        sum(chunk.usage is not None for chunk in chunks) == 1, "Missing SSE usage."
    )


async def run_demo() -> dict:
    """Return the checked, synthetic-only transcript with sanitized wire captures.

    Raising on a failed check gives the CLI a nonzero exit code. Values in this
    result are safe to display only because this demo accepts no external input.
    """
    upstream = create_fake_upstream(_echo_sanitized)
    config = ShieldConfig(detection=DetectionConfig(mode="fast"))
    app = create_app(config, upstream_transport=httpx.ASGITransport(app=upstream))
    expected_content = "\n".join(message["content"] for message in _MESSAGES)
    exchanges = []
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://shield.local"
        ) as client,
    ):
        for stream in (False, True):
            payload = {
                "model": "synthetic-offline-model",
                "messages": _MESSAGES,
                "n": 2,
                "stream": stream,
            }
            if stream:
                payload["stream_options"] = {"include_usage": True}
            response = await client.post("/v1/chat/completions", json=payload)
            _require(
                response.status_code == 200,
                "Protected request failed; install the pinned stage1 model first.",
            )
            _require(
                len(upstream.state.captures) == len(exchanges) + 1,
                "Expected exactly one upstream call per completion.",
            )
            capture = upstream.state.captures[-1].body
            sent = json.loads(capture)
            _require(
                all(value not in capture.decode() for value in _SYNTHETIC_VALUES),
                "A synthetic sensitive value reached the fake provider.",
            )
            _require(
                sent["stream"] is False and "stream_options" not in sent,
                "The provider request must be buffered JSON.",
            )
            report = json.loads(response.headers["x-shield-report"])
            _require(
                report["protected_count"] == 5 and report["unknown_token_count"] == 0,
                "Unexpected protection or restoration counts for the fixture.",
            )
            if stream:
                _require(
                    response.headers["content-type"].startswith("text/event-stream"),
                    "Expected SSE content type.",
                )
                _check_sse(response.text, expected_content)
                delivered = response.text
            else:
                delivered = response.json()
                completion = ChatCompletionResponse.model_validate(delivered)
                _require(
                    [choice.index for choice in completion.choices] == [0, 1]
                    and all(
                        choice.message.content == expected_content
                        for choice in completion.choices
                    ),
                    "JSON completion choices were not completely restored.",
                )
            exchanges.append(
                {
                    "delivery": "buffered_sse" if stream else "json",
                    "upstream_request": sent,
                    "report": report,
                    "response": delivered,
                }
            )
        health = await client.get("/shield/health")
        _require(health.status_code == 200, "Health check failed.")
    return {
        "synthetic": True,
        "mode": config.detection.mode,
        "stage1_status": health.json()["stage1_status"],
        "checks_passed": True,
        "exchanges": exchanges,
    }


def main() -> None:
    try:
        result = asyncio.run(run_demo())
    except DemoFailure as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from None
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
