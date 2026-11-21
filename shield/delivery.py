"""Restore every assistant text field and serialize buffered JSON or SSE."""

from pydantic import Field
from starlette.responses import JSONResponse, Response

from shield.api import (
    ChatCompletionChunk,
    ChatCompletionResponse,
    ChunkChoice,
    CompletionDelta,
)
from shield.contracts import Contract, Count, ProtectionReport
from shield.rehydrate import MappingReader, rehydrate_text


class RestoredCompletion(Contract):
    completion: ChatCompletionResponse = Field(repr=False)
    unknown_token_count: Count


def restore_completion(
    completion: ChatCompletionResponse, session: MappingReader
) -> RestoredCompletion:
    choices = []
    unknown = 0
    for choice in completion.choices:
        message = choice.message
        update = {}
        for field in ("content", "refusal"):
            value = getattr(message, field)
            if value is None:
                update[field] = None
            else:
                restored = rehydrate_text(value, session)
                update[field] = restored.text
                unknown += restored.unknown_token_count
        choices.append(
            choice.model_copy(update={"message": message.model_copy(update=update)})
        )
    return RestoredCompletion(
        completion=completion.model_copy(update={"choices": choices}),
        unknown_token_count=unknown,
    )


def completion_response(
    completion: ChatCompletionResponse,
    *,
    stream: bool,
    include_usage: bool,
    report: ProtectionReport,
    session_id: str | None = None,
) -> Response:
    """Construct the entire delivery body before committing any response headers."""
    headers = {"Cache-Control": "no-store", "X-Shield-Report": report.model_dump_json()}
    if session_id is not None:
        headers["X-Shield-Session"] = session_id
    if not stream:
        return JSONResponse(completion.model_dump(mode="json"), headers=headers)
    base = dict(
        id=completion.id,
        object="chat.completion.chunk",
        created=completion.created,
        model=completion.model,
        system_fingerprint=completion.system_fingerprint,
        service_tier=completion.service_tier,
    )
    frames = []

    def emit(choices, usage=None):
        chunk = ChatCompletionChunk(**base, choices=choices, usage=usage)
        frames.append("data: " + chunk.model_dump_json(exclude_none=True) + "\n\n")

    for choice in completion.choices:
        emit(
            [
                ChunkChoice(
                    index=choice.index,
                    delta=CompletionDelta(
                        role="assistant",
                        content=choice.message.content,
                        refusal=choice.message.refusal,
                    ),
                )
            ]
        )
        emit(
            [
                ChunkChoice(
                    index=choice.index,
                    delta=CompletionDelta(),
                    finish_reason=choice.finish_reason,
                )
            ]
        )
    if include_usage and completion.usage is not None:
        emit([], completion.usage)
    frames.append("data: [DONE]\n\n")
    return Response("".join(frames), media_type="text/event-stream", headers=headers)
