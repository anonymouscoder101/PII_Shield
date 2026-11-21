"""Restore every assistant text field and serialize buffered JSON or SSE."""

from starlette.responses import JSONResponse, Response

from shield.api import (
    ChatCompletionChunk,
    ChatCompletionResponse,
    ChunkChoice,
    CompletionDelta,
)
from shield.rehydrate import MappingReader, rehydrate_text


def restore_completion(
    completion: ChatCompletionResponse, session: MappingReader
) -> ChatCompletionResponse:
    choices = []
    for choice in completion.choices:
        message = choice.message
        update = {
            field: rehydrate_text(value, session).text if value is not None else None
            for field in ("content", "refusal")
            for value in (getattr(message, field),)
        }
        choices.append(
            choice.model_copy(update={"message": message.model_copy(update=update)})
        )
    return completion.model_copy(update={"choices": choices})


def completion_response(
    completion: ChatCompletionResponse, *, stream: bool, include_usage: bool
) -> Response:
    """Construct the entire delivery body before committing any response headers."""
    headers = {"Cache-Control": "no-store"}
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
