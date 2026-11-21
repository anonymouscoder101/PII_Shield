"""The explicit text-only HTTP subset. Unlisted fields are rejected at every level.

These models validate shape, not PII. Never forward a validated request before
detection, substitution, mapping registration, and the final guard are implemented.
"""

from typing import Annotated, Literal, Self

from pydantic import AwareDatetime, Field, model_validator

from shield.contracts import (
    Contract,
    Count,
    DetectedSpan,
    NonEmptyString,
    ProtectionReport,
)

PositiveInt = Annotated[int, Field(ge=1)]
FinishReason = Literal["stop", "length", "content_filter"]


class SessionCreateRequest(Contract):
    """Session creation takes no fields; passphrases never arrive over HTTP."""


class ChatMessage(Contract):
    role: Literal["system", "developer", "user", "assistant"]
    content: str = Field(repr=False)


class StreamOptions(Contract):
    include_usage: bool = False


class ChatCompletionRequest(Contract):
    model: NonEmptyString = Field(repr=False)
    messages: Annotated[list[ChatMessage], Field(min_length=1)]
    stream: bool = False
    stream_options: StreamOptions | None = None
    temperature: Annotated[float, Field(ge=0, le=2, allow_inf_nan=False)] | None = None
    top_p: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)] | None = None
    n: Annotated[int, Field(ge=1, le=128)] = 1
    max_tokens: PositiveInt | None = None
    max_completion_tokens: PositiveInt | None = None
    presence_penalty: (
        Annotated[float, Field(ge=-2, le=2, allow_inf_nan=False)] | None
    ) = None
    frequency_penalty: (
        Annotated[float, Field(ge=-2, le=2, allow_inf_nan=False)] | None
    ) = None
    seed: Annotated[int, Field(ge=-(2**63), lt=2**63)] | None = None

    @model_validator(mode="after")
    def consistent_options(self) -> Self:
        if self.stream_options is not None and not self.stream:
            raise ValueError("stream_options requires stream=true")
        if self.max_tokens is not None and self.max_completion_tokens is not None:
            raise ValueError("supply only one completion token limit")
        return self


class AssistantMessage(Contract):
    role: Literal["assistant"]
    content: str | None = Field(repr=False)
    refusal: str | None = Field(default=None, repr=False)
    # Empty annotations from ordinary text completions are compatible. Rich
    # annotations contain additional text/URLs and require a future policy.
    annotations: Annotated[list[None], Field(max_length=0)] = Field(
        default_factory=list
    )


class CompletionChoice(Contract):
    index: Count
    message: AssistantMessage
    finish_reason: FinishReason
    logprobs: None = None


class PromptTokenDetails(Contract):
    cached_tokens: Count | None = None
    cache_write_tokens: Count | None = None
    audio_tokens: Count | None = None
    image_tokens: Count | None = None
    text_tokens: Count | None = None


class CompletionTokenDetails(Contract):
    reasoning_tokens: Count | None = None
    audio_tokens: Count | None = None
    text_tokens: Count | None = None
    accepted_prediction_tokens: Count | None = None
    rejected_prediction_tokens: Count | None = None


class CompletionUsage(Contract):
    prompt_tokens: Count
    completion_tokens: Count
    total_tokens: Count
    prompt_tokens_details: PromptTokenDetails | None = None
    completion_tokens_details: CompletionTokenDetails | None = None


class ChatCompletionResponse(Contract):
    id: NonEmptyString
    object: Literal["chat.completion"]
    created: Count
    model: NonEmptyString
    choices: Annotated[list[CompletionChoice], Field(min_length=1)]
    usage: CompletionUsage | None = None
    system_fingerprint: str | None = None
    service_tier: str | None = None

    @model_validator(mode="after")
    def unique_indices(self) -> Self:
        indices = [choice.index for choice in self.choices]
        if len(indices) != len(set(indices)):
            raise ValueError("choice indices must be unique")
        return self


class CompletionDelta(Contract):
    role: Literal["assistant"] | None = None
    content: str | None = Field(default=None, repr=False)
    refusal: str | None = Field(default=None, repr=False)


class ChunkChoice(Contract):
    index: Count
    delta: CompletionDelta
    finish_reason: FinishReason | None = None
    logprobs: None = None


class ChatCompletionChunk(Contract):
    id: NonEmptyString
    object: Literal["chat.completion.chunk"]
    created: Count
    model: NonEmptyString
    choices: list[ChunkChoice]
    usage: CompletionUsage | None = None
    system_fingerprint: str | None = None
    service_tier: str | None = None

    @model_validator(mode="after")
    def valid_choices(self) -> Self:
        if not self.choices and self.usage is None:
            raise ValueError("empty choices require a usage event")
        indices = [choice.index for choice in self.choices]
        if len(indices) != len(set(indices)):
            raise ValueError("choice indices must be unique")
        return self


class SessionResponse(Contract):
    """Public reusable-session metadata, without keys or mapping values."""

    session_id: NonEmptyString
    created_at: AwareDatetime
    expires_at: AwareDatetime


class AnalyzeRequest(Contract):
    text: str = Field(repr=False)


class AnalyzeResponse(Contract):
    sanitized_text: str = Field(repr=False)
    spans: tuple[DetectedSpan, ...]
    report: ProtectionReport
    preserved_token_count: Count
    below_threshold_count: Count
    preview_only: bool
    session_id: NonEmptyString | None = None


Stage1Status = Literal["not_loaded", "loading", "loaded", "unavailable"]


class HealthResponse(Contract):
    """Local capability snapshot; no credentials, paths or model identifiers."""

    status: Literal["ok"] = "ok"
    ephemeral_available: Literal[True] = True
    persistent_sessions_enabled: bool
    vault_state: Literal["disabled", "locked", "unlocked"]
    stage1_status: Stage1Status
    stage2_available: bool = False
