# Supported API contract

Phase 1 task 4 defines a strict text-only subset of the
[Chat Completions API](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create).
The contract is intentionally narrower than the provider API. The models live in
[`shield/api.py`](../shield/api.py); every model uses `extra="forbid"` and strict
validation. Unknown fields are errors, including fields whose values are null,
false, or empty containers. JSON booleans cannot be replaced with strings/integers.

## Current endpoint behavior

`POST /v1/chat/completions` accepts `Content-Type: application/json` (with optional
parameters such as `charset=utf-8`). It validates the request and returns **503**
`protection_unavailable` for a valid ephemeral payload. Selecting a persistent
session while the vault is locked returns **423** `vault_locked`.
`POST /shield/sessions` is a locked creation stub accepting an empty object or no
body; it also returns 423. It rejects extra body fields, including credentials.
The scaffold makes no upstream calls. Detection, protection, restoration, actual
buffered SSE delivery, and working session endpoints are implemented in later
phases. `/docs` and `/openapi.json` expose the contract.

```json
{
  "model": "synthetic-model",
  "messages": [{"role": "user", "content": "Hello, Synthetic Person."}],
  "stream": false
}
```

## Request limits and session selection

The proxy bounds HTTP request bodies before JSON parsing with
`server.max_request_bytes` (default 1048576, 1 MiB). Requests exceeding the declared
or measured byte limit return 413. Chunked requests and requests without a length
header are counted as they arrive. Duplicate, invalid, and mismatched
`Content-Length` values return 400. UTF-8 bytes and JSON escapes count toward the
limit, not the number of characters in decoded content. An incomplete upload or
oversized body never reaches a route. Rejections can close HTTP/1 connections
without draining the upload.

`server.request_timeout_s` (default 120 seconds) is a cooperative deadline covering
body upload and application processing through the first response headers. Expiry
returns JSON 408 `request_timeout`, including when the client asked for streaming.
Cancellation propagates to async handlers and runs their `finally` cleanup.
Synchronous work cannot be forcibly interrupted, but headers arriving after the
deadline are rejected. Slow response delivery after headers is outside this
deadline, so future buffered SSE delivery is not truncated by the processing timer.
These limits do not replace the separate upstream or Stage 2 timeouts implemented
alongside those clients in later phases.

No `X-Shield-Session` header selects ephemeral operation, with no vault readiness
lookup. A supplied header must be nonblank and occur exactly once; invalid header
forms return 400. Valid persistent selections require both
`sessions.persistent_enabled: true` and a vault service reporting an authenticated
unlock. All foundation vaults start unavailable, so persistent requests return 423
even if startup collected a passphrase. Unknown/expired session lookup and reusable
session creation remain Phase 2 work. No session ID is returned by the foundation.

## Request fields

| Field | Supported value | Default |
| --- | --- | --- |
| `model` | Required nonempty string; provider model identifier | Required |
| `messages` | Required nonempty array of message objects | Required |
| `messages[].role` | `system`, `developer`, `user`, or `assistant` | Required |
| `messages[].content` | String, including an empty string; no arrays or null | Required |
| `stream` | Boolean | `false` |
| `stream_options` | Object with only `include_usage`, a boolean; requires `stream: true` | Omitted/null |
| `stream_options.include_usage` | Request a final usage chunk | `false` |
| `temperature` | Finite number in [0, 2] | Omitted/null |
| `top_p` | Finite number in [0, 1] | Omitted/null |
| `n` | Integer in [1, 128] | `1` |
| `max_tokens` | Positive integer; mutually exclusive with `max_completion_tokens` | Omitted/null |
| `max_completion_tokens` | Positive integer; mutually exclusive with `max_tokens` | Omitted/null |
| `presence_penalty`, `frequency_penalty` | Finite numbers in [-2, 2] | Omitted/null |
| `seed` | Signed 64-bit integer | Omitted/null |

Only the listed fields are supported. Examples of rejected fields include message
`name`, `tool_calls`, `tool_call_id`, `function_call`, and top-level `tools`,
`tool_choice`, `functions`, `user`, `metadata`, `stop`, `response_format`, `store`,
`logprobs`, credentials, and multimodal fields. Tool/function roles are rejected.
The proxy also rejects content-part arrays containing only text. Model-specific
parameter support remains the upstream provider's responsibility.

All four accepted message roles will go through the same protection pipeline,
including restored assistant history. The final guard must also inspect every
other supported user-controlled string, including the model identifier; a model
identifier cannot be treated as an unchecked text channel. Validation alone does
not protect PII. No request forwarding is enabled by this task.

## Complete JSON response fields

`ChatCompletionResponse` defines the following fields for future upstream
validation and restored client responses. Unlisted fields are rejected, never
silently passed through. There are no untyped passthrough objects.

| Object | Fields |
| --- | --- |
| Completion | Required `id` and `model` nonempty strings, `object: "chat.completion"`, nonnegative integer `created`, nonempty `choices`; optional nullable `usage`, `system_fingerprint`, `service_tier` |
| Choice | Required nonnegative integer `index`, `message`, `finish_reason`; optional `logprobs` accepting only null |
| Assistant message | Required `role: "assistant"` and `content` (string or null); optional nullable string `refusal`, and `annotations` accepting only an empty array |
| Usage | Required nonnegative integer `prompt_tokens`, `completion_tokens`, `total_tokens`; optional nullable `prompt_tokens_details`, `completion_tokens_details` |
| Prompt token details | Optional nullable nonnegative integers `cached_tokens`, `cache_write_tokens`, `audio_tokens`, `image_tokens`, `text_tokens` |
| Completion token details | Optional nullable nonnegative integers `reasoning_tokens`, `audio_tokens`, `text_tokens`, `accepted_prediction_tokens`, `rejected_prediction_tokens` |

Choice indices must be unique. Supported finish reasons are `stop`, `length`, and
`content_filter`. Tool/function outputs, non-null log probabilities, and nonempty
annotations are unsupported. Both assistant `content` and `refusal` text must be
rehydrated in Phase 4. Null content permits filtered/refusal-only answers.
Usage counts describe the tokenized upstream exchange, including any reasoning
tokens, rather than a retokenization of restored text.

## Buffered SSE response fields

The `ChatCompletionChunk` contract follows the
[streaming event shape](https://developers.openai.com/api/reference/resources/chat/subresources/completions/streaming-events).
Chunks have required `id`, `object: "chat.completion.chunk"`, `created`, `model`,
and `choices`, plus the same optional `usage`, `system_fingerprint`, and
`service_tier` fields as complete responses. Each choice has a nonnegative integer
`index`, required `delta`, optional nullable `finish_reason`, and optional null-only
`logprobs`. Delta accepts only optional nullable `role` (if present, `assistant`),
string `content`, and string `refusal`. Indices are unique within each chunk.
An empty choices array requires a non-null usage object.

Phase 4 will fetch the full upstream answer with `stream: false`, restore it, and
then emit role/text and finish events as JSON in `data:` SSE frames. With
`stream_options.include_usage: true`, it will also emit a final usage event with
empty choices; other events carry null usage. Every stream ends with
`data: [DONE]` and a blank line. IDs and choice indices stay consistent. SSE headers
must wait until upstream success and restoration; pre-delivery errors return JSON.
Buffering delays the first content until generation is complete. This task defines
the schemas and protocol; it does not emit SSE frames yet.

## Errors

All public failures use this envelope with a static message:

```json
{"error": {"code": "invalid_request", "message": "Invalid or unsupported request payload."}}
```

| HTTP status | Error codes |
| --- | --- |
| 400 | `invalid_request` (including malformed JSON and unsupported nested fields) |
| 404 | `not_found`, `session_not_found` |
| 405 | `method_not_allowed` (preserves a valid `Allow` header) |
| 408 | `request_timeout` |
| 410 | `session_expired` |
| 413 | `request_too_large` |
| 415 | `unsupported_media_type` |
| 422 | `protection_blocked` |
| 423 | `vault_locked` |
| 500 | `internal_error` (including invalid response data) |
| 502 | `upstream_error` |
| 503 | `protection_unavailable`, `detection_failed`, `reviewer_unavailable` |
| 504 | `upstream_timeout` |

Validation, request limits, framework errors, locked-vault selection, and the
unavailable pipeline are exercised by the current chat route. Other codes define
behavior for their later components; session lookup and upstream timeouts remain
future work.
Handlers never return validation inputs, field paths supplied by the caller,
provider bodies, exception strings, or credentials. Unexpected HTTP exceptions
produce a fixed log event without traceback text. If an unexpected error occurs
after response headers, the response body ends without emitting exception text;
it cannot be replaced with a JSON error at that point.

## Startup credentials

The CLI reads the provider key only from the environment variable named by
`upstream.api_key_env`. A missing key is allowed for the current scaffold and local
fake upstream; an explicitly empty or whitespace-containing key is rejected.
No YAML field, command-line value, or HTTP request field accepts a provider key
or vault passphrase.

`sessions.persistent_enabled: true` opts into a startup passphrase prompt using
`getpass`. Default ephemeral operation never prompts. If echo cannot be disabled,
input is closed, or the passphrase is blank, startup stops before the server runs.
The passphrase preserves its exact spelling, including surrounding whitespace.
The CLI collects runtime credentials into masked `SecretStr` fields excluded from
serialization and passes them to `create_app(config, credentials)`. Programmatic
callers must explicitly call `load_credentials(config)` to obtain the same behavior.
Secrets stay in process memory; this does not promise secure memory erasure.

The persistent-session setting currently collects a passphrase only. Vault key
derivation, unlock verification, persistent session creation, and session lifecycle
remain Phase 2 work. Default request sessions remain ephemeral even when persistent
session support is enabled.
