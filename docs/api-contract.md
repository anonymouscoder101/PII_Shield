# Supported API contract

Phase 1 task 4 defines a strict text-only subset of the
[Chat Completions API](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create).
The contract is intentionally narrower than the provider API. The models live in
[`shield/api.py`](../shield/api.py); every model uses `extra="forbid"` and strict
validation. Unknown fields are errors, including fields whose values are null,
false, or empty containers. JSON booleans cannot be replaced with strings/integers.

## Current endpoint behavior

`POST /v1/chat/completions` accepts `Content-Type: application/json` (with optional
parameters such as `charset=utf-8`). It validates the request and prepares all message contents within the selected
session (or a fresh ephemeral session). Preparation runs detection, policy, and
substitution for every supported role, including previous assistant replies.
The outgoing payload is serialized once after mapping registration. A final
read-only Stage 1 scan inspects every decoded JSON string value, including
`model`, using the same threshold/allowlist policy and exact token ownership
checks as substitution. JSON escapes cannot conceal text from this scan.
Any remaining accepted, non-allowlisted span blocks preparation with a static
422 `protection_blocked` JSON error, including for `stream: true`. This applies
to every scanned string value, including `model`; the guard does not rewrite
model identifiers. Allowlisted or below-threshold detections do not block.
After successful preparation the exact guarded bytes are sent upstream with
`stream: false`. All supported assistant content and refusal fields in every
choice are restored before JSON or buffered SSE delivery.
Detector failures return 503 `detection_failed`; foreign canonical placeholders
return 400 `invalid_request`. Selecting a persistent
session while the vault is locked returns **423** `vault_locked`.
`POST /shield/sessions` accepts an empty object or no body, rejects extra fields
including credentials, and creates a reusable session only when the vault is unlocked.
Local detection/substitution without upstream calls are available at
`POST /shield/analyze`. Protected forwarding, restoration and buffered SSE are
available at the chat endpoint. `/docs` and `/openapi.json` expose the contract.

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
unlock. Startup lifespan authenticates the vault when persistence is enabled.
A supplied unknown ID returns 404; an expired ID is deleted and returns 410 on
that access. Once cleanup removes an ID, later lookups return 404. Supplied IDs
never silently fall back to ephemeral sessions. A valid selected session reaches
the current 503 protection scaffold. Session headers are returned on successful
creation/metadata responses; error responses expose no session header.

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

`ChatCompletionResponse` defines the following fields for upstream
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

The proxy fetches the full upstream answer with `stream: false`, restores it, and
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
| 409 | `session_busy` |
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
protection guard and upstream errors are exercised by the current chat route.
Provider timeouts return 504; request-budget exhaustion returns 408.
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


## Reusable session endpoints

With `sessions.persistent_enabled: true`, startup prompts locally for a passphrase
and initializes a genuinely empty vault or authenticates its existing unlock
verifier. Startup aborts on wrong/missing credentials or corrupt metadata; a
failed unlock never resets a vault. KDF/unlock work runs off the event loop.
Default startup with persistence disabled creates no vault files. Credentials
never arrive in HTTP requests, and the application releases its passphrase
reference after startup authentication or failure.

| Method and path | Success | Returned metadata |
| --- | --- | --- |
| `POST /shield/sessions` | 201 | `session_id`, `created_at`, `expires_at` |
| `GET /shield/sessions/{session_id}` | 200 | Same fields |
| `DELETE /shield/sessions/{session_id}` | 204, empty body | None |

Creation and metadata reads return `X-Shield-Session`. Timestamps are UTC ISO 8601
values in responses; the vault stores integer Unix seconds. Configured TTL is
rounded up to whole seconds, with a minimum of one second. Reading or using a
session does not extend its TTL. All three endpoints return 423 when persistence
is disabled or the vault is locked. Unknown/deleted IDs return 404. Expiry is
inclusive at admission; an idle lookup of a retained expired row deletes it and
returns 410. An already admitted request may finish through restoration.
Startup also prunes expired rows, so an already-pruned ID returns 404. Error
messages never echo the selected ID. Wrapped-key integrity failures return a
static 500 and do not treat edited timestamps as trusted expiry instructions.

Deletion cascades to mappings in the same transaction. No unwrapped HMAC keys are
cached across operations; scoped request references are released in `finally`.
Deletion does not prevent recovery from old database copies or guarantee memory
erasure. Active chat requests use the guarded upstream client and exclusively reserve
their selected session; competing metadata, deletion and chat requests return
409 `session_busy` immediately. Retry after the active request completes. Busy
sessions are skipped by expiry pruning, with expiry enforced on the next idle
access. Other session IDs and ephemeral requests remain independent. Shutdown
blocks new admissions while existing request scopes finish.


Persistent service startup requires exclusive OS ownership of its configured
vault. A second owner (including another worker process) fails startup. The lock
file is retained on disk; do not unlink it while any owner could be running.
This coordinates application services, not arbitrary programs editing SQLite.
No lock is needed or acquired for default ephemeral requests.


## Local analysis endpoint

`POST /shield/analyze` accepts `Content-Type: application/json` and exactly one
required field: `text`, a string (including empty text). Non-string text, extra
fields, body session IDs, credentials, metadata, messages and client-selected
models are rejected with 400. Session selection uses the same strict
`X-Shield-Session` header rules as chat. Request-size and timeout limits apply.

```json
{"text":"Email synthetic@example.test."}
```

Successful responses contain:

| Field | Meaning |
| --- | --- |
| `sanitized_text` | Original text with accepted spans replaced by registered tokens |
| `spans` | Final redaction spans: original Python-string `start`/`end`, `entity_type`, `confidence`, `stage` |
| `report` | Protected counts/total, separate allowlisted-disclosure counts/total, and unknown-token count (zero until restoration) |
| `preserved_token_count` | Exact existing session-token occurrences left unchanged |
| `below_threshold_count` | Unique candidate detections discarded by the confidence policy |
| `preview_only` | `true` for ephemeral operation; `false` for an explicit persistent session |
| `session_id` | Present only when an explicit persistent session was selected |

These spans describe newly replaced intervals, not every raw candidate or
allowlisted decision. Coordinates always refer to the submitted text, even when
replacement lengths differ or text contains emoji/combining characters. Existing
placeholders are counted separately. Allowlists can intentionally leave sensitive
text visible; detector misses can also remain. Analysis is not a guarantee of
complete PII removal.

Default requests require no vault and return no reusable ID or session header.
A new in-memory key/mapping store is used for every request and closed before a
success result leaves the worker. Ephemeral tokens are preview-only: submitting
one in a subsequent request without its original session is an unknown-token
error. With an explicit persistent ID, mappings are encrypted and committed before
success; later analyses reuse their full identities and first observed spellings.
Success returns `X-Shield-Session` only for that explicit selection. Every success
also returns `Cache-Control: no-store`. Keys, digests, original mapping values and
internal ephemeral IDs are never response fields.

Canonical token syntax is reserved as described in [substitution](substitution.md).
Unknown/cross-session canonical placeholders return static 400 `invalid_request`.
Locked/disabled persistence returns 423, unknown/deleted IDs 404, expired IDs 410,
and competing active-session operations 409. No failure silently creates an
alternative persistent or ephemeral session. Error responses return no session
header. Missing/unloadable models and known sanitization failures return safe
503 `detection_failed`; unexpected internal failures return a static 500.

The detector is initialized lazily with the configured recognition and span
policy, once per app after successful loading. Model loading and analysis run
in a worker. No runtime downloader or provider request is used. App construction,
config loading, startup with persistence disabled and malformed-body rejection do
not load a model. The CLI uses the pinned `stage1` optional dependency; install it
with `uv sync --locked --extra stage1` before using real analysis.

On timeout or task cancellation, the job signals cancellation and closes its
published session state. It blocks subsequent mapping operations and response
publication. The route also monitors ASGI disconnects; a dropped connection does
not otherwise cancel a normal FastAPI JSON route automatically. Disconnects discard
the result and trigger the same cleanup. CPU/model work and an in-flight SQLite
transaction cannot be forcibly interrupted. The worker retains its persistent
lease until it drains, so competing operations can temporarily continue returning
409 after the HTTP request is gone. Successful earlier persistent allocations
remain under normal TTL/deletion policy. This is reference cleanup, not secure
memory erasure or a guarantee that a running worker has stopped retaining source
text. No upstream request is made by this endpoint on success or failure.

## Upstream transport

Phase 4 task 4 adds `shield/upstream.py`. `UpstreamClient(config, api_key)` is an
async context manager; use `await client.complete(prepared.payload)` only after
`prepare_chat` succeeds and while its active session remains open. It sends the
exact guarded bytes to `<upstream.base_url>/chat/completions`, preserving a custom
base path. It does not accept downstream headers, invoke detection, open a vault,
or own a session. The public chat route calls it only after successful preparation
and retains the active session through fetching and restoration.

HTTPS uses normal certificate and hostname verification. HTTP remains available
for the configured local fake upstream; HTTP does not provide TLS. Environment
proxies and environment TLS overrides are disabled (`trust_env=False`), and
redirects are rejected. Only the runtime provider key supplies the optional
Bearer header; absent keys omit Authorization, supporting the local fake and
unauthenticated endpoints. Provider authentication failures return a static error.

`upstream.timeout_s` sets connect, read, write and pool timeouts and an overall
async deadline for sending, buffering, and validating the response. An absolute
clock check rejects success if synchronous JSON validation runs past that deadline;
synchronous work cannot be preempted mid-validation. Cancellation
propagates without conversion; context exit closes the pooled HTTP client.
The caller must retain its session through the eventual send and restoration.

The retry bound is **zero retries**, or one attempt per call. No timeout,
connection error, 429 or 5xx is retried. A failed POST can still have been accepted
or billed, so automatic retries require a future explicit idempotency and cost
policy. Detector/vault failures occur before client invocation, never inside a
retry loop. No retry setting is exposed by the current client.

Only HTTP 200 with a supported `ChatCompletionResponse` is accepted. Timeouts
raise static `upstream_timeout` (504); other transport/status/response-validation
failures raise static `upstream_error` (502). Error bodies, exception details,
provider headers and retry hints are never returned or logged by the client.
HTTPX/httpcore records are suppressed within client sends/close to avoid leaking
URLs, headers or exception details even with DEBUG logging enabled. Successful
responses remain untrusted until restoration; never log their body.

Tests use ASGI and mock transports with synthetic values; no provider calls are
needed. Injected transports are server-side test facilities, not HTTP options.

## Response restoration

Phase 4 task 5 adds `rehydrate_text(text, active_session)` in
`shield/rehydrate.py`. It returns a `RehydrationResult` with restored `text`,
`exact_count`, `variant_count`, and their sum `restored_count`. Text is excluded
from repr. Callers must keep the session open throughout restoration and handle
`RehydrationError` as a failure; its message never contains source or vault text.
Public chat integration restores all choices before JSON/SSE delivery.

Exact uppercase bracketed tokens are looked up first. Remaining matches accept
ASCII case changes, `_`, `-`, or whitespace separators, dropped square brackets,
and line wrapping within labels or suffixes. Balanced square brackets may have
inner whitespace; single/mismatched brackets are not repaired. Markdown wrapping
and trailing straight/curly apostrophe possessives remain around the restored
value. Ordinary horizontal spaces inside a suffix are not accepted, avoiding
accidental consumption of prose following a bare token.

Every candidate must resolve to a complete canonical type/suffix pair registered
in the current session. Token metadata must agree with its type and full digest.
The original first-observed spelling is restored; persistent reads use existing
authenticated vault decryption. A typed exact lookup API was added to ephemeral
sessions to provide the same session-scoped interface without SQLite access.
Unknown pairs and pairs from another session remain unchanged. No fuzzy matching,
Unicode lookalike correction, prefix matching, or guessed-character repair occurs.
Bare matches require Unicode word boundaries, so token-like parts of longer
words/identifiers are not restored.

Both matching passes inspect the original response, and replacements are applied
once in source order. Inserted original values cannot trigger another restoration,
even when an original itself contains a registered token. Unknown-token occurrences are counted in the response report. This helper does not call the
provider, own a session, or log/store response text.

## Buffered chat delivery

Phase 4 task 6 connects preparation, async HTTP, restoration and delivery. Both
client modes send a non-streaming upstream request; downstream `stream_options`
are omitted from that payload. The active session remains held through network
work, restoration of every choice's `message.content` and `message.refusal`, and
serialization of the complete delivery body. Null content/refusal remains null
in JSON; usage and choice indices are preserved.

For `stream: true`, the response has `Content-Type: text/event-stream`. Each
choice receives a `chat.completion.chunk` containing its assistant role and text
(or refusal) delta, followed by a chunk with empty delta and its finish reason.
The upstream completion ID, creation timestamp, model, fingerprint, service tier
and choice indices are preserved. When requested with
`stream_options.include_usage: true` and supplied by the provider, a final usage
chunk has empty choices. The last frame is `data: [DONE]`.

Frames use the typed chunk's JSON serializer, so newlines and quotes in IDs or
text cannot inject SSE frames. Delivery is buffered, not live provider token
streaming: first-byte latency includes the entire upstream answer, restoration
and serialization. Provider usage describes tokenized prompts and responses,
not the restored text. No body or SSE success headers are committed until this
work succeeds. Guard, detector, vault, transport and restoration errors return
ordinary JSON errors even if the client requested streaming. Restoration failures
return a static 500; upstream errors/timeouts return 502/504.

Worker-owned session scopes span the async fetch and restoration. HTTP runs on
the application's event loop while the worker retains the lease. Cancellation
or disconnect signals the worker, closes its published session state, and cancels
the async fetch. If transport cancellation cleanup is still running, the worker
keeps the persistent lease until the actual coroutine drains; competing session
operations continue to return 409. Successful serialization finishes before
session cleanup and before any response headers. Report headers include protection, disclosure and unknown-token counts.

`create_app(upstream_transport=...)` is a server-side test hook for the local fake
or an HTTPX mock transport; it is not a request/configuration field. Tests never
need provider access. For a manual local demo, start `python -m
shield.fake_upstream` on port 8001, then the shield on port 8000 using the default
upstream URL. The fake's canned response contains fixed synthetic tokens; only
actual current-session tokens are restored. Unknown fixed tokens remain visible.

## Protection report headers

Phase 4 task 7 returns `X-Shield-Report` on successful chat responses, identically
for JSON and buffered SSE. The value is compact JSON, using `ProtectionReport`:

```json
{"protected_counts":{"PERSON":2},"allowlisted_disclosure_counts":{"EMAIL_ADDRESS":1},"unknown_token_count":3,"protected_count":2,"allowlisted_disclosure_count":1}
```

`protected_counts` counts original message spans actually replaced, rather than
unique mappings or restored occurrences. `allowlisted_disclosure_counts` counts
intentional disclosures in message content and other outgoing fields, including
`model`. For each message, preparation and final-guard disclosure spans are
reconciled in original-text coordinates using replacement intervals. The shared
overlap and visibility policy counts each disclosure group once, preserving
partially visible originals and disclosures newly recognized after substitution
changes detector context. Other fields use final-guard counts tracked separately
by JSON location. Coordinate metadata remains internal; headers contain counts only. Confidence thresholds and allowlist rules
remain the same as detection. These counts are not a guarantee of complete
PII detection. Totals are the sums of each map.

`unknown_token_count` counts unresolved token occurrences across every choice's
content and refusal text, with repeated occurrences counted separately. Counted
forms include complete recognized-label/suffix pairs in the supported exact or
formatting-variant syntax that have no active-session mapping. Simple bracketed
unknown ASCII labels (1–32 letters/digits starting with a letter) followed by an
underscore, space or hyphen and a 4–32 character Base32 suffix are also counted.
Malformed/incomplete token shapes and arbitrary bare unknown-label identifiers
are outside this counting grammar. Such text remains unchanged too. Unknowns
are counted from original response text, so inserted originals containing token
literals are neither counted nor rescanned. Exact matches are counted once,
never again as formatting variants. The rehydration result exposes this count;
restoration aggregates it across fields and choices before delivery.

The report contains no plaintext, tokens, mapping digests, internal session IDs,
provider data or credentials. `X-Shield-Session` is returned only when the caller
explicitly selected a valid persistent session. Ephemeral requests never receive
an internal ID. Errors do not return chat report or session headers. All headers
are constructed after complete restoration and serialization; ephemeral cleanup
finishes before success headers are emitted, including for SSE.

## Private metrics and logging

Phase 4 task 8 adds `shield/metrics.py`. The CLI emits one JSON `request_finished`
event through the `shield.metrics` logger at INFO after each HTTP request ends.
When embedding `create_app`, configure this logger at INFO with your host's log
handler to collect events. Metrics do not open files or contact an exporter.
Non-HTTP lifespan events are not request metrics.

Each event contains only these fields:

- `event`: fixed `request_finished`.
- `endpoint`: fixed `chat`, `analyze`, `health`, `sessions`, or `other` category.
- `status`: actual HTTP status once headers start, or null before headers.
- `outcome`: `success`, `error`, `cancelled`, or `disconnected`.
- `duration_ms`: elapsed monotonic time through delivery/cancellation.
- `error_code`: an approved `ErrorCode`, or null.
- `report`: the typed protection report, only for successful chat/analysis requests.

Reports contain protected, intentionally disclosed and unknown-token occurrence
counts. Failed or abandoned requests do not publish partial protection reports.
An exception after 200 headers is recorded as an error with status 200, since
already sent headers cannot be changed. Cancellation is recorded promptly even
when a worker retains its lease while draining; it never emits a second event.

Request-local context propagates into processing workers and async upstream
work. Concurrent requests have independent accumulators. Error codes accept only
the enum; protection reports are reconstructed from explicit fields and validated
before a plain count snapshot is retained. Free-text values, tokens, digests,
request IDs, session IDs, model names, URLs, headers, input/output bodies,
exception details, provider error bodies and reviewer reasons have no metrics
fields. The logger receives JSON serialized from this fixed schema, with no
exception traceback attached. A failed metrics sink does not replace a response.

The supported CLI starts Uvicorn at INFO with `access_log=False`; access logs can
otherwise expose sensitive URLs, queries and session identifiers. No body logging
middleware is installed. HTTPX/httpcore logs stay suppressed during provider
sends/cleanup, and Presidio source-word logging is disabled during detection.
If embedding the app in another server, disable that server's access/body/TRACE
logging too: application middleware cannot control host logs emitted outside it.

Static exception handling surrounds request limits as well as routes, covering
upload failures and errors during response delivery without exposing exception
strings. Upstream failures remain fixed 502/504 errors; unsupported input remains
400; detector/vault failures never become upstream retries. No reviewer component
is installed yet, and no storage or logging API accepts its free-text reasons.
Future reviewer integration must reduce failures to approved codes and counts.
