# Local contextual reviewer setup

Phase 5 task 1 provides a local Ollama/LangChain adapter and a measured latency
baseline. Task 2 adds the masked-text handoff and source map described below.
The first five tasks provide the components; task 6 connects them to public
chat/analysis modes and cached health availability. Task 3 adds structured validation and merged coordinate plans, and task 4
adds an enforced additive merge and adversarial document/reviewer checks.
Task 5 adds bounded failure-policy orchestration and outcome reporting. Public
mode integration and final guard orchestration are described in the final section.

## Reproducible installation

The target machine already had Ollama CLI/server version **0.9.0** installed.
The implementation started a server bound to `127.0.0.1:11434` and downloaded
`llama3.1:8b`. Model files are outside the repository in a temporary store:

```sh
OLLAMA_HOST=127.0.0.1:11434 \
OLLAMA_MODELS=/private/tmp/pii-shield-ollama-models ollama serve
```

Keep that process running in a terminal; it is not installed as a login service.
In another terminal:

```sh
OLLAMA_HOST=127.0.0.1:11434 ollama pull llama3.1:8b
uv sync --locked --extra stage1 --extra stage2 --inexact
.venv/bin/python scripts/benchmark_reviewer.py --model llama3.1:8b \
  --samples 5 --timeout 60 --output /private/tmp/reviewer-latency.json
```

Temporary model files may be removed by the OS; rerun the pull if needed. For a
permanent model store, set `OLLAMA_MODELS` to your chosen directory when starting
the server. The adapter does not pull, start, upgrade, or configure a service at
request time. The download is about 4.9 GB. No document text is sent while pulling.
The default review model remains `detection.stage2_model: llama3.1:8b`.

`stage2` is an optional dependency extra, pinning the four direct integrations
listed below, including `langchain-ollama==1.0.1`.
`uv.lock` pins all transitive versions and hashes; the measured environment used
`langchain-core==1.8.4`, `ollama==0.6.3`, and `langsmith==0.16.0`.
The adapter follows the [official ChatOllama integration](https://reference.langchain.com/python/langchain-ollama/langchain_ollama/chat_models/ChatOllama).

## Interface and privacy boundary

`shield.detect.stage2.Reviewer` exposes `available()`, `review(masked_text)`, and
`aclose()`. `OllamaReviewer(model, timeout_s=10)` is an async context manager.
Input and output use `SecretStr` to avoid accidental repr logging. Output is
**untrusted JSON text**, not accepted detections; the validation layer below must
check exact text/positions and map offsets. The prompt asks for spans without free-text reasons.
The adapter does not store source text, model output, or reviewer reasons.

The endpoint is fixed at `http://127.0.0.1:11434`; environment host/proxy settings
cannot redirect it. It checks installed model names and rejects remote/cloud
manifests and cloud model tags before inference. Redirect following is disabled.
A static local Authorization value overrides the SDK's otherwise automatic
`OLLAMA_API_KEY` forwarding. This is not a credential or a remote authentication
attempt. The local Ollama server must be trusted; this adapter is not a sandbox
for a malicious server that pretends a remote model is local.

Global LLM caching is explicitly disabled with `cache=False`. Inference runs in
a clean context so inherited run collectors/callback managers cannot capture text.
LangSmith tracing is explicitly disabled per invocation, callbacks are empty,
verbose output is off, and LangChain global DEBUG mode causes a static failure
before the prompt is passed to LangChain. HTTPX/Ollama transport logs are suppressed
within review/availability operations. A caller should not wrap review in tracing
instrumentation that records arguments before this boundary.

`available()` performs only local `/api/tags` and `/api/show` checks. It does not
warm a model or guarantee subsequent inference. Review uses temperature 0, seed 0,
4096 context tokens, a 256-token generation cap, JSON format, and a five-minute
keep-alive. A total async deadline and client timeouts apply; exceptions become
`ReviewerUnavailable` with a static message. Cancellation propagates. Context exit
closes both LangChain-owned Ollama clients (via tested, pinned SDK internals).
The validation layer enforces schema/offset checks and a default output-byte cap.
Task 5 adds bounded transport and failure-policy handling below. Raw adapter
results must never be used directly for redaction.

## Measured baseline: 2026-11-21

[Aggregate measurement artifact](benchmarks/stage2-local-2026-11-21.json)
records model digest, software versions, machine information and all durations.
No prompts, output text, or reviewer reasons are exported. Input is a fixed,
132-character synthetic paragraph containing placeholders only.

| Measurement | Result |
| --- | --- |
| Machine | Apple M1 Pro, arm64, 16 GiB RAM |
| Model | llama3.1:8b, digest 46e0c10c039e… |
| First call, including adapter/import/model load overhead | 8.145 s |
| Warm calls | 5 |
| Warm median | 4.346 s |
| Warm p95, nearest rank | 4.471 s |
| JSON objects containing a spans array | 6 / 6 |

With five warm samples, p95 is the maximum observed warm duration. This is a small
latency smoke benchmark, not a fidelity evaluation or a throughput guarantee.
The model was explicitly unloaded before this final-adapter run; OS/filesystem
and model initialization caches may still have been warm. An earlier
[initial provisioning run](benchmarks/stage2-initial-load-2026-11-21.json) took
24.845 seconds on its first call (warm median 4.826 s). That earlier run preceded
the cache/context privacy fixes, with no global cache or collector configured.
The initial call exceeded the configured 10-second review timeout. A cold model
will need explicit warm-up or a timeout decision when Stage 2 is integrated;
this task does not silently increase the application's setting. The benchmark
uses 60 seconds to measure cold loading. Models may unload after five minutes,
so later calls can incur cold latency again. Longer inputs/outputs may be slower.

## Masked handoff and source map

Phase 5 task 2 adds `shield.detect.contextual.review_texts(texts, session,
detector, reviewer)`. The caller owns the active session and loaded detector;
the helper runs the existing Stage 1 detection/policy/substitution over the full
batch before any reviewer call. Unknown canonical tokens anywhere in that batch
fail preflight before allocation or review. Only the resulting sanitized strings,
wrapped in `SecretStr`, are passed to `reviewer.review`. Raw originals, source
maps, mappings and session identifiers are never reviewer arguments.

The returned `ContextualReview` contains the unchanged `stage1` substitution
result, its `source_map`, and secret `raw_output`. Raw output remains untrusted;
no additions are accepted and no Stage 1 decision can be modified through this
helper. Text-bearing fields are excluded from repr and model dumps. Reviewer
failures have the static `ReviewerUnavailable` message; cancellation propagates
and prevents remaining messages from being submitted. CPU detection is synchronous
in this helper; later route integration must retain the established worker-owned
session lifecycle rather than calling expensive NLP on the event loop.

Every substitution result now has an internal `SourceMap`. It stores only original
and masked character lengths and frozen, contiguous coordinate pieces. It holds
no original text, token strings, keys or IDs and is excluded from substitution
serialization. This extends the Phase 1 half-open Python-string span convention;
there was no prior source-map implementation to replace. Offsets count Unicode
code points, including combining marks, not bytes or UTF-16 units.

`source_map.to_original(start, end)` returns an exact original interval only when
the entire nonempty span lies in unchanged text. It returns `None` if the span
intersects a generated placeholder, an input placeholder already registered in
the session, or crosses a masked interval. Equal-length substitutions remain
unmappable. Exact boundaries just before/after placeholders are valid. Invalid
bounds and malformed source-map construction raise static `SourceMapError`.
Empty inputs have an empty map. Mapping remains correct after multiple token
expansions/contractions, repeated tokens and Unicode prefixes.

This strict map is for future reviewer additions, which must refer to intact
source text. It intentionally differs from the gateway's permissive interval
projection used solely to reconcile partially visible allowlist disclosures.
The validation layer below checks schema, exact text, bounds, unambiguous mapping
and original text equality before accepting any contextual span. Public chat and
analysis behavior remain unchanged until mode orchestration is connected.

## Structured output validation and merging

Phase 5 task 3 adds `validate_review(original_text: SecretStr, review, policy)`
in `shield.detect.review_validation`. `review_and_resolve_texts` composes the
masked handoff and validation for a batch. The caller retains the original
snapshot and active session. Neither helper is connected to HTTP routes yet.

The required output schema is a strict JSON object containing only `spans`:

```json
{"spans":[{"entity_type":"CONTEXTUAL","text":"the only cardiologist","start":0,"end":21,"confidence":0.95}]}
```

Entity types use the supported enum, including `CONTEXTUAL`. Every candidate
requires a string quote, integer offsets, and finite confidence in [0, 1]. Boolean
or string offsets are rejected. Optional `reason` text is accepted only as a
secret field, never used, logged, exported or retained in validated results.
All other fields are rejected. The Ollama prompt now requests confidence and
uses `CONTEXTUAL` for identifying descriptions.

Malformed JSON, duplicate keys, nonstandard numeric constants, missing required
fields and schema violations invalidate the entire review with a static
`ReviewerOutputError`. Validation errors and input text are never logged.
Once the schema is valid, individual candidates are discarded if their range is
empty/out of bounds, quoted text does not equal the precise masked slice, their
span intersects/crosses any placeholder, or the mapped original slice differs
from the quote. There is no quote search, normalization, fuzzy match or offset
repair. Source metadata is revalidated and its unmodified regions must agree
with the supplied original snapshot.

Mapped candidates are tagged Stage 2 and passed through the shared confidence,
exact-allowlist, duplicate and transitive-overlap policy. Accepted Stage 2 spans
are merged with the already accepted Stage 1 spans; Stage 1 is not re-thresholded
or re-allowlisted. The returned `ValidatedReview` contains only accepted addition
coordinates, a merged `ResolvedDetections` plan/report, and a rejected-candidate
count. Discard counts concern invalid ranges/quotes/maps; below-threshold counts
are separately carried by the resolved plan. Duplicate removal does not increment
the invalid-candidate count. Raw quotes and reasons are not present in results.

Validation allocates no tokens and does not apply additional substitutions yet.
The `CONTEXTUAL` type has its own token label, text normalization and HMAC domain,
so later substitution can use the existing session/vault machinery. Stage 1's
recognizer registry remains unchanged. Public mode routing, second-stage masking,
final guard orchestration and failure-policy behavior follow in later tasks.

## Additive-only review and instruction boundaries

Phase 5 task 4 makes `merge_additions(stage1, additions)` the merge boundary.
It validates provenance (Stage 1 baseline, Stage 2 additions) and rejects overlap
with the authoritative baseline independently of the source map. Only Stage 2
spans are merged with one another; baseline spans keep their exact coordinates,
entity type, confidence and stage. Adjacent additions do not expand a baseline
span. Empty reviewer output leaves the baseline intact. A changed threshold or
allowlist applies to proposed additions only, never to accepted Stage 1 spans.
Malformed or overlapping merge inputs fail with the static `ReviewerOutputError`.

The Ollama adapter sends exactly two messages: the fixed system policy and one
human data message serialized as `{"document": "...masked text..."}`. Quotes,
newlines, forged chat-role arrays and closing delimiters in the document remain
inside that JSON string. The system policy specifies that offsets and quotes
refer to the decoded `document` value, not JSON escape bytes or the outer envelope.
It asks only for additions and explicitly forbids treating document instructions
as changes to roles, thresholds, output format or existing placeholders.

Safety does not depend on the model obeying that prompt. Reviewer JSON cannot
set policies or replace Stage 1 lists: unknown control fields fail the strict
schema, and candidates over/through placeholders fail exact source mapping.
Reasons are data, never evaluated instructions. In-range additions still require
exact masked/original text equality and the configured confidence/allowlist checks.
A model can miss contextual PII or propose unnecessary additions; this boundary
guarantees preservation of Stage 1 rather than perfect Stage 2 detection.

Offline adversarial tests exercise empty responses to malicious documents,
reviewer removal/allowlist/threshold commands, high-confidence placeholder
reclassification, cross-placeholder proposals, and role-delimiter injection in
the actual adapter's message construction. They verify application invariants,
not claims about a particular model's behavior against every injection. The
latency artifacts above describe the earlier task 1 prompt; rerun the benchmark
if measurements for this hardened prompt/envelope are needed. No model calls are
made by these tests. Public mode integration is described below.

## Bounded review and failure policy

Phase 5 task 5 adds `review_with_policy(texts, session, detector, reviewer, config)`
in `shield.detect.review_policy`. It returns `ReviewBatch` with Stage 1 results,
validated coordinate plans, and a typed `Stage2Outcome`. This is the entry point
for Stage 2 mode orchestration, now used by public chat and analysis in task 6.

`detection.stage2_max_output_bytes` defaults to **65536** (strict positive integer).
Pass this value to `OllamaReviewer(max_output_bytes=...)` too. The adapter bounds
preflight metadata and inference response streams before the Ollama SDK/LangChain
can accumulate them. It requests identity encoding and rejects compressed bodies,
counts actual bytes even without a truthful Content-Length, and closes a stream
on a limit violation. This cap includes NDJSON protocol overhead, not just model
text. The 256-token generation setting is additional, not a substitute for this
transport cap. The validator checks UTF-8 size before JSON parsing. Policy also
limits the aggregate JSON text bytes across all messages; character count alone
is insufficient for Unicode text.

`stage2_timeout_s` bounds the entire contextual batch, including validation,
after Stage 1 sanitization. Both async cancellation deadlines and absolute clock
checks prevent late synchronous validation from publishing success. The adapter
retains its per-call timeout. These are cooperative limits, not preemption of
synchronous work or proof that the daemon immediately stopped generation.

On any contextual outage, timeout, size violation or invalid schema:

- Default `on_stage2_failure: fail_closed` records a typed failed outcome and raises
  the static 503 `reviewer_unavailable` category before any provider continuation.
- Explicit `fail_open` discards **all** partial contextual additions and returns
  Stage 1-only plans for the whole batch. It never mixes successful earlier Stage 2
  messages with fallback messages while claiming Stage 1-only behavior.

Stage 1/detector/storage failures are outside this fallback path. Lost session
state, guard/session errors and caller cancellation cannot become successful
fail-open continuation. The caller still owns session lifetime and must run the
final guard before forwarding fallback payloads.

Delivery accepts the batch outcome via `completion_response(..., stage2=outcome)`.
Successful JSON and SSE responses receive `X-Shield-Stage2: complete` or
`X-Shield-Stage2: stage1_fallback`. Fallback additionally returns
`X-Shield-Stage2-Failure` with one fixed category: `timeout`, `output_limit`,
`invalid_output`, or `unavailable`. Failed outcomes cannot be passed off as success;
they raise the static reviewer error and do not emit success/report headers.
Metrics record the same typed `stage2` status/failure object, including failures,
without reviewer text or exception details. Requests that never attempt review
retain their existing headers and metrics (no Stage 2 outcome field).

The policy and delivery primitives are tested together using controlled local
routes and fake reviewers, including JSON/SSE error boundaries. The public mode flow now selects review only in Stage 2 modes, passes configured
adapter limits, preserves worker-owned sessions, applies merged plans and runs
the final outgoing guard.

## Public mode orchestration

Phase 5 task 6 connects `/v1/chat/completions` and `/shield/analyze` to mode
selection via `shield/processing.py`:

| Mode | Processing |
| --- | --- |
| `fast` | Stage 1 only; never constructs a reviewer, checks its availability, or imports the optional LangChain runtime |
| `balanced` | Stage 1 followed by bounded, validated contextual review; default threshold 0.5 |
| `paranoid` | The same two stages; default threshold 0.3 |

An explicit threshold still overrides the mode default. Balanced remains the
configuration default, so install the `stage2` extra and run the local model for
normal operation. Missing optional dependencies, model outages, invalid output,
limits and deadlines follow `on_stage2_failure` (default fail-closed). Fast mode
needs only the Stage 1 dependencies/model and remains independent of Ollama.

NLP and token allocation remain in a worker that owns the request/session scope.
Stage 2 HTTP runs on the application event loop, using precomputed Stage 1 results
so heavy NLP is not repeated there. Each request creates its reviewer lazily and
closes it before final application. Factory/close failures enter the contextual
failure policy. Cleanup errors cannot replace cancellation or an earlier guard,
session or review error; success is checked against the absolute deadline after
cleanup as well as after validation.

Only after the entire batch succeeds are accepted Stage 2 additions applied in
original coordinates. Stage 1 token identities are reused; new contextual
mappings are registered/committed before forwarding. Explicit fail-open uses only
the original Stage 1 batch. Chat then serializes the final request once and runs
the Stage 1 guard over every decoded string in those exact bytes, in all modes
and on fallback. Guard failure sends zero provider requests. The same guarded
bytes are sent upstream, followed by full restoration and JSON/buffered SSE
serialization before the worker releases its session.

Analysis returns combined spans with original source coordinates and their
`stage1`/`stage2` provenance, final sanitized text and combined counts. It makes no
provider calls; the provider-payload guard belongs to chat's forwarding boundary.
Both endpoints return the typed Stage 2 outcome/fallback headers and metrics.
Fast responses have no Stage 2 outcome headers. A cancelled/disconnected request
cannot forward a new payload; its lease stays held until any in-flight reviewer
or HTTP cleanup actually drains.

Health's `stage2_available` is a cached observation of the latest completed
review: initially false, true after valid review, false after review failure or
fallback. Health never constructs a reviewer or performs a model/network probe.
This can become stale if Ollama stops after the last request and says nothing
about model accuracy. Cancellation does not reclassify model availability.

The default 10-second contextual budget covers the whole sequential message
batch, including reviewer cleanup. Multiple warm calls or cold model loading can
exceed it; the historical single-paragraph benchmark does not guarantee a
multi-message request fits. Configure the timeout deliberately for your workload,
warm the model, or use fast mode; the application does not silently extend it.

`create_app(reviewer_factory=...)` is a server-side injection hook. The factory
receives validated `DetectionConfig` and should return a fresh request-owned
reviewer implementing `review` and `aclose`. Tests use local doubles, including an
empty default reviewer fixture for existing API regressions; the production
default remains `OllamaReviewer` with fixed localhost endpoint and configured caps.
