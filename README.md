# PII Shield

A planned single-user localhost proxy that detects sensitive text, replaces it
with session-specific tokens before an upstream Chat Completions call, and
restores known tokens in the response. See [the implementation plan](IMPLEMENTATION_PLAN.md)
and [the accepted design decisions](docs/decisions/001-session-storage-and-buffered-sse.md).

## Current status

Phase 1 tasks #1–6 are implemented: the package scaffold, shared typed domain
contracts, validated configuration, strict Chat Completions schemas, safe errors,
runtime credential loading, request limits, locked-vault checks, and a separate
fake upstream with synthetic fixtures.
Phase 2 tasks #1–6 add an opt-in SQLite storage module with a versioned schema,
transactional ciphertext inserts, full-digest constraints, Argon2id key derivation,
an authenticated unlock verifier, and AES-GCM entry
encryption with authenticated reads. Ephemeral requests receive independent
memory-only HMAC keys. Optional persistent sessions support startup unlock,
creation, lookup, restart recovery, TTL enforcement, and deletion.
See [vault storage](docs/vault-storage.md) for its scope and disk permissions.
Phase 3 tasks #1–7 add explicit local Stage 1 detection with the pinned spaCy
English model, an audited Presidio registry, and a numbered-street address
baseline, labeled birth dates, API keys/secrets, and configurable employee IDs.
Phone regions and location/address coverage are configurable. Shared span policy
validates bounds, filters confidence and exact allowlists, and resolves overlaps
deterministically. Type-specific normalization, HMAC derivation, and atomic
full-digest token allocation are available in [pseudonyms](docs/pseudonyms.md).
[Text substitution](docs/substitution.md) preserves original offsets and exact
registered session tokens. See [Stage 1 detection](docs/stage1-detection.md) for supported types
and coverage limits.
Phase 4 task #1 adds conversation preparation in `shield/gateway.py`, wired into
`/v1/chat/completions`. Every system, developer, user, and assistant message is
sanitized in the active session, including restored PII in prior assistant replies.
Prepared requests preserve generation options and force non-streaming upstream
mode. Client stream preferences remain on the original request for buffered SSE delivery.
Phase 4 task #2 freezes the outgoing JSON bytes after mapping registration and
runs a read-only Stage 1 guard on every decoded string value, including `model`.
Known session tokens are recognized; JSON escapes are decoded before detection.
Persistent allocations are committed before this scan; ephemeral mappings stay
in memory. Phase 4 task #3 blocks remaining accepted, non-allowlisted PII with
422 `protection_blocked`, including PII in the model field.
Phase 4 task #4 adds the separately tested async `UpstreamClient` in
`shield/upstream.py`: verified HTTPS, configured phase and total timeouts,
static errors, response validation, and one attempt per call (no automatic
retries or redirects). It sends the exact guarded JSON bytes. See
[upstream transport](docs/api-contract.md#upstream-transport) for its lifecycle
and cost policy.
Phase 4 task #5 adds `shield/rehydrate.py` for exact and deterministic formatting
variants of known tokens, using only the active session's authenticated mappings.
See [response restoration](docs/api-contract.md#response-restoration).
Phase 4 task #6 connects the protected round trip. Both client modes fetch a full
upstream completion with `stream: false`, restore content and refusal text for
all choices, then deliver JSON or buffered SSE. SSE emits role/text deltas,
finish-reason chunks, optional usage, and `[DONE]`, preserving IDs and choice
indices. First-byte latency includes the full upstream completion and restoration;
usage counts describe the tokenized exchange. Session cleanup completes before
success headers; cancellation keeps persistent leases until HTTP cleanup drains.
Phase 4 task #7 adds `X-Shield-Report` with protected occurrence counts, separate
allowlisted-disclosure counts, and unknown response-token counts. Unknown tokens
stay unchanged; `X-Shield-Session` is returned only for an explicitly selected
persistent session. Both JSON and SSE are fully restored and serialized before
ephemeral state is released.
Phase 4 task #8 adds structured, count-only request metrics and safe exception
coverage for uploads and response delivery. The CLI disables access logs and
emits JSON telemetry without URLs, session IDs, credentials, bodies, or reviewer
reasons. See [private metrics and logging](docs/api-contract.md#private-metrics-and-logging).
Phase 4 task #9 adds `GET /shield/health`, a local liveness and capability snapshot
with ephemeral support, optional-vault lock state, Stage 1 loading state, and
Stage 2 availability. It does not load models or contact upstream services.
See [health status](docs/api-contract.md#health-status).
Phase 5 task #1 adds an optional LangChain/Ollama reviewer interface and a local
latency benchmark. The final adapter measured an
8.14 s first call after model unload and a 4.35 s warm median on this M1 Pro;
the initial provisioning call took 24.85 s. It is not wired into chat yet; see
[local reviewer setup](docs/local-reviewer.md) for installation, privacy controls,
measurement details, and the cold-start timeout limitation.
Phase 5 task #2 adds a Stage 1-masked reviewer handoff and exact source-coordinate
mapping. Placeholder-overlapping spans are unmappable; raw reviewer output stays
untrusted until task #3 validates it. This helper is not connected to chat yet.

## Setup with uv

Use [uv](https://docs.astral.sh/uv/getting-started/installation/).
Python **3.14.8** is pinned in `.python-version`, matching the latest stable release
listed by [Python.org](https://www.python.org/downloads/) when this skeleton was
created on October 4, 2026. The manifest targets the 3.14 series; later Python
series require dependency validation before extending that range.

```sh
uv python install 3.14.8
uv sync --locked
uv run --locked python --version
```

If an older uv reports that no download exists for 3.14.8, update uv using its
original installation method (`uv self update` for standalone installations).
`uv sync --locked` creates `.venv/`, installs this package in editable mode and
installs the default `dev` dependency group. `pyproject.toml` declares dependencies;
`uv.lock` pins their resolved versions and must be committed with manifest changes.
Use `uv add PACKAGE` for new dependencies and `uv add --dev PACKAGE` for development
tools. Use `uv sync --locked --no-dev` for a runtime-only environment.

Commands prefixed with `uv run --locked` use the virtual environment automatically.
To activate it manually in zsh/bash:

```sh
source .venv/bin/activate
```

The dependency set includes FastAPI, Pydantic, Uvicorn, HTTPX, PyYAML, Presidio,
spaCy, cryptography, and Argon2. Development tools include pytest, pytest-asyncio,
Hypothesis, Faker, and Ruff. The optional `stage1` extra installs the pinned
`en_core_web_lg` 3.8.0 model; its wheel and SHA-256 are recorded in `uv.lock`.
Install it before using the detector or running the full test suite:

```sh
uv sync --locked --extra stage1
```

To preserve additional packages already installed in your environment, use
`uv sync --locked --extra stage1 --inexact`. Detection loads the local model
explicitly and never downloads one at runtime. App construction/startup remains
independent of the model until the gateway is wired. Stage 2 integrations arrive
in their own phase.

## Run the scaffold

```sh
uv run --locked pii-shield
# Equivalent:
uv run --locked python -m shield
```

The server binds to `127.0.0.1:8000`. Open `http://127.0.0.1:8000/docs` to inspect
the supported request schema. `/v1/chat/completions` rejects unsupported payloads
with 400 and forwards supported valid requests through the protection pipeline. Requests selecting persistent sessions and all
session endpoints return 423 while the vault is locked. Enable
`sessions.persistent_enabled: true` to collect a non-echoed startup passphrase and
initialize or unlock the configured vault. `POST /shield/sessions` returns 201
with reusable session metadata and `X-Shield-Session`; `GET /shield/sessions/{id}`
returns metadata, and `DELETE /shield/sessions/{id}` returns 204. Unknown IDs return
404; encountering an expired idle session removes it and returns 410. A busy
session returns 409; retry after its active request finishes. `POST /shield/analyze`
now returns a local sanitized preview and original-coordinate spans. See
[the analysis API](docs/api-contract.md#local-analysis-endpoint).
Stop with Ctrl-C.

## Run the fake upstream

```sh
uv run --locked python -m shield.fake_upstream
```

This separate app binds to `127.0.0.1:8001`, matching the example upstream URL.
It accepts JSON at `/v1/chat/completions`, captures exact request body bytes in
memory, and returns a deterministic response containing `[PERSON_7K2Q]` and
`[EMAIL_2M4R]`. It supports multiple choices via `n`; its usage counts are synthetic
zeros. It rejects upstream `stream: true` so tests can catch a proxy that
forgets to request buffered JSON. Request bodies and authorization headers are
not logged; headers are not captured.

Use synthetic inputs only. For example, in another terminal:

```sh
curl http://127.0.0.1:8001/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"synthetic-model","messages":[{"role":"user","content":"Contact [PERSON_7K2Q] at [EMAIL_2M4R]."}],"stream":false}'
```

For tests, `create_fake_upstream(response_factory=...)` accepts a synchronous
function taking `ChatCompletionRequest` and returning `ChatCompletionResponse`.
Inspect `fake.state.captures`, a list of records whose `.body` is the original
serialized JSON, using HTTPX `ASGITransport` to avoid network access. Each app has
its own capture list, including malformed/rejected chat requests. Clear the list
with `.clear()` between cases. Captures are not exported or exposed over HTTP.
See [the fixture guide](eval/datasets/README.md) and
[`test_fake_upstream.py`](tests/test_fake_upstream.py) for controlled response examples.

## Configuration example

The CLI loads `shield.yaml` from the working directory when present; otherwise it
uses built-in defaults matching [`shield.example.yaml`](shield.example.yaml).
An explicit file must exist. For example:

```sh
cp shield.example.yaml shield.yaml
uv run --locked pii-shield
# Or select another configuration file:
uv run --locked pii-shield --config path/to/settings.yaml
```

[`shield/config.py`](shield/config.py) validates every section before server startup.
Unknown fields, duplicate YAML keys, unsupported modes, invalid URLs, nonpositive
timeouts/TTL, and invalid ports fail with field-specific errors that omit input
values. Empty documents are rejected; use `{}` to select all defaults. The server
host must be `127.0.0.1`; `server.port` may be changed. Upstream URLs must use HTTP
or HTTPS without credentials, queries, fragments, or whitespace. The default URL
reserves `127.0.0.1:8001/v1` for the future fake upstream.

`detection.threshold` is optional: `config.detection.effective_threshold` resolves
to fast=0.6, balanced=0.5, or paranoid=0.3 unless an explicit threshold in [0, 1]
overrides it, including zero. Allowlist terms preserve their exact spelling and
must be nonblank strings. Stage 2 model, timeout, and failure-policy settings are
validated but no reviewer is loaded yet.

Vault paths expand `~`; relative paths resolve beside the YAML file. The loader
creates no files or directories and does not open or unlock a vault. Session TTL
is a positive finite number of hours, defaulting to 24. Default sessions must be
ephemeral; reusable sessions require explicit creation. Argon2 parameters
default to 65536 KiB, 3 iterations, and parallelism 4. Loading requires positive
iteration/parallelism values and memory of at least eight times parallelism.

The CLI passes settings and runtime credentials to `create_app(config, credentials)`.
Settings are available as `app.state.config`. Importing `shield.app:app` directly
uses built-in settings without reading YAML or credentials; use the CLI to load
them. Opt-in ASGI lifespan uses the configured persistence settings; detection
and upstream HTTP timeouts are consumed by `UpstreamClient`.

The proxy enforces `server.max_request_bytes` (default **1048576 bytes**, 1 MiB)
before JSON parsing, and `server.request_timeout_s` (default **120 seconds**) from
body upload through response-header creation. Oversized bodies return 413; expired
requests return 408. Actual bytes are counted for chunked or falsely declared
uploads. Invalid, duplicate, or mismatched `Content-Length` values return 400.
Limits also apply to session requests and other HTTP routes. Delivery after
response headers is outside this deadline, including buffered SSE.
The timeout cooperatively cancels async work and runs its cleanup; synchronous
work cannot be forcibly interrupted, and late headers are rejected when it returns.

Selecting `X-Shield-Session` requires an enabled, authenticated unlocked vault.
Without authenticated startup, persistent routes return 423. Default requests
without that header never consult vault readiness. With persistence enabled,
startup initializes or unlocks the vault; creation and lookup expose session
metadata while unknown, expired or deleted IDs fail without replacement.

The CLI reads provider credentials from the environment variable named by
`api_key_env`; a missing key is allowed for this scaffold. Setting
`sessions.persistent_enabled: true` collects a passphrase through a non-echoing
startup prompt and fails if echo cannot be disabled. Lifespan authenticates the
vault before serving and releases the startup passphrase reference. Default
ephemeral operation never prompts. The example
contains no secrets; local `shield.yaml`, `.env` files, vaults and SQLite sidecars,
logs, generated datasets, and evaluation results are ignored by Git.

## Project layout

```text
shield/                 Python runtime package and ASGI scaffold
  detect/               Future detection and span-resolution modules
eval/                   Future detection/utility experiments and plots
  datasets/             Synthetic generators, fixtures, and loaders
tests/                  Future unit, integration, and property tests
demo/                   Future scripted synthetic round-trip demo
docs/decisions/          Accepted architecture decisions
shield.example.yaml     Proposed configuration example
pyproject.toml          Package, dependencies, and tool configuration
uv.lock                 Reproducible dependency resolution
.python-version         Exact interpreter pin
```

The design's `session.py`, `vault.py`, `pseudonym.py`,
`rehydrate.py`, detector modules, and evaluation scripts will be added as their
implementation tasks are completed.

## Shared contracts

[`shield/contracts.py`](shield/contracts.py) defines validated Pydantic models for
detected spans, in-memory token mappings, session metadata, protection reports,
and API error envelopes. Models reject unknown fields and implicit coercion;
Python callers use the supplied enums for entity types, stages, session kinds,
and error codes. [`shield/api.py`](shield/api.py) defines strict HTTP models;
[`docs/api-contract.md`](docs/api-contract.md) lists all supported request/response
fields, buffered SSE behavior, error statuses, and credential handling.

- `DetectedSpan` uses half-open Python string indices (`text[start:end]`), including
  Unicode code points. Call `span.validate_for_text(text)` to check source bounds.
- `TokenMapping` retains the full 32-byte entity digest and first observed spelling.
  The original value is masked during representation and serialization; restoration
  and encryption code must explicitly access `original_value.get_secret_value()`.
  The digest is excluded from serialization. This model is not a vault storage row.
- `SessionRecord` contains metadata only. Persistent records require a timezone-aware
  expiry after creation; ephemeral records have no expiry timestamp and must be
  released by the request lifecycle. No keys are included in this record.
- `ProtectionReport` counts protected occurrences and intentional allowlisted
  disclosures separately by entity type, with derived totals and an unknown-token
  occurrence count. Counts do not establish that undetected PII was removed.
- `APIError` wraps a stable error code and a message. Callers must supply static,
  privacy-safe messages; arbitrary exception and provider text is not sanitized.

Validation exception text hides input values. Structured validation errors can
still contain inputs and must not be logged or returned directly to clients.

## Development checks

```sh
uv run --locked ruff check .
uv run --locked ruff format --check .
uv build
```

Run the full tests with `uv run --locked --extra stage1 pytest`. They cover domain contracts,
configuration validation, strict HTTP contracts, safe errors, credential prompts,
and CLI settings propagation. Use synthetic fixtures and the fake upstream before any
provider smoke test. Future buffered SSE will wait for the complete upstream
answer, and detector misses must be measured rather than treated as a guarantee
that all PII is removed.


## Persistent request coordination

One service process owns a persistent vault at a time. Startup holds an OS lock
in `<vault path>.lock`; starting another owner fails before unlocking. The lock
file contains no secrets, remains on disk, and is released by closing its handle,
including after a process exit. Keep the configured vault in a private local
directory and use one server worker.

`PersistentSessions.use(id)` grants an exclusive request scope without waiting.
Competing calls for that session return `409 session_busy`; other sessions and
ephemeral requests proceed independently. A request admitted before expiry may
finish, including restoration. Pruning skips busy sessions; a subsequent idle
lookup enforces expiry. Shutdown refuses new scopes and releases the vault key
and ownership only after existing scopes exit.

Within a request scope, add new mappings to `active.mappings` and use
`await active.send(callback)` for the future gateway send: it commits pending
mappings before invoking the callback, and never calls it if commit fails. Use
`active.read_mapping(token)` while the scope is held. Keep the scope open through
restoration, then exit to release its key and mappings. Standalone service calls
for that session are competing operations; they cannot reenter an active scope.
The chat route now uses the guarded upstream client and restores the complete response.


## Local analysis

Install the pinned model extra and start the server:

```sh
uv sync --locked --extra stage1 --inexact
uv run --locked --extra stage1 pii-shield
```

Then submit synthetic text without a provider call:

```sh
curl -s http://127.0.0.1:8000/shield/analyze \
  -H 'Content-Type: application/json' \
  -d '{"text":"Email synthetic@example.test."}'
```

The response includes sanitized text, original-coordinate redaction spans,
protection/disclosure counts and `preview_only`. Without a session header,
keys/mappings are request-local and discarded before success returns; those
tokens cannot be resumed. To retain mappings, opt into persistent sessions,
create one, and send its ID in `X-Shield-Session`. Only explicit selections return
that header and a response session ID. Detection is local and loaded lazily on
the first analysis request; no model is downloaded at runtime. Missing models
produce a safe 503 while other local routes can still run. Unknown canonical
input placeholders return 400. The protected chat route uses the same detector before forwarding.
