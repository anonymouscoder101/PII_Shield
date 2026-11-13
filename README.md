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
Phase 2 tasks #1–3 add an opt-in SQLite storage module with a versioned schema,
transactional ciphertext inserts, full-digest constraints, Argon2id key derivation, an authenticated unlock verifier, and AES-GCM entry
encryption with authenticated reads.
See [vault storage](docs/vault-storage.md) for its scope and disk permissions.
The proxy's `/v1/chat/completions` validates requests and returns 503 until the
protection pipeline exists. Detection, session lifecycle/startup unlock, restoration, and working proxy
endpoints are future tasks. The proxy scaffold makes no
upstream calls and provides no PII protection yet.

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
Hypothesis, Faker, and Ruff. The spaCy `en_core_web_lg` model is a separate artifact;
it is not installed or loaded by this scaffold. Pin and validate the model when
Stage 1 is implemented. Stage 2 integrations will be added in their own phase.

## Run the scaffold

```sh
uv run --locked pii-shield
# Equivalent:
uv run --locked python -m shield
```

The server binds to `127.0.0.1:8000`. Open `http://127.0.0.1:8000/docs` to inspect
the supported request schema. `/v1/chat/completions` rejects unsupported payloads
with 400 and returns 503 for valid ephemeral requests. Persistent requests and
`POST /shield/sessions` return 423 while the vault is locked. Other `/shield/*`
endpoints are not available yet.
Stop with Ctrl-C.

## Run the fake upstream

```sh
uv run --locked python -m shield.fake_upstream
```

This separate app binds to `127.0.0.1:8001`, matching the example upstream URL.
It accepts JSON at `/v1/chat/completions`, captures exact request body bytes in
memory, and returns a deterministic response containing `[PERSON_7K2Q]` and
`[EMAIL_2M4R]`. It supports multiple choices via `n`; its usage counts are synthetic
zeros. It rejects upstream `stream: true` so later tests can catch a proxy that
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
ephemeral; reusable sessions will require explicit creation. Argon2 parameters
default to 65536 KiB, 3 iterations, and parallelism 4. Loading requires positive
iteration/parallelism values and memory of at least eight times parallelism.

The CLI passes settings and runtime credentials to `create_app(config, credentials)`.
Settings are available as `app.state.config`. Importing `shield.app:app` directly
uses built-in settings without reading YAML or credentials; use the CLI to load
them. Settings for detection, HTTP timeouts, and persistence will be consumed by
their implementations in later tasks.

The proxy enforces `server.max_request_bytes` (default **1048576 bytes**, 1 MiB)
before JSON parsing, and `server.request_timeout_s` (default **120 seconds**) from
body upload through response-header creation. Oversized bodies return 413; expired
requests return 408. Actual bytes are counted for chunked or falsely declared
uploads. Invalid, duplicate, or mismatched `Content-Length` values return 400.
Limits also apply to session requests and other HTTP routes. Delivery after
response headers is outside this deadline, including future buffered SSE.
The timeout cooperatively cancels async work and runs its cleanup; synchronous
work cannot be forcibly interrupted, and late headers are rejected when it returns.

Selecting `X-Shield-Session` requires an enabled, authenticated unlocked vault.
The foundation initializes the vault as unavailable, so a passphrase collected at
startup still leaves persistent requests locked. `POST /shield/sessions` accepts
an empty object or no body and returns 423. Default requests without that header
never consult vault readiness. Real unlock, lookup, expiry, and persistent session
creation remain Phase 2 work.

The CLI reads provider credentials from the environment variable named by
`api_key_env`; a missing key is allowed for this scaffold. Setting
`sessions.persistent_enabled: true` collects a passphrase through a non-echoing
startup prompt and fails if echo cannot be disabled. Vault unlock and persistent
sessions remain Phase 2 work. Default ephemeral operation never prompts. The example
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

The design's `session.py`, `vault.py`, `pseudonym.py`, `upstream.py`,
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

Run the tests with `uv run --locked pytest`. They cover domain contracts,
configuration validation, strict HTTP contracts, safe errors, credential prompts,
and CLI settings propagation. Use synthetic fixtures and the fake upstream before any
provider smoke test. Future buffered SSE will wait for the complete upstream
answer, and detector misses must be measured rather than treated as a guarantee
that all PII is removed.
