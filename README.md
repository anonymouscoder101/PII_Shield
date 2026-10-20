# PII Shield

A planned single-user localhost proxy that detects sensitive text, replaces it
with session-specific tokens before an upstream Chat Completions call, and
restores known tokens in the response. See [the implementation plan](IMPLEMENTATION_PLAN.md)
and [the accepted design decisions](docs/decisions/001-session-storage-and-buffered-sse.md).

## Current status

Phase 1 tasks #1–2 are implemented: the package scaffold and shared typed domain
contracts. The configuration loader, HTTP request/response contracts, fake upstream,
detection, vault, restoration, and proxy endpoints are future tasks. The scaffold serves
FastAPI's documentation and OpenAPI schema only; it makes no upstream calls and
provides no PII protection yet.

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
the empty API scaffold; `/v1/chat/completions` and `/shield/*` are not available yet.
Stop with Ctrl-C.

## Configuration example

[`shield.example.yaml`](shield.example.yaml) records the proposed configuration.
Its local upstream URL reserves port 8001 for the future fake upstream. The
scaffold does not read YAML or environment credentials yet; startup uses the
loopback address and port above. Implement validated loading in Phase 1 task #3.

Keep provider credentials in the environment variable named by `api_key_env`.
Persistent sessions will obtain a passphrase through a non-echoing prompt, while
default ephemeral requests will keep keys and mappings in memory. The example
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

The design's `config.py`, `session.py`, `vault.py`, `pseudonym.py`, `upstream.py`,
`rehydrate.py`, detector modules, and evaluation scripts will be added as their
implementation tasks are completed.

## Shared contracts

[`shield/contracts.py`](shield/contracts.py) defines validated Pydantic models for
detected spans, in-memory token mappings, session metadata, protection reports,
and API error envelopes. Models reject unknown fields and implicit coercion;
Python callers use the supplied enums for entity types, stages, session kinds,
and error codes. HTTP payload models and error/status handling belong to task #4.

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

Run the contract tests with `uv run --locked pytest`. They cover Unicode offsets,
validation boundaries, secret representation, session lifetimes, report accounting,
and error envelopes. Use synthetic fixtures and the fake upstream before any
provider smoke test. Future buffered SSE will wait for the complete upstream
answer, and detector misses must be measured rather than treated as a guarantee
that all PII is removed.
