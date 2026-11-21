# Local contextual reviewer setup

Phase 5 task 1 provides a local Ollama/LangChain adapter and a measured latency
baseline. Task 2 adds the masked-text handoff and source map described below.
Neither task connects Stage 2 to chat or changes health's Stage 2 availability
flag. Structured validation, merging and mode/failure-policy orchestration follow
in tasks 3–6.

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
**untrusted JSON text**, not accepted detections; later tasks must validate exact
text/positions and map offsets. The prompt asks for spans without free-text reasons.
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
Full output size/schema/offset policy remains task 3/5 work; do not feed these
results into redaction before that validation exists.

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
Task 3 must validate schema, exact text, bounds, unambiguous mapping and original
text equality before accepting any contextual span. Public chat/analysis behavior
and fast-mode independence remain unchanged in task 2.
