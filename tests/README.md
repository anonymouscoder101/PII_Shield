# Tests

`test_contracts.py` checks shared contract boundaries: Python Unicode offsets,
full digest length, masked mapping values, session lifetimes, separate allowlist
accounting, and nested error validation.

`test_config.py` checks YAML validation, threshold precedence, safe defaults,
relative vault paths, localhost binding, and CLI startup/error behavior without
starting a server or contacting an upstream.

`test_api.py` checks nested field rejection, strict text content and scalar types,
response/stream schemas, safe HTTP errors, and protected chat using an
in-process HTTPX transport. `test_credentials.py` checks environment-only provider
keys, masked runtime state, opt-in passphrase prompting, and failure before any
echoed fallback input or server startup.

`test_fake_upstream.py` checks byte-for-byte request capture, configurable
token-bearing and refusal-only responses, rejected requests, concurrency and app
isolation, localhost startup, and synthetic fixture coordinates/expected payloads.

`test_limits.py` checks declared and streamed byte limits, Unicode byte counts,
request framing, upload/processing deadlines, cancellation cleanup, and response
delivery after headers. `test_session_access.py` checks that a locked vault blocks
persistent selection and creation, while ephemeral requests ignore vault readiness.

Install the pinned model with `uv sync --locked --extra stage1`, then run
`uv run --locked --extra stage1 pytest`. All fixtures must use synthetic values. The
detailed verification strategy is in
`IMPLEMENTATION_PLAN.md`.

`test_vault.py` checks schema creation/reopening and incompatible-schema refusal,
foreign keys and cascading deletes, digest/token uniqueness, transaction rollback
on conflicts and cancellation, restrictive database/journal permissions, and
full-identity AAD with synthetic AES-GCM ciphertext. The storage round-trip test
checks that its seeded plaintext is absent from database and journal bytes;
production entry encryption is exercised separately below.


`test_vault_unlock.py` exercises real Argon2id with the documented defaults,
stored custom parameters, fresh salts/nonces, restart unlock, wrong passphrases,
metadata tampering, cost bounds, initialization rollback, and secret absence on
disk. Most negative tests use explicitly reduced synthetic-test KDF costs.


`test_vault_entries.py` checks production AES-256-GCM entry encryption and reads,
Unicode spelling preservation, fresh nonces, complete AAD binding, tampered/swapped
rows, exact session lookup, wrong key sizes, atomic encrypted-batch rollback,
restart recovery and plaintext absence from database/journal/WAL/SHM artifacts.


`test_session_keys.py` checks fresh independent ephemeral keys, mapping isolation,
cleanup on failure/cancellation, real chat request integration without SQLite,
persistent-only key wrapping, fresh nonces, 32-byte key requirements, full wrapped
key AAD binding, restart recovery and absence of raw key bytes from disk.


`test_persistent_sessions.py` checks lifecycle creation and restart recovery,
scoped-key release, inclusive TTL and cascade cleanup, corruption and wrong-key
startup failures, opt-in lifespan behavior, metadata and deletion endpoints,
unknown/expired selections, failure/cancellation cleanup, and real async timeout
cleanup for ephemeral state. ASGI lifespan is explicitly entered in startup tests.


`test_session_concurrency.py` uses events, real threads and a child process to
check exclusive leases, HTTP busy responses, distinct-session progress, expiry
pinning, shutdown drain and vault ownership. Send callbacks verify committed
rows through an independent SQLite connection. Failed commits never invoke the
callback; timeout/cancellation release keys and leases. Concurrent ephemeral
contexts retain independent mappings and keys.


`test_stage1.py` loads the real pinned local spaCy model once and exercises all
baseline entity types with synthetic text. It checks capability/NER-label
availability, missing-model/version failures, Unicode offsets, repeated entities,
clean input, source-free spans and errors, no network during scanning, debug-log
privacy, malformed result rejection and fail-closed regex timeouts. These tests
require the `stage1` extra; they are not silently skipped when it is absent.


`test_custom_recognizers.py` checks labeled and invalid birth dates, API/secret
value-only spans, Unicode/repetition and debug privacy, custom employee patterns,
GB national phone detection, enabled capability policies, invalid/sensitive
configuration failures and zero-width regex rejection. The full detector tests
continue to use the pinned local model and synthetic text only.


`test_span_resolution.py` exercises shared policy without NLP models: full bounds
validation, forged contract rejection, inclusive thresholds, exact allowlists,
Unicode/repeated terms, transitive/nested/adjacent spans, input-order invariance,
filter-before-merge bridges, deterministic ties and disclosure coverage. A
Hypothesis test checks accepted character coverage and ordering across generated
span sets. `test_stage1.py` also verifies detector-plus-policy integration.


`test_pseudonym.py` checks type-specific normalization, exact preservation of
secrets/case-sensitive identifiers, email local-part case, numeric formatting and
extensions, Unicode/canonical equivalence, IP prefixes/zones, and conservative
fallbacks. It verifies HMAC input bytes, full digests, stable labels, bounded Base32
suffixes, masked outputs, session independence, and normalization idempotence.
These tests require no model, database or provider calls.


`test_token_allocation.py` forces every suffix-collision step and exhaustion,
checks full-digest reuse and first-spelling restoration, and verifies concurrent
memory/SQLite allocations create one mapping. It forbids decryption during
persistent reuse, reopens sessions, checks encryption rollback, invalid metadata,
closed scopes, index refresh and plaintext/key absence in persistent artifacts.


`test_substitution.py` checks source-order allocation and right-to-left rendering,
Unicode/repeated/adjacent spans, exact known-token preservation, unknown/cross-session
rejection, batch preflight, policy-filtered boundaries, allocation errors and
persistent restart without plaintext lookup. It also runs the real detector and
a property test proving every unselected Unicode segment remains unchanged.


`test_analyze_api.py` covers the real local analysis endpoint plus deterministic
injected detectors: strict JSON, Unicode coordinates, policy counts, ephemeral
cleanup/no vault access, explicit-session persistence/restart, safe errors,
no-provider behavior, size/timeout limits and cancellation. Event-controlled
workers verify lease retention while cancelled work drains, and a direct ASGI
`http.disconnect` test verifies prompt cleanup on an actual disconnect.

`test_gateway.py` covers conversation preparation across all supported roles,
repeated/restored assistant PII, exact known tokens, whole-batch token preflight,
separate allowlist counts, preserved options, and chat route integration.

`test_outgoing_guard.py` covers decoded JSON string scanning (including model),
owned placeholders, allowlist/threshold policy, immutable payload bytes, static
failure messages, read-only scans, and persistent commit visibility before scanning.

`test_guard_blocking.py` injects incomplete masking after real mapping registration
to verify blocking across every role and both stream settings, static errors,
zero network sends, ephemeral cleanup, persistent lease release, model-field
blocking, and allowlist/threshold exceptions.

`test_upstream_client.py` covers exact bytes with the fake upstream, auth and URL
construction, verified-TLS/client options, phase and total timeouts, cancellation,
static status/transport/schema errors, zero retries/redirects, and scoped log suppression.

`test_rehydrate.py` covers exact and formatting-variant restoration, Markdown and
possessives, complete identity boundaries, Unicode lookalikes, no recursive
replacement, active-session isolation, persistent restart recovery, and safe failures.

`test_chat_roundtrip.py` exercises the full protected local round trip, multi-choice
content/refusal restoration, JSON/SSE framing and usage, zero leaked fixture values
in captured payloads, JSON errors before SSE headers, pre-header state cleanup,
disconnect/cancellation, and persistent leases through fetch and cancellation drain.

Phase 4 task 7 extends restoration/round-trip coverage with unknown occurrence
counting, no double counting or scanning inserted originals, count-only report
headers, final-scan disclosure counts including model, and selected-session headers
for JSON/SSE success with header omission on errors.

`test_metrics.py` verifies count-only structured events, fixed endpoint categories,
static errors including upload/late failures, cancellation/limits, concurrent
isolation, validation of telemetry data, and seeded provider/body/credential/reviewer
text exclusion at DEBUG. The CLI configuration test checks disabled access logs.

`test_health.py` covers the strict local health contract, credential/configuration
privacy, no network/model loading or vault creation, optional-vault authenticated
lifecycle, disabled-vault isolation, detector load failure/recovery, non-blocking
snapshots during loading, and the OpenAPI schema.

`test_stage2_reviewer.py` requires the optional stage2 extra and uses local HTTP
mocks/fake models. It covers local-only readiness, cloud/remote rejection, safe
failure/timeout behavior, disabled tracing and environment credential forwarding,
and DEBUG-mode fail-closed behavior. Ordinary tests never run model inference;
use `scripts/benchmark_reviewer.py` explicitly for the synthetic local benchmark.

`test_review_source_map.py` covers masked-only batch handoff, unknown-token preflight,
review failure/cancellation, Unicode/source mapping after expansion and contraction,
repeated/pre-existing tokens, equal-length/adjacent masks, invalid maps/bounds, and
exclusion of raw review text from repr and serialization. It needs no Ollama service.

`test_review_validation.py` covers strict reviewer JSON/schema errors, exact quoted
positions, original-snapshot checks, Unicode/length-changing maps, placeholder and
cross-placeholder rejection, shared threshold/allowlist/overlap behavior, masked
batch-to-validation composition, and persistent CONTEXTUAL token restoration.

`test_review_injection.py` exercises additive merge preservation, provenance and
overlap rejection, empty results under malicious documents, reviewer policy/removal
commands, placeholder reclassification, and reason-text non-disclosure. The
adapter suite checks forged chat roles stay inside one JSON document message.

`test_review_policy.py` covers default closed/explicit open review failures,
aggregate UTF-8 budgets, synchronous deadline overruns, cancellation, whole-batch
Stage 1 fallback, and typed delivery/metrics outcomes. `test_review_transport.py`
checks streaming byte caps despite absent/misleading lengths and compressed replies.
The adapter suite also exercises the real SDK stream path with synthetic chunks.

`test_modes.py` verifies fast-mode reviewer independence, balanced/paranoid chat
and analysis, combined masking/counts, live fallback headers, final guard placement,
zero forwarding on failure, persistent contextual mapping commits/restoration,
cached health state, delayed reviewer cleanup leases, and cleanup timeout/cancellation
precedence. `conftest.py` supplies an empty reviewer only as the default application
test double; explicit mode tests and SDK mocks exercise their own behaviors. No
ordinary test depends on an Ollama daemon; live inference uses the benchmark.


`test_demo.py` runs the executable offline JSON/SSE demo using the real local
Stage 1 model, with outbound sockets forbidden. `test_evaluation.py` checks
seeded synthetic ground truth, Unicode/repeated offsets, matching and disclosure
scoring, utility denominators, and a small real-detector/fake-upstream pilot.
The full experiment suite remains Phase 6 work.

The completion review adds name-shaped secret identity and transitive opaque
overlap regressions, plus Stage 2 cleanup deadline/lease tests under caller
cancellation and forced garbage collection. Live local reviewer API smoke
observations are recorded separately in `docs/phase-1-5-review.md`.
