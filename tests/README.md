# Tests

`test_contracts.py` checks shared contract boundaries: Python Unicode offsets,
full digest length, masked mapping values, session lifetimes, separate allowlist
accounting, and nested error validation.

`test_config.py` checks YAML validation, threshold precedence, safe defaults,
relative vault paths, localhost binding, and CLI startup/error behavior without
starting a server or contacting an upstream.

`test_api.py` checks nested field rejection, strict text content and scalar types,
response/stream schemas, safe HTTP errors, and the blocked chat scaffold using an
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
