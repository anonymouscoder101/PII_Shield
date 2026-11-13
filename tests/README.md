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

Run `uv run --locked pytest`. All fixtures must use synthetic values. The
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
