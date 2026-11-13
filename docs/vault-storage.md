# Persistent vault storage

Phase 2 tasks 1–5 add `shield/vault.py`. It is an internal persistence layer,
opened explicitly with `with VaultStore(path) as store:`. Constructing a store
or constructing the app does not open SQLite or create vault directories.
Startup without persistence enabled also creates no vault artifacts. Default
ephemeral requests continue to bypass the vault. Persistent routes require opt-in
and authenticated startup unlock.

## Schema version 1

`PRAGMA user_version = 1` identifies the layout even before KDF initialization.
Opening an empty database initializes all three tables and the version in one
transaction. An existing database with an unknown version, an unversioned
nonempty layout, or a changed layout is rejected without schema repair. There
are no migrations yet. The original design's unversioned schema is unsupported.

The tables follow the revised design document:

- `vault_meta`: singleton `id = 1`, salt, serialized KDF parameters, verifier
  nonce and ciphertext, schema version. Explicit initialization populates this table; an empty
  table indicates schema initialization only and does not establish vault readiness.
- `sessions`: session ID, wrapped HMAC key nonce/ciphertext, creation and expiry
  timestamps in integer Unix seconds. Only persistent sessions belong here.
- `entries`: session ID, token, entity type, full 32-byte HMAC digest, nonce,
  and ciphertext. `(session_id, token)` is the primary key and
  `(session_id, entity_digest)` is unique. Digests are SQLite BLOBs of exactly
  32 bytes. Foreign keys are enabled on every store connection; deleting a
  session cascades to its entries.

Tables use SQLite STRICT typing. Nonces are 12-byte BLOBs; wrapped 32-byte keys
have 48-byte ciphertexts including the GCM tag; entry ciphertexts include at least
an authentication tag. Python row contracts validate these boundaries too.

`insert_session(..., entries=...)` commits session and initial entries together.
`insert_entries(...)` commits a complete batch. Conflicts raise instead of
silently replacing the first observed mapping. Any exception, including cancellation
or an interrupted iterable, rolls back the transaction. `transaction()` is an
internal escape hatch for later vault services. It uses `BEGIN IMMEDIATE`, cannot
be nested, and must contain no awaits or network operations. The store is
synchronous and confined to its opening thread; active-request coordination,
TTL enforcement, and atomic collision selection are later tasks.

## Authenticated entry identity

`entry_aad(row)` encodes a compact ASCII JSON array, in this fixed order:

```text
["pii-shield/entry", 1, session_id, token, entity_type, full_digest_hex]
```

JSON escaping and explicit array elements make field boundaries unambiguous.
The digest is all 32 bytes rendered as lowercase hex. This encoding binds the
domain, schema version, session, token, type, and full digest when used by AES-GCM.
`encrypt_entry` and `decrypt_entry` use this encoding for production AES-GCM
encryption and authenticated reads. Raw `insert_entries` accepts already-encrypted
rows and cannot verify supplied bytes without a key. Prefer `insert_mappings`
and `read_mapping` for value storage and restoration.
The unlock verifier and wrapped session keys use separate AAD domains.

## Disk behavior and limitations

On POSIX systems the database is created with mode `0600`, including under a
permissive umask; existing database permissions are restricted before SQLite
opens it. A newly created containing directory has mode `0700`. Existing parent
directory permissions are preserved. Use a private parent directory: filesystem
path replacement by an attacker able to write that directory is outside this
layer's protection. New rollback journals inherit the database permissions;
existing journal/WAL/SHM files are restricted to `0600` before opening. Final-file
symlinks and nonregular files are rejected where OS support permits. Other
platforms rely on their filesystem ACLs and OS support. No process-wide umask is
changed. SQLite's default rollback journal is sufficient; WAL is not enabled.

Only encrypted values and wrapped keys belong on disk. Token/type/session metadata
and keyed full digests remain visible. Do not log SQLite exception text or row
values. Deleting rows removes active sessions and entries; it does not prevent
recovery from old database copies, backups, or retained journal pages. Python
memory and host swap also prevent a secure memory-erasure guarantee.


## Vault initialization and unlock

On an explicitly opened store, `initialize(SecretStr(...), params=Argon2Config(...))`
creates a random 16-byte salt and derives a 32-byte vault key with Argon2id
(version 19). Defaults are `memory_kib=65536` (64 MiB), `time_cost=3`, and
`parallelism=4`. Passphrases are UTF-8 encoded without normalization or trimming;
empty or whitespace-only passphrases are rejected. Explicit nondefault settings
are stored with the vault and used on every subsequent unlock.

Initialization encrypts a fixed verifier using AES-256-GCM and a fresh random
12-byte nonce. Verifier AAD is compact, sorted-key ASCII JSON:

```text
["pii-shield/verifier", schema_version, salt_hex, kdf_parameter_object]
```

The object includes `algorithm`, `version`, `hash_len`, `memory_kib`, `time_cost`,
and `parallelism`. This domain is distinct from entry AAD. All parameters must
be present and valid. Salt, parameters, verifier nonce/ciphertext and schema
version commit in one transaction. Initialization refuses any existing metadata,
sessions or entries; it never overwrites a vault or silently resets its key.

`unlock(SecretStr(...))` validates metadata, derives with the stored parameters,
and authenticates the verifier before returning a key. Wrong passphrases and
corrupt metadata raise the same static `VaultUnlockError`. No automatic
reinitialization follows a failed unlock. The header is unchanged on failure.
Missing metadata in a nonempty vault is an error requiring investigation.

Both methods return `SecretBytes`; trusted encryption code must explicitly
extract its 32 bytes. The store does not cache the key or set an unlocked flag.
The passphrase and key are never persisted or logged. The caller owns key
lifetime; secret wrappers mask representations but do not securely erase memory.
The CLI collects credentials locally; opt-in application lifespan authenticates
the vault before serving. The application then drops its passphrase reference.

Stored KDF metadata is untrusted. Before allocation, parameter JSON is limited
to 1024 characters, extra/missing fields and unsupported algorithms/versions/key
lengths are rejected, and costs are bounded to at most 1 GiB memory, 10 passes,
and 16 lanes. Memory must also be at least eight times the lane count. These are
local resource limits, applied on creation and unlock; higher settings require
an explicit code/policy change. Existing lower-cost explicit configurations are
supported, but the documented defaults are recommended. Unlock is synchronous
and must not run on a request event loop; later startup integration will manage it.


## Persistent entry encryption and reads

`encrypt_entry(mapping, key)` UTF-8 encodes the exact original spelling and
returns an `EntryRow` encrypted with AES-256-GCM. Every call draws a fresh 12-byte
nonce from `os.urandom`; nonces are not derived from tokens, digests or counters.
Only 32-byte keys are accepted. `decrypt_entry(row, key)` authenticates ciphertext,
nonce and the complete entry AAD before decoding a value into a masked
`TokenMapping`. Any authentication or decoding failure raises the static
`VaultEntryError`, without returning a partial value or logging row contents.

`insert_mappings(mappings, key)` encrypts before binding anything to SQLite and
commits the batch atomically. Encryption, nonce-generation, iteration or identity
conflict failures roll back all rows in the batch. Conflicts never overwrite the
first spelling; later pseudonym logic will resolve reuse/collisions by full digest.
`read_mapping(session_id, token, key)` selects only that session/token and validates
and authenticates its stored identity. Missing rows return `None`; corrupt rows
raise an authentication error. It never falls back to another session or mapping.
These methods accept a trusted caller's authenticated vault key and retain no key
cache. Low-level entry encryption alone is not vault unlock or session authorization.

Production tests exercise restart reads and plaintext absence from database,
rollback-journal and WAL/SHM files, plus nonce, ciphertext, digest, identity and
cross-session row swaps. Metadata such as tokens and full keyed digests remains
visible by design. Session endpoints require the authenticated service described
below. Active-request coordination is task 6.


## HMAC session keys

`shield/session.py` has no vault dependency. `generate_hmac_key()` draws 32 fresh
random bytes and returns a masked `SecretBytes`. `ephemeral_session()` creates
one request-local key, internal ID, and mapping dictionary. Its `finally` path
clears mappings and drops its key reference on normal completion, exceptions,
timeout or cancellation. Each valid chat request without `X-Shield-Session` uses
this context, including the current blocked proxy scaffold. It creates no SQLite
files or reusable session headers. Supplied session IDs follow the locked-vault
checks and do not silently create ephemeral replacements.

`wrap_session_key(record, key, vault_key)` accepts only a `SessionRecord` whose
kind is explicitly `persistent`. It wraps a 32-byte HMAC key using AES-256-GCM
under the 32-byte vault key, with a fresh random 12-byte nonce, and returns a
`PersistentSessionRow`. Only that ciphertext row is passed to `insert_session`.
Wrapping performs no I/O and is never invoked for default ephemeral requests.

Wrapped-key AAD is compact ASCII-escaped UTF-8 JSON with this fixed order:

```text
["pii-shield/session-key", schema_version, session_id, created_at, expires_at]
```

Both timestamps are integer Unix seconds, matching stored rows. Subsecond
lifetimes that collapse to a zero-second interval cannot be persisted. This
separate domain prevents ciphertext substitution with entries or the verifier.
Binding the lifetime also makes stored timestamp edits fail authentication.
`unwrap_session_key(row, vault_key)` authenticates before returning a masked
32-byte key. Wrong keys, changed identity/timestamps/nonces/ciphertexts and domain
or schema substitutions raise static `VaultSessionKeyError` failures. Helpers
neither cache unwrapped keys nor bypass session authorization. The lifecycle service checks expiry and manages deletion and the reusable-session
endpoints.

Request cleanup releases owned references rather than erasing memory; callers
must not retain or log extracted keys or mappings. Persistent ciphertexts remain
recoverable from old copies using the vault passphrase, as documented above.


## Persistent lifecycle

`shield/persistent.py` owns the authenticated vault key while enabled. Its
`PersistentSessions.open(...)` authenticates stored metadata, initializes only
an empty vault, and prunes expired sessions at startup. A missing header in a
nonempty vault is an error, never permission to reset its key. Application
lifespan runs initialization/KDF in a worker and closes the service on shutdown.
Constructing the app alone does not open SQLite; embedded callers must run ASGI
lifespan to enable persistence.

Creating a session generates an independent HMAC key and random UUID, wraps the
key, and inserts its metadata. The service stores no unwrapped HMAC-key cache.
Each scoped `use(id)` authenticates/unwraps the row and releases its key and
request mappings in `finally`, including failure or cancellation. Lifecycle
lookup returns metadata without retaining the key. Internal mapping operations
check session validity before calling encrypted storage methods.

Session lifetimes are fixed at creation; lookups do not refresh them. Creation
uses whole-second UTC timestamps, with configured TTL rounded up to at least one
second. Expiry is inclusive. Lookup authenticates lifetime metadata before
checking expiry, then deletes an expired session and its entries in one
transaction. It raises the expiry error after commit so cleanup is retained.
Explicit deletion uses the same cascade transaction. Cleanup is lazy on access
and also runs at startup; `prune_expired()` can be invoked explicitly. There is
no background cleanup scheduler. Already-pruned/deleted IDs are unknown; no
replacement session is silently created.

The service has no long-lived SQLite connection or HMAC cache. Scoped references
are dropped when a scope exits; this does not erase caller copies or revoke an
already active scope. Coordination of active requests, expiry and deletion
across multiple operations is task 6, required before upstream proxy work uses
persistent mappings. Deleting active rows still does not destroy old database
copies or guarantee erasure from freed process memory.
