# Persistent vault storage

Phase 2 tasks 1–2 add `shield/vault.py`. It is an internal persistence layer,
opened explicitly with `with VaultStore(path) as store:`. Constructing a store
or starting the proxy does not open SQLite or create vault directories. Default
ephemeral requests continue to bypass the vault; the app's persistent session
routes remain locked until the session service and its authenticated startup flow are wired.

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
Task 3 will use it for production encryption and authenticated reads. This storage
layer accepts already-encrypted rows; it cannot prove supplied bytes are ciphertext
or authenticate them by itself. It accepts no original-value or raw-key argument.
The unlock verifier uses a separate domain; task 4 supplies wrapped-key AAD.

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
The current CLI still only collects credentials. Startup unlock, persistent API
sessions, entry encryption and wrapped HMAC keys are subsequent Phase 2 tasks.

Stored KDF metadata is untrusted. Before allocation, parameter JSON is limited
to 1024 characters, extra/missing fields and unsupported algorithms/versions/key
lengths are rejected, and costs are bounded to at most 1 GiB memory, 10 passes,
and 16 lanes. Memory must also be at least eight times the lane count. These are
local resource limits, applied on creation and unlock; higher settings require
an explicit code/policy change. Existing lower-cost explicit configurations are
supported, but the documented defaults are recommended. Unlock is synchronous
and must not run on a request event loop; later startup integration will manage it.
