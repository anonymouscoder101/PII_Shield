# Persistent vault storage

Phase 2 task 1 adds `shield/vault.py`. It is an internal persistence layer,
opened explicitly with `with VaultStore(path) as store:`. Constructing a store
or starting the proxy does not open SQLite or create vault directories. Default
ephemeral requests continue to bypass the vault; the app's persistent session
routes remain locked until authenticated unlock and session management exist.

## Schema version 1

`PRAGMA user_version = 1` identifies the layout even before KDF initialization.
Opening an empty database initializes all three tables and the version in one
transaction. An existing database with an unknown version, an unversioned
nonempty layout, or a changed layout is rejected without schema repair. There
are no migrations yet. The original design's unversioned schema is unsupported.

The tables follow the revised design document:

- `vault_meta`: singleton `id = 1`, salt, serialized KDF parameters, verifier
  nonce and ciphertext, schema version. Task 2 will populate this table; an empty
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
Task 2 supplies the KDF/unlock verifier and task 4 supplies wrapped-key AAD.

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
