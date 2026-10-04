# ADR 001: Session storage, entity identity, and buffered SSE

Status: Accepted following the author's review of design version 0.1.

Applies to: design version 0.2 and `IMPLEMENTATION_PLAN.md`.

## Context

The original design required reusable sessions, stored wrapped HMAC session keys, encrypted entries under the passphrase-derived vault key, and rejected streaming in version 1. It incorrectly claimed that deleting the HMAC key prevented recovery of mappings from old database copies.

Chat Completions clients resend conversation history. Redacting the full conversation within one request preserves repeated-entity consistency without requiring stable tokens across requests. Clients requesting streaming still need SSE responses even when generation is buffered.

## Decision

### Default ephemeral requests

Without `X-Shield-Session`, create a fresh random HMAC key and a request-local mapping store in memory. Do not write either to SQLite, logs, or other application artifacts. Detect the full conversation together so repeated normalized entities share tokens within the request.

Restore the complete response before releasing mappings. Release references to mappings and keys on success, failure, timeout, or cancellation. Buffered response text can remain in memory until delivered. A later request independently redacts any restored history; no default session ID is issued for reuse.

Ephemeral requests do not require a vault passphrase. Python, swap, and process dumps prevent a secure memory-erasure guarantee; host compromise remains outside the threat model.

### Optional persistent sessions

`POST /shield/sessions` explicitly creates a reusable session in the unlocked vault. Return its ID and `X-Shield-Session`; requests selecting that ID retain stable tokens across turns. Unknown or expired IDs return an error rather than silently creating a replacement.

Persistent entries remain encrypted under the vault key, and their HMAC keys are wrapped under it for restart recovery. Deletion and TTL expiry remove active entries, wrapped keys, and cached references. Call this **session deletion**.

An old database copy plus the passphrase can still recover persistent mappings. Deleting an HMAC key does not change this: it controls token derivation, while the vault key decrypts entry values.

| Property | Ephemeral default | Explicit persistent session |
| --- | --- | --- |
| Scope of token consistency | One complete request | Requests using the same session ID |
| Mapping/key storage | Process memory only | Encrypted mappings and wrapped HMAC key in SQLite |
| Vault unlock required | No | Yes |
| Survives restart | No | Yes, until expiry or deletion |
| Cleanup | Release request state after restoration or failure | Delete active vault rows and cached state |
| Old database-copy recovery | No application-created mapping/key rows | Remains possible with the passphrase |

### Full-digest entity identity

Retain the complete 256-bit HMAC-SHA256 digest as each entity's identity. For persistent entries, add:

```sql
entity_digest BLOB NOT NULL CHECK (length(entity_digest) = 32)
```

Use a unique constraint on `(session_id, entity_digest)` alongside the existing `(session_id, token)` primary key. Ephemeral stores use the same identity rule in memory.

- Equal full digest: reuse the existing token without decrypting its value to compare identity.
- Equal short token suffix with a different full digest: a suffix collision; extend the suffix.
- Different raw spellings with the same normalized identity: reuse the token and restore the first observed spelling.

Normalization is type-specific; API keys and other case-sensitive secrets are never casefolded. Digest lookup, collision resolution, and insertion must be atomic. Bind the digest and other identity metadata into entry AAD so tampering fails authentication when the value is used. A full keyed digest is lookup metadata, not an unkeyed hash of PII, and must never be sent upstream.

### Buffered SSE

Accept `stream: true` in the supported request schema. Always request `stream: false` upstream, receive the full response, and restore every supported choice before delivery.

For a streaming client:

1. Return `Content-Type: text/event-stream`.
2. Emit a `chat.completion.chunk` event carrying the restored role/content delta for each choice.
3. Emit finish-reason information for each choice, preserving IDs and choice indices; include usage events only when explicitly supported by the request contract.
4. End with `data: [DONE]` and a blank line.

Use JSON serialization for event payloads so newlines in restored text cannot break SSE framing. Do not commit SSE headers until upstream success and restoration; earlier failures return normal HTTP errors. Non-streaming clients receive the ordinary JSON response.

This preserves the streaming protocol but delays the first content until generation finishes. True incremental upstream streaming and token-boundary buffering remain future work. Multimodal content and tool requests remain unsupported; nested request models use `extra="forbid"`.

## Alternatives and consequences

Requiring reusable sessions would retain cross-request token linkage and disk artifacts even when clients need only within-request consistency. Ephemeral defaults avoid that requirement, while explicit sessions retain restart recovery for users who choose it.

Decrypting stored values for collision checks adds work and confuses raw spelling variants with identity. Full HMAC digests distinguish normalized reuse from truncated-suffix collisions directly.

Rejecting `stream: true` would break clients that request SSE by default. Buffered SSE adds protocol handling without requiring incremental token restoration, but it provides no generation-latency benefit.

A future design for encryption-key destruction must encrypt session mappings with a distinct data-encryption key kept in memory only, never persisted or wrapped on disk. It would forgo restart recovery and still require explicit memory/swap limitations. Memory-only HMAC keys alone do not make vault-key-encrypted entries unrecoverable. This stronger encrypted-storage design is outside the MVP.

## Required validation

- Ephemeral requests create no mapping/key rows or PII-bearing logs and release state on all exit paths.
- Explicit sessions reopen after restart; unknown/expired IDs fail predictably.
- Normalized spelling variants reuse one full-digest identity; secrets differing in case remain distinct.
- Forced short-suffix collisions extend tokens without overwriting mappings.
- Changes to stored digests, tokens, or ciphertext fail authentication on value use.
- A compatible SSE client parses restored content, multiple choices, finish reasons, and `[DONE]`.
- Reports distinguish allowlisted disclosures, and total leakage accounting includes them.
