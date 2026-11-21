# Normalization and deterministic token derivation

Phase 3 tasks 4–5 add `shield/pseudonym.py`. It derives a candidate token and a full
HMAC identity from a session key, a typed entity, and a masked source value.
`normalize_entity(EntityType, SecretStr)` returns a masked normalized value;
`derive_token(EntityType, SecretStr, SecretBytes)` returns `TokenDerivation`.
Derivation itself caches no keys or values and performs no logging or I/O.
Allocation uses the selected session store, as described below.

## Per-type normalization

| Detector type | Normalization |
| --- | --- |
| `PERSON`, `LOCATION`, `ADDRESS`, `CONTEXTUAL` | Unicode NFC, casefold, collapse Unicode whitespace to single spaces, trim surrounding whitespace, NFC again |
| `DATE_OF_BIRTH` | Same text normalization; preserve date order and separators, without guessing ambiguous numeric dates |
| `PHONE_NUMBER` | ASCII decimal digits after removing whitespace and `+()-./`; supported extension markers become `;ext=digits` |
| `CREDIT_CARD`, `US_SSN` | ASCII decimal digits after removing whitespace, hyphens and periods |
| `EMAIL_ADDRESS` | Preserve local-part case and spelling; lowercase and NFC-normalize the domain when a nonempty single-`@` value has no whitespace |
| `IP_ADDRESS` | Standard-library compressed address/interface form; preserve CIDR prefix, host bits and scope identifier spelling |
| `API_KEY`, `SECRET`, `EMPLOYEE_ID` | Exact original value, including case, Unicode form, and all whitespace |

Names/places keep punctuation and diacritics. No address-abbreviation expansion,
accent removal or NFKC compatibility folding is performed. An explicit type
controls the rule; a credential is never routed through general name casefolding.
Employee detection may match case-insensitively, but its identifier's identity
remains case-sensitive unless a later explicit policy changes that decision.

Phone normalization does not infer country codes, trunk prefixes or regions.
A national number and its international form can therefore have different
identities. Extension markers `ext`, `ext.`, `extension`, `x`, `#`, and `;ext=`
are recognized at the end; the canonical separator prevents extension digits from
aliasing a longer main number. Decimal Unicode digits are converted to their
ASCII digit values; leading zeros and order are retained. Superscripts and other
nondigit symbols are not silently folded into numbers.

For numeric, email and IP values outside the supported formatting rules, preserve
the exact original value. Resolved overlap unions can contain extra words; merely
stripping all nondigits would incorrectly merge those values with a plain number.
Fallbacks are idempotent and do not erase distinguishing content. Email domain
normalization does not perform public-suffix checks, DNS lookups or IDNA conversion.
Email local parts remain exact, including canonical Unicode differences. IP zone
identifiers remain case-sensitive, including when combined with a CIDR prefix.
No date parsing or day/month interpretation is performed for birth dates.

Empty source values are rejected. Name/place/DOB values that become empty after
whitespace normalization are rejected. Opaque secrets retain even whitespace-only
nonempty values because stripping them would change credential identity.
The implementation performs no semantic validity check such as card checksum or
phone reachability; recognizer validation happens before this layer.

## HMAC identity and display labels

A session HMAC key must contain exactly 32 bytes. Given normalized text `norm`,
the exact input is:

```text
UTF8(entity_type.value) || 0x00 || UTF8(norm)
digest = HMAC-SHA256(session_key, input)
```

Use the canonical **detector type** in the HMAC input, not the display alias.
For example, the email domain separator is `EMAIL_ADDRESS` followed by NUL.
The closed enum prevents delimiter ambiguity between types; NUL inside an opaque
value remains part of that value. Independent session keys produce independent
identities; repeated normalized inputs with the same key produce the same digest.
This implements the design document's type-separated format without hashing a
normalized value unkeyed.

| Detector type | Token label |
| --- | --- |
| `PERSON` | `PERSON` |
| `EMAIL_ADDRESS` | `EMAIL` |
| `PHONE_NUMBER` | `PHONE` |
| `CREDIT_CARD` | `CARD` |
| `US_SSN` | `SSN` |
| `LOCATION` | `LOCATION` |
| `ADDRESS` | `ADDRESS` |
| `IP_ADDRESS` | `IP` |
| `DATE_OF_BIRTH` | `DOB` |
| `API_KEY` | `APIKEY` |
| `SECRET` | `SECRET` |
| `EMPLOYEE_ID` | `EMPLOYEE` |
| `CONTEXTUAL` | `CONTEXTUAL` |

`TOKEN_LABELS` is immutable and labels are unique. Initial display tokens use
`[LABEL_XXXX]`, where the suffix is the first four characters of uppercase,
unpadded RFC 4648 Base32 of the digest. This is 20 display bits, not entity identity.
`TokenDerivation.entity_digest` retains all 32 bytes, excluded from representation
and model serialization. The result contains no normalized or original value.

`format_token(type, full_digest, suffix_length=...)` can extend a candidate using
only the full digest. Lengths from 4 through 32 are supported (up to 160 display
bits). The full 256-bit digest is never exported as a token, consistent with
[ADR 001](decisions/001-session-storage-and-buffered-sse.md). Reject malformed keys,
digests, lengths, types, or unencodable values with static `PseudonymError` messages
that do not include source values, normalized text or underlying exceptions.
Normalization rules, type-domain names, labels and token syntax are compatibility
decisions; changes require an explicit migration/version decision before existing
persistent sessions are reused.

## Atomic allocation and full-digest reuse

`EphemeralSession.allocate(type, SecretStr(value))` and
`PersistentSessionState.allocate(type, SecretStr(value))` return `TokenAllocation`:
the derived type, label, chosen token, full digest (hidden from representation and
serialization), `reused`, and `collision_count`. Obtain the persistent state from
`with service.use(session_id) as active:` so its exclusive request lease remains
held through allocation, send and restoration. Closed scopes cannot allocate.

For each call:

1. Normalize and derive the complete 32-byte HMAC identity with that session's key.
2. Look up the full digest in the selected session before considering a suffix.
   An equal digest returns the stored token, including an already-extended token.
   Stored type/token metadata must agree with the identity. No original-value
   equality comparison or decryption is performed for identity decisions.
3. For a new digest, try suffix lengths **4, 6, 8, 12, 16, 20, 24, 28, 32** in order.
   A token occupied by a different full digest is a collision; never overwrite it.
   The token includes its label, so an identical suffix under a different label
   is not a collision. `collision_count` counts occupied candidates skipped by
   this allocation. Digest reuse normally reports zero new collisions.
4. Insert the chosen token, full digest, and the first original spelling. Return
   only after the insertion succeeds; persistent allocation returns after commit.
5. If every supported prefix is occupied, raise static `TokenCollisionError` and
   leave the store unchanged. No full-digest token, random replacement, overwrite
   or decryption-based fallback is used.

The first successful insertion defines restoration spelling. For example, names
`" Alice  Smith "` and `"ALICE SMITH"` share one identity but restore to the first
observed spelling. In concurrent allocation the first successful lock/transaction
wins; input scheduling order is not promised. Case-sensitive secret and employee
ID variants retain different identities, as defined above.

### Ephemeral memory storage

Each request owns a reentrant allocation lock, a full-digest index, and a
`MemoryMappings` view. Every mutation of that view uses the same lock and changes
a version; allocation rebuilds its metadata index after external view mutations.
Invalid session/token/digest metadata and duplicate full identities fail closed.
Index rebuilding never reads or compares original values. Normal allocation keeps
the index current without scanning every existing mapping on each call.

Digest lookup, token occupancy checks, and insertion happen while holding that
single lock. Concurrent calls for the same identity create one mapping. Session
close clears the mappings and digest index and releases its key reference. This
path has no vault dependency or disk writes. Direct mutation of mapping metadata
must remain consistent; prefer allocation for new identities.

### Persistent encrypted storage

`VaultStore.allocate_token(...)` owns one `BEGIN IMMEDIATE` transaction spanning
full-digest lookup, suffix checks, encryption and insert. SQLite's per-session
digest and token uniqueness constraints provide a second guard. Independent
connections cannot both insert the same identity or claim one display token.
Encryption or commit failure rolls the transaction back before returning a token.
Persistent state flushes any existing manually staged mappings before invoking
this allocator. Each entity allocation commits independently; a later allocation
or provider failure does not roll back earlier successful entity registrations.

The persistent allocator stores the first original value only as AES-GCM
ciphertext. Reuse selects identity metadata and returns the token without
reading plaintext. This lookup does **not** authenticate the entry ciphertext;
`read_mapping` authenticates the complete entry AAD and ciphertext before exposing
a value for restoration. Modified identity metadata that happens to pass format
checks still fails authentication when its ciphertext is used. Schema/key/metadata
corruption never authorizes a plaintext comparison as an identity fallback.

The service's request lease prevents deletion/expiry racing API allocations.
The raw vault method is a trusted internal primitive; its caller supplies the
session HMAC key, authenticated vault key, and valid active session. Low-level
transaction tests use independent connections to exercise the database boundary.
No full digests or original values belong in upstream payloads or metrics.

[Text substitution](substitution.md) now applies allocated tokens while keeping
original coordinates and exact known session placeholders. The
[analysis HTTP endpoint](api-contract.md#local-analysis-endpoint) now uses this
allocator; protected upstream forwarding remains a later task.

Phase 5 task 3 adds `CONTEXTUAL` for identifying descriptions found by the local
reviewer. It uses text normalization and its own HMAC domain/token label. It is
not a Stage 1 recognizer type. Existing token identities remain unchanged; the
vault's existing schema accepts this typed value without a schema migration.
