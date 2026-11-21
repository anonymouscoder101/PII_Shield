# Text substitution and placeholder ownership

Phase 3 task 6 adds `shield/substitute.py`. It uses the active request/session
allocator and shared span policy. The
[analysis HTTP endpoint](api-contract.md#local-analysis-endpoint) uses this module;
the chat pipeline also uses it before protected forwarding. This module itself
makes no provider calls.

## APIs and original coordinates

- `substitute_spans(text, resolved_spans, session)` applies already-resolved,
  disjoint spans. Out-of-order inputs are sorted; invalid or overlapping spans
  fail before any allocation. Adjacent spans stay separate.
- `sanitize_text(text, session, detector)` runs detection, policy and substitution.
- `sanitize_texts(texts, session, detector)` processes an ordered batch, such as
  all supported message roles. The gateway must use the batch form so input-token
  checks finish for every message before any message allocates new tokens.

Every supplied/detected span is reconstructed and bounds-checked against its
original Python string, including forged Pydantic instances. The functions use
original Unicode code-point coordinates throughout. Source-order allocation
ensures the leftmost first occurrence defines restoration spelling. Allocation
across a batch follows message order and then source order within each message.

After all spans for a text have allocated registered tokens, rendering processes
replacements from right to left. It joins original-source slices and replacement
tokens without repeated whole-string copies. Changes in token length never shift
later source coordinates. All text outside replacement intervals remains byte-for-
byte equivalent under UTF-8 encoding (with the same original Python characters).

`SubstitutionResult` contains `sanitized_text`, source-coordinate replacement
metadata, `preserved_token_count`, `below_threshold_count`, and `ProtectionReport`.
Replacement metadata contains the span, token, reuse flag, and skipped-collision
count, without original values or full digests. `sanitized_text` is excluded from
representations because unselected text can still contain sensitive information.
Serialization intentionally includes it for local analysis responses. No claim of
complete detection is made; the gateway also runs its pre-send guard.

## Exact known-token preservation

Canonical syntax is `[LABEL_SUFFIX]`: a current uppercase token label and four to
32 uppercase Base32 characters (`A-Z2-7`). It is reserved protocol syntax.
Every canonical input token must already be registered in the active session.
Metadata lookup verifies its exact token/type/full-digest prefix, without reading
or decrypting its original value. Persistent lookup recognizes committed rows
only and runs inside the caller's active session lease. A different session's
mapping cannot grant ownership. Metadata lookup is not ciphertext authentication;
restoration still uses authenticated value reads.

Exact known tokens remain unchanged, including repeated mentions and punctuation
around them. They do not create new allocations or count as newly replaced spans;
`preserved_token_count` counts their occurrences separately. Before NLP runs,
known placeholder characters are replaced by spaces of the same length, retaining
all surrounding coordinates while excluding placeholder interiors from detection.
The original text is also scanned when known placeholders are present. Blanking
a placeholder can split a credential or change NER boundaries; original-text
evidence prevents that change from silently dropping a secret suffix. Combined
candidates receive the configured threshold and allowlist decisions in original
text. Spurious detections wholly inside a known token are discarded before policy.

If a remaining accepted span crosses a known-token boundary, the operation fails
with a static `TokenSubstitutionError`. It does not cut a hole in a redaction or
erase a valid token. Below-threshold or allowlisted crossing candidates cause no
replacement, so those policy decisions still run before boundary rejection.

## Unknown and similar-looking input

A canonical token without an existing selected-session mapping raises static
`UnknownSessionToken`, even if a candidate span would otherwise redact or allowlist
it. The error never includes the literal token or selected session ID. There is
no guessed mapping, silent new mapping for the literal, or cross-session lookup.
Canonical syntax has no literal-escape convention in this version.

Batch preflight validates all canonical input tokens before any new allocation.
Otherwise an unknown literal in a later message could accidentally become known
when an earlier message allocates a colliding token. Callers must supply the
complete message batch rather than independently sanitizing its messages.

Malformed forms, unknown labels, lowercase forms, alternate separators and bare
lookalikes receive ordinary detection and policy; they are never exempted merely
for resembling placeholders. This input policy does not implement tolerant
response rehydration (Phase 4). Exact registered placeholders are the only forms
preserved as session protocol at this stage.

## Scope and failure behavior

Use ephemeral helpers inside `with ephemeral_session() as active:` and persistent
helpers inside `with service.use(id) as active:`. The request scope must remain
alive through allocation, future send and restoration. Lookup/allocate methods
reject closed scopes. After each allocation the helper validates its token and
confirms registration before inserting it into output text. Persistent mappings
commit before allocation returns; ephemeral mappings remain in memory only.

Static substitution errors expose no source, offsets, keys, or underlying error
text. Unknown-token and invalid-span failures happen before new allocations for
that text. A later detector/allocation failure returns no partial batch or text;
already successful persistent allocations may remain for their normal TTL,
as documented by the allocator. No send is performed by these functions.

The shared report counts new resolved replacements and intentional allowlist
disclosures. Existing placeholders are tracked separately. They are not proof
that all source PII was detected. The detector, policy and substitution helpers
perform synchronous work; the eventual gateway must manage its worker/deadline
boundary while keeping session scope ownership intact.

## Serialized outgoing guard

`prepare_chat` registers each replacement before serializing the outgoing request.
Ephemeral allocations stay in the active memory store; persistent allocations
commit atomically to SQLite before serialization and guard execution.
`PreparedChat.payload` holds immutable UTF-8 JSON bytes, excluded from repr and
model dumps. Future transport must send those exact bytes rather than serialize
`PreparedChat.request` again: its nested collections remain mutable.

`scan_payload` in `shield/guard.py` parses those bytes and scans every string leaf,
including model, roles, and message contents. Object keys are fixed by the strict
request schema. Unicode, quotes, backslashes, and newlines are decoded according
to JSON before detection; each value is scanned independently. Only exact tokens
owned by the active session are exempted. The guard shares substitution's
placeholder masking and original-text boundary evidence, confidence threshold,
and exact allowlist rules. It never allocates or rewrites text.

The internal `GuardReport` contains counts of remaining accepted spans, separate
allowlisted disclosures, and below-threshold candidates. For chat headers, the
message disclosure spans from preparation and the final guard are reconciled in
original coordinates through the source/token replacement intervals. The shared
overlap and visibility policy counts them once, including partially visible
originals and disclosures newly recognized after context changes. The guard
separately tracks disclosures outside message content by JSON location; only
those additional counts are added. Source/field span metadata stays internal.
Malformed payloads or detector failures raise static errors; unknown canonical
tokens fail ownership checks. Phase 4 task 3 makes `prepare_chat` reject any nonzero remaining count with
`ShieldError(PROTECTION_BLOCKED)` before returning a prepared payload. The HTTP
route returns static JSON 422 even when SSE was requested. Successful guard
checks now proceed to the async upstream client and full response restoration. Persistent
allocations already committed before a block remain until normal session expiry
or deletion. Worker cleanup releases the session lease on blocked requests;
ephemeral state is discarded before returning the error.
