# PII Shield implementation plan

Source: `PII_Shielding_Proxy_Design_Document.docx`, version 0.2, October 2026; incorporates the author's review of the nine design gaps.

This plan translates the proposed design into implementation tasks, dependencies, and acceptance criteria. The nine reviewed gaps are resolved by the accepted decisions below; implementation choices added here are identified explicitly. It does not start implementation or authorize provider calls with real PII.

## 1. Target outcome and scope

Build a single-user, localhost proxy that accepts text-only OpenAI-compatible Chat Completions requests, including buffered SSE for clients requesting streaming, detects sensitive spans, replaces them with session-specific tokens, forwards the sanitized request, and restores known tokens in the response.

The minimum viable build includes:

- Stage 1 detection using Presidio, spaCy, and custom recognizers.
- Ephemeral per-request sessions by default, deterministic HMAC tokens with full-digest identity, and an encrypted SQLite vault for optional reusable sessions.
- Exact and tolerant rehydration, followed by JSON or buffered SSE output.
- A pre-send detection guard, privacy-safe logs, and the five proposed HTTP endpoints.
- Synthetic data, detector evaluation, an end-to-end leakage measurement, and a limited threshold/utility experiment.

The extended build adds the local contextual reviewer and the complete E1–E6 evaluation suite. Incremental upstream streaming, non-text inputs, tool requests, browser extensions, multilingual support, and multi-user deployment remain outside version 1. Buffered SSE is included in version 1; clients wait for the complete upstream answer before receiving content.

Success means **detected, non-allowlisted PII is removed before forwarding**, with measured residual leakage from detector misses. Do not describe the system as guaranteeing that no PII ever reaches the provider.

## 2. Accepted design decisions

| Gap in design version 0.1                                                                                  | Accepted implementation decision                                                                                                                                                                                                                                                                                                                            | Why it matters                                                                                                                                                                                           |
| ---------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Entry ciphertext is encrypted with the vault key, but deleting the session key is called crypto-shredding. | Call persistent cleanup session deletion, without claiming recovery prevention from old copies. Default ephemeral requests keep keys and mappings in memory only. A future key-destruction design must use a data-encryption key that is never persisted or wrapped on disk, and sessions cannot survive restart.                                           | Deleting the HMAC session key does not stop the vault key from decrypting retained entry ciphertext. Even a per-session encryption key can remain recoverable from a backup containing its wrapped copy. |
| Stage 2 reviews text whose Stage 1 replacements change character offsets.                                  | Build a source map from masked text to original text. Require exact quoted text plus offsets, verify them against the masked text, then map accepted spans back to the original. Reject spans intersecting placeholder interiors.                                                                                                                           | Prevents contextual spans from redacting the wrong characters, including when phrases occur more than once.                                                                                              |
| Normalization makes different spellings share a token.                                                     | Document that one normalized entity restores to its first observed spelling in a session. Store the full 256-bit HMAC digest as the entity identity; equal digest means reuse, while equal suffix with a different digest means a collision. No decryption is needed for this comparison. Avoid casefolding case-sensitive identifiers such as API secrets. | A single token cannot preserve every original spelling or formatting variant. Applying blanket casefolding can merge distinct secrets.                                                                   |
| Clients can supply arbitrary OpenAI request fields, including nested text.                                 | Use Pydantic with extra="forbid" at every request-model level. Accept only explicitly listed fields and string message content; reject message names, tools/tool calls, user, metadata, content-part arrays, and other unsupported fields. Sanitize every supported message role.                                                                           | Sanitizing only `messages[].content` can leave raw PII in tool arguments, names, or extra request fields.                                                                                                |
| Version 1 is non-streaming, while compatibility is described as drop-in.                                   | Accept `stream: true`, fetch the full answer upstream with `stream: false`, rehydrate it, then return valid SSE completion chunks and `[DONE]`. Include role/content and finish information for each choice. Reject multimodal/tool requests and document the buffering delay.                                                                              | Buffered SSE preserves the client protocol without token-boundary buffering. It provides compatibility, not incremental generation latency.                                                              |
| Requests without a session header create a session, but the return mechanism is unspecified.               | With no header, use an ephemeral session for this request only and discard it after restoration or failure. Explicit session creation opts into a reusable vault-backed session; return its ID and `X-Shield-Session` when used. Unknown or expired supplied IDs produce an error, never a silent replacement.                                              | The full conversation is redacted together each request, so continuity is optional. Ephemeral defaults reduce cross-request token linkage; explicit sessions offer stable tokens across requests.        |
| Mode defaults and an explicit threshold can conflict.                                                      | Resolve configuration as: explicit threshold overrides the mode default. Without an override, use fast=0.6, balanced=0.5, paranoid=0.3.                                                                                                                                                                                                                     | Makes configuration sweeps reproducible.                                                                                                                                                                 |
| Allowlisted terms may still be caught by the final guard.                                                  | Share recognizer and allowlist policy between detection and the guard. Make intentional allowlist disclosures explicit in reports and evaluation.                                                                                                                                                                                                           | Prevents inconsistent blocking and prevents deliberate exceptions from being hidden in privacy claims.                                                                                                   |
| Span overlap and confidence handling are underspecified.                                                   | Apply threshold and allowlist decisions before merging accepted overlapping spans. Merge transitively; select an accepted opaque credential type first to preserve case-sensitive identity, then the highest-confidence type with a deterministic tie-break. Record this policy (see the phase review for the validation-driven exception).                                                                                                                                                               | Low-confidence spans should not enlarge an accepted redaction after being discarded.                                                                                                                     |

The session storage, full-digest identity, and buffered SSE decisions are recorded in [ADR 001](docs/decisions/001-session-storage-and-buffered-sse.md). Revisit these decisions only when validation exposes a concrete problem.

## 3. Implementation phases

Dependencies: **foundation → vault and sessions → Stage 1 and tokens → round-trip proxy → contextual reviewer → full evaluation**. Create synthetic fixtures during the foundation phase and expand them throughout implementation; do not wait until evaluation to generate ground truth.

### Phase 1 — Foundation and API contract

**Tasks**

1. Create the Python package, dependency manifest/lock, README, `.gitignore`, and configuration example. Use the document's proposed `shield/`, `eval/`, `tests/`, and `demo/` structure.
2. Define typed contracts for detected spans, token mappings, session records, protection reports, and API errors. Span offsets use Python string indices, including Unicode.
3. Implement validated configuration: upstream URL and timeouts, detector mode, threshold, allowlist, vault location, session TTL, and localhost binding.
4. Define an explicit supported request/response field list, nested Pydantic models with `extra="forbid"`, and error behavior. Include `stream` as a supported boolean. Keep API credentials in environment variables; collect the passphrase through a non-echoing prompt when persistent sessions are enabled.
5. Add a fake upstream that captures outgoing requests and returns controlled token-bearing responses. Start with synthetic examples only.
6. Add request-size and timeout limits. A locked vault cannot create or serve persistent sessions; default ephemeral requests do not require the vault.

**Deliverables:** runnable package skeleton, configuration loader, request contracts, fake upstream, initial synthetic fixtures.

**Acceptance:** the app binds to `127.0.0.1`; invalid configuration fails clearly; unsupported payloads are rejected; no raw passphrase or provider key is logged. Any early passthrough scaffold forwards only to the fake upstream until sanitization is implemented.

### Phase 2 — Vault and session lifecycle

**Tasks**

1. Implement the revised SQLite schema for optional persistent sessions with explicit schema versioning, foreign keys enabled, transactional inserts, and restrictive file permissions where supported. Add a 32-byte `entity_digest` column, unique per session, and authenticate it in the entry AAD; ephemeral requests write no keys or mappings to SQLite.
2. Generate the vault salt and derive the 32-byte vault key using the documented Argon2id parameters. Store KDF parameters and an authenticated unlock verifier.
3. Encrypt persistent entry values with AES-GCM using fresh 96-bit random nonces. Encode AAD unambiguously with a domain label, schema version, session ID, token, entity type, and full HMAC digest so digest tampering or swapping fails authentication.
4. Generate a fresh HMAC key for every ephemeral request and keep it in memory only. Wrap HMAC keys only for explicitly persistent sessions; use distinct, domain-separated AAD for wrapped keys and the verifier.
5. Implement optional persistent session creation, lookup, restart recovery, TTL enforcement, and session deletion. Release ephemeral mappings and keys in a `finally` path on success, failure, timeout, or cancellation; remove expired persistent keys from caches and delete their entries transactionally. Do not promise secure memory erasure or destruction of old database copies.
6. Define concurrent-request behavior so deletion or expiry cannot race an active persistent request into inconsistent mappings or send a request whose persistent mappings were not committed. Ensure ephemeral state is isolated between requests.

**Deliverables:** `vault.py`, `session.py`, unlock flow, session endpoints, vault tests.

**Acceptance:** default requests persist no mappings or session keys and cannot be resumed; explicit persistent sessions reopen with the correct passphrase; wrong passphrases fail; modified ciphertext, nonces, AAD, full digests, and swapped rows fail authentication; expired/deleted sessions cannot be used through the API; seeded plaintext is absent from database files, including journal/WAL files. Document deletion limitations for backups and freed memory.

### Phase 3 — Stage 1 detection and deterministic pseudonyms

**Tasks**

1. Configure Presidio and spaCy for PERSON, EMAIL_ADDRESS, PHONE_NUMBER, CREDIT_CARD, US_SSN, LOCATION/ADDRESS, and IP_ADDRESS. Verify actual recognizer availability rather than assuming every listed type is supplied by the library.
2. Add DATE_OF_BIRTH, API_KEY/SECRET, and configurable EMPLOYEE_ID recognizers. Make phone region and location/address policy configurable.
3. Implement span bounds validation, confidence filtering, allowlist behavior, and overlap resolution. Include adjacent spans, nested spans, repeated text, and Unicode fixtures.
4. Define normalization per entity type. Derive HMAC tokens using the session key and the document's type-separated input format; maintain a stable mapping from detector types to token labels.
5. Compute and retain the full 256-bit HMAC digest for each entity. Reuse the token when `(session_id, entity_digest)` matches; equal truncated suffixes with different full digests trigger extension from 4 to 6 to 8 characters, with a defined further-extension fallback. Keep digest lookup, collision checks, and inserts atomic; never compare decrypted raw values to decide identity. Restore the first observed spelling for a normalized entity and never casefold secrets.
6. Substitute spans from right to left to preserve original offsets. Preserve known session tokens when prior conversation turns already contain them; define handling for user text that resembles tokens.
7. Implement `/shield/analyze` with original-text span coordinates, sanitized text, protection counts, and separate allowlisted-disclosure counts. Without a session header, use ephemeral mappings and discard them before return; tokens are preview-only. With an explicit persistent session, store mappings so its tokens remain usable.

**Deliverables:** `detect/stage1.py`, `recognizers.py`, `resolve.py`, `pseudonym.py`, analysis endpoint, labeled synthetic dataset generator.

**Acceptance:** seeded entity cases produce expected spans; repeated normalized entities reuse tokens; different requests without a session header use independent keys; explicit sessions reuse their key; repeated digest identity reuses the first spelling without decryption; forced collisions extend deterministically without overwriting a mapping; replacement preserves surrounding text. Detector misses remain evaluation findings rather than hidden test exclusions.

### Phase 4 — Protected round-trip proxy and rehydration

**Tasks**

1. Implement the gateway pipeline over every supported message role, including previous assistant responses containing restored PII.
2. Register mappings in the active request store before any network send; commit them to SQLite only for persistent sessions. Run the final Stage 1 guard over every user-controlled text field in the exact serialized outgoing payload, accounting for JSON escaping when scanning text values. Recognize generated placeholders so the guard does not flag them as new identifiers.
3. Block requests with remaining high-confidence, non-allowlisted PII. Exercise this path with deliberately incomplete masking.
4. Implement the asynchronous HTTP client with verified TLS, configured timeouts, safe error handling, and bounded retry policy. Restrict retries to cases with a defined duplication/cost policy; never retry a detector or vault failure as an upstream call.
5. Restore exact known tokens first, then case, separator, bracket, Markdown, possessive, and line-break variants. Match complete type/suffix pairs against the current session; never use fuzzy edit-distance or guessed-token restoration.
6. Fetch upstream with `stream: false` for both client modes. Rehydrate all supported assistant text outputs and multiple choices. Return ordinary JSON for `stream: false`; for `stream: true`, use `text/event-stream`, emit `chat.completion.chunk` events with a role/content delta per choice, a finish-reason chunk, optional supported usage information, and a final `data: [DONE]` event. Preserve chunk IDs and choice indices; generate frames with a JSON serializer. Document buffering latency and that provider usage counts refer to the tokenized exchange.
7. Leave unknown token-like strings unchanged and count them. Return `X-Shield-Report` with protection counts and separate allowlisted-disclosure counts; return `X-Shield-Session` only for an explicitly selected persistent session. Restore the complete response before releasing ephemeral state, including when delivering SSE.
8. Implement PII-free structured metrics and safe exceptions. Disable request/response body logging and avoid persisting reviewer reasons or upstream error bodies that may repeat sensitive text.
9. Finish `/shield/health`, including optional-vault readiness, ephemeral-mode availability, and Stage 2 availability without exposing credentials or sensitive configuration.

**Deliverables:** `app.py`, `upstream.py`, `rehydrate.py`, `metrics.py`, end-to-end integration tests and demo.

**Acceptance:** captured upstream payloads contain none of the detected fixture values; responses restore only the active session's mappings; known token variants restore correctly; errors and logs do not disclose seeded values; failures before forwarding result in zero upstream requests. Ephemeral cleanup and explicit-session reuse, expiry, deletion, and malformed inputs behave consistently. An SSE client can parse role/content, choice indices, finish reasons, and `[DONE]`; no SSE response headers are committed until upstream success and rehydration, so pre-delivery failures return normal HTTP errors.

**Milestone:** the Stage 1 MVP is usable after this phase. Run a small E2 threshold/utility pilot before spending time on Stage 2.

### Phase 5 — Local contextual review

**Tasks**

1. Install/configure Ollama with a locally available model and measure its latency on the target machine. Follow the document's LangChain approach with pinned dependencies; hide it behind a small reviewer interface.
2. Send Stage 1-masked text only to the local reviewer. Implement the offset/source map established in Phase 1.
3. Require schema-valid structured output with exact text and positions. Validate bounds and text equality, map back to original offsets, and merge accepted additions.
4. Enforce that the reviewer cannot remove accepted Stage 1 detections. Treat document text and prompt-injection attempts as untrusted data.
5. Implement bounded output size, timeout, and `fail_closed`/`fail_open` behavior. Fail closed by default in Stage 2 modes; report Stage 1-only fallback in headers and metrics when explicitly configured.
6. Keep `fast` mode independent of Ollama availability. Run the final guard after both stages.

**Deliverables:** `detect/stage2.py`, mode orchestration, source mapping, reviewer validation and failure tests.

**Acceptance:** contextual spans map to correct original characters after multiple length-changing replacements; invalid or ambiguous spans are discarded; injected instructions cannot remove Stage 1 results; a local-model outage follows the selected policy; no contextual review request goes to a cloud service.

### Phase 6 — Evaluation, paper artifacts, and demo

**Tasks**

1. Generate approximately 150 synthetic emails, support tickets, and notes with exact labeled offsets and reproducible seeds. Include each entity type and difficult negatives.
2. Prepare approximately 40 utility prompts covering summarization, reply drafting, and extraction. Separate tuning fixtures from final evaluation examples.
3. Add Presidio and TAB dataset loaders after checking access, licensing, and label mappings. Use synthetic data as the independent fallback; do not upload real labeled identifiers to the provider for baseline comparisons.
4. Implement per-type precision, recall, and F2 with documented exact and overlapping-span matching rules. Compute leakage against the captured outgoing payload, including entity values repeated across messages. Report allowlisted disclosures separately and also include them in total verbatim disclosure; they must not disappear from the overall leakage denominator.
5. Record utility scores, extraction exact match, rehydration fidelity, and added latency. Use fixed upstream/judge configurations, a written scoring rubric, and blinded answer ordering where practical. Use synthetic PII for cloud baseline and judging calls.
6. Record configuration, seeds, model identifiers, machine specifications, sample counts, and failures. Keep raw PII-bearing evaluation artifacts local; exported tables and logs contain aggregate results.
7. Run the experiments below, produce plots and CSV/JSON summaries, and explain small-sample uncertainty and detector limitations.
8. Prepare setup instructions, an architecture/threat-model update, a scripted synthetic demo, and the paper/poster figures.

| Experiment | Dependency                               | Comparison and artifact                                                                                                          |
| ---------- | ---------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| E1         | Phase 3; Phase 5 for the full comparison | Stage 1 vs. Stage 1 + Stage 2: per-type detection table. MVP reports Stage 1 baseline only.                                      |
| E2         | Phase 4                                  | Thresholds 0.2–0.9: leakage–utility curve. MVP runs Stage 1 only; extended build repeats with Stage 2.                           |
| E3         | Phase 4                                  | Random vs. deterministic tokens: utility change; keep each random mention reversible and hold other settings constant.           |
| E4         | Phase 4                                  | Exact vs. tolerant restoration: fidelity and false-restoration counts. Use controlled token variants as well as model responses. |
| E5         | Phase 2                                  | Modified, swapped, and truncated vault records: authentication-failure evidence.                                                 |
| E6         | Phase 4; Phase 5 for all modes           | Warm and cold latency, median and p95, stage breakdown, sample count, and local hardware.                                        |

**Acceptance:** commands reproduce the reported runs; metric denominators and matching rules are documented; privacy–utility plots use comparable task/configuration settings; failures are counted; results distinguish measured leakage from broader inference risk.

## 4. Proposed eight-week schedule

The source allocates approximately **20 hours total**. Treat this as a constrained prototype budget, not a reliable estimate for all functionality, security tests, six experiments, paper, and poster. The following schedule preserves the eight-week sequence but allocates additional effort. These are planning estimates, not measured implementation times.

| Week | Focus                                  | Exit deliverable                                              | Estimated effort |
| ---- | -------------------------------------- | ------------------------------------------------------------- | ---------------- |
| 1    | Phase 1 and decision records           | Contracts, configuration, fake upstream, fixtures             | 4–6 hours        |
| 2    | Phase 2                                | Unlockable vault, sessions, tamper tests                      | 6–8 hours        |
| 3    | Phase 3                                | Stage 1, custom recognizers, `/shield/analyze`, stable tokens | 7–10 hours       |
| 4    | Phase 4 gateway and guard              | Sanitized forwarding, supported API contract, safe errors     | 5–7 hours        |
| 5    | Phase 4 rehydration and MVP evaluation | JSON/SSE round-trip demo, E4/E5, small Stage 1 E1/E2 baseline | 5–7 hours        |
| 6    | Phase 5                                | Local reviewer, offset mapping, failure behavior              | 6–9 hours        |
| 7    | Phase 6 evaluation                     | E1–E6 tables, curve, latency report                           | 6–10 hours       |
| 8    | Documentation and presentation         | Paper figures, poster, reproducible demo                      | 4–6 hours        |

**Estimated total: 43–63 hours**, excluding major dependency/hardware problems and substantial paper revision. Benchmark the first two weeks and revise the remaining estimate.

If 20 hours is a hard limit, target a narrower demonstrator: supported text-only messages, Stage 1, ephemeral mappings, a small optional persistent-session vault, buffered SSE, exact restoration with a small set of tolerant variants, the guard, synthetic integration tests, and a small E1/E2 pilot. Defer Stage 2, external datasets, E3, broad performance sweeps, and presentation polish. Keep vault integrity and prevention of forwarding after failures as completion requirements. Reassess feasibility after the foundation and vault work.

## 5. Verification strategy

Use focused tests tied to the main failure modes rather than duplicating every implementation detail:

- **Vault:** wrong passphrase, row swapping, modified AAD/ciphertext/full digest, persistent restart, deletion, expiry, plaintext-at-rest inspection, and zero persistence for ephemeral requests.
- **Detection and offsets:** every supported entity type, repeated substrings, Unicode, overlap rules, allowlist consistency, and Stage 2 source mapping.
- **Tokens:** normalization behavior, full-digest reuse without decryption, secret case sensitivity, ephemeral key isolation, forced suffix collisions, concurrent insertion, existing tokens, and token-looking user text.
- **Restoration:** controlled variants, suffix length changes, unknown tokens, false matches, and cross-session isolation. Use property tests for token/text combinations where they add coverage.
- **Gateway:** captured final payload, all supported roles/fields, nested unknown-field rejection, blocked requests making zero upstream calls, optional locked vault, reviewer failure, timeouts, malformed provider responses, ephemeral cleanup on exceptions/cancellation, unknown session errors, and separate allowlist accounting. Parse buffered SSE with a compatible client, including multiple choices and finish events.
- **Logging:** scan success, failure, and exception output for seeded PII, API credentials, and reviewer text.

Run unit/integration tests against the fake upstream first. Use a synthetic provider smoke test only after the guard and payload-capture checks pass.

## 6. Main risks and response

| Risk                                         | Response                                                                                                                                                                        |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Detector misses or contextual inference      | Measure leakage and state the limitation; never turn fixture success into a universal privacy guarantee.                                                                        |
| Stage 2 latency or insufficient local memory | Benchmark early in its phase; retain Stage 1 mode and report the privacy/latency tradeoff.                                                                                      |
| Dependency/model installation changes        | Pin compatible versions and document reproducible installation; confirm APIs during implementation.                                                                             |
| Excessive provider evaluation cost           | Run a small pilot, estimate calls before the full sweep, cache synthetic responses locally, and expose a configurable budget. The source's under-$10 figure remains unverified. |
| Real PII or secrets entering the repository  | Use synthetic fixtures, ignore vaults and raw evaluation outputs, and add a secret scanner before sharing changes.                                                              |
| Overstated deletion or compatibility claims  | Document backup/key retention and the supported API subset; keep unsupported modes explicit.                                                                                    |

## 7. Completion checklist

- All supported text reaches the provider only through detection, substitution, and the final guard; approved allowlisted disclosures are counted explicitly.
- Vault/session integrity and rehydration tests pass, including adversarial failure cases.
- Ephemeral defaults, optional persistent-session continuity, buffering delay, and the supported Chat Completions subset are documented.
- Logs and shared artifacts pass seeded-PII/secret checks.
- The selected MVP or full-build experiments reproduce from documented commands.
- The evaluation reports residual leakage, utility loss, restoration behavior, and latency honestly.
- The demo uses synthetic data, exercises both JSON and buffered SSE, and works with the fake upstream when internet access is unavailable.
- Final documentation records normalization tradeoffs, allowlist disclosures, deletion limits, and deferred scope.
