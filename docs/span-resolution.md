# Span filtering and overlap policy

Phase 3 task 3 adds `shield/detect/resolve.py`. `SpanPolicy` takes a snapshot of
`DetectionConfig.effective_threshold` and the literal allowlist so the detector
and pre-send guard share one policy. The snapshot holds no source
text; subsequent mutations to a configuration list cannot change its decisions.

Use `Stage1Detector.load(config).analyze(text)` for detection plus resolution,
or `SpanPolicy(config).resolve(text, candidates)` for already-detected original
coordinates. `detect(text)` remains available for raw candidate inspection and
evaluation. [Substitution](substitution.md) and the
[HTTP analysis endpoint](api-contract.md#local-analysis-endpoint) now use this policy. The gateway guard uses the same detector/policy configuration.

## Decision order

1. Validate every candidate against the source before filtering. All offsets are
   half-open Python string indices, including Unicode. Negative, empty, reversed
   or out-of-range spans, non-enum types/stages, and nonfinite/out-of-range scores
   fail the complete call. Reconstruction validates even contracts forged with
   `model_construct` or `model_copy`. Invalid low-confidence candidates are errors
   too; they are not silently discarded.
2. Deduplicate `(start, end, entity_type)` candidates. Retain the highest score;
   tied stages use their lexical names, so `stage1` precedes `stage2`. Different
   occurrences of the same source value remain independent. No decrypted/raw
   entity identity comparison is involved.
3. Filter scores **below** the effective threshold. Equality passes. Explicit
   configuration overrides the mode default, including thresholds zero and one.
   `below_threshold_count` counts unique candidates discarded here.
4. Compare each surviving candidate's **entire source slice** with the allowlist.
   Matching is literal, case-sensitive and Unicode-code-point exact: no case
   folding, Unicode normalization, trimming, regex or substring matching. Record
   exempt candidates in `allowlisted_spans`; they do not enlarge redactions.
5. Sort the remaining accepted spans by coordinates and merge strict overlaps
   transitively. `[0, 4)` and `[3, 8)` merge; `[0, 4)` and `[4, 8)` remain separate.
   A low-confidence or allowlisted bridge cannot connect accepted components.

Each merged component uses the union of its accepted bounds. Select a member by
this ascending tuple:

```text
(not_opaque_type, -confidence, entity_type.value, start, end, stage.value)
```

The component retains that member's type, confidence and stage. Accepted opaque
types (`SECRET`, `API_KEY`, `EMPLOYEE_ID`) take precedence so an overlapping name
cannot casefold a credential. Within that safety class, the highest confidence
wins; score ties choose the alphabetically first type, then earliest start/end
and lexical stage. Without an opaque member, the original highest-confidence
rule applies. Threshold and allowlist filtering still happen first. A component's score is not averaged
or boosted. Its stage identifies the winning member, not every contributing
stage. Output spans are ordered, disjoint, and invariant to candidate input order.
Presidio's own validation and context enhancement occur before this policy.
`candidates.py` bypasses its cross-recognizer containment deduplication, and runs
singleton pattern copies so one pattern's outer span cannot discard another's
nested span. Without this adapter an allowlisted outer value could hide a nested
non-allowlisted credential before policy ran. Exact deduplication belongs to the
policy; no containment pruning runs across candidate patterns beforehand.

## Allowlist reporting and overlap

`ResolvedDetections` contains immutable span tuples, `below_threshold_count`, and
a `ProtectionReport`. It contains no extracted source values. The report's
`protected_counts` count final merged redaction components by their winning type.
`unknown_token_count` remains zero until restoration supplies that separate metric.

An allowlisted candidate can overlap another non-allowlisted accepted span.
The latter still redacts its complete bounds; allowlisting never cuts a hole
inside another accepted redaction. Keep every unique threshold-passing allowlist
decision in `allowlisted_spans` for later inspection, even if another span hides
all of it. These are decisions, not a promise that the full term remains visible.

For `allowlisted_disclosure_counts`, exclude candidates whose complete interval is
covered by redactions, including coverage by multiple adjacent spans. Count a
partly visible candidate as a disclosure, since some of its characters remain
exposed. Merge overlapping remaining allowlisted candidates with the same winner
rule for report counts, preventing duplicate `API_KEY`/`SECRET` observations of
one credential from counting twice. Separate occurrences and adjacent intervals
remain separate. Partially masked cases therefore count an intentional disclosure
without claiming the original value was exposed in full.

This is occurrence accounting based on accepted detections, not a measurement of
detector recall or all possible residual leakage. Below-threshold candidates are
not intentional allowlist disclosures. Evaluation must still measure misses.

## Failures and resource behavior

Failures raise static `SpanResolutionError("Span resolution failed.")`, without
logging input values, field paths or underlying exception text. Candidate-iterator
failures also abort the entire result. Policy work holds no vault keys and makes
no network calls. It sorts candidates and sweeps overlap groups; coverage queries
use coalesced redaction runs and binary search. Neither the source nor extracted
slices are retained in the output. Pydantic contracts are frozen at the top level;
the existing report dictionaries follow the shared contract's normal mutability.


The candidate adapter retains original recognizer identities on its singleton
copies so Presidio context scoring and validation hooks remain active. It uses
the locked analyzer's context-enhancement hook, makes no global monkey patches,
and returns no analysis explanations. The full real-model suite, including a
nested assigned/Bearer secret regression, must pass on Presidio upgrades. Regex
matching within each pattern still follows the regex engine's normal match
semantics; this adapter does not guarantee discovery of every nested entity.
