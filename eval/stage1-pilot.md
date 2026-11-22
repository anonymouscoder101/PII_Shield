# Stage 1 threshold pilot

This is the small Phase 4 milestone, completed as catch-up after Stage 2 was
implemented. It uses the real installed Stage 1 model, production preparation,
guard, HTTP client, and response restoration, with an in-process fake upstream.
No cloud provider, local reviewer, public API route, persistent vault, or
semantic utility judge participates. The full Phase 6 evaluation is deferred.

The [aggregate artifact](benchmarks/stage1-pilot-2026-11-22.json) records the
actual run time, seed, canonical dataset hash, package/model versions, settings,
denominators, failures, and latency. Reproduce it using the commands in
[the evaluation README](README.md). The pilot contains 36 cases (six per
template), including six negatives, and 144 labeled occurrences across all
twelve Stage 1 types. It uses seed 1729, generator version 1, Faker 40.40.0,
Presidio 2.2.364, spaCy 3.8.16, and `en_core_web_lg` 3.8.0. The default US phone,
all-location, numbered-street-address, and employee-ID policies apply. Mode is
explicitly fast, with threshold overrides 0.3, 0.5, and 0.6; Stage 2 is disabled.

One generated email value is intentionally allowlisted, identified in the
artifact by case/entity reference. It remains in every disclosure denominator.
No raw request/response, credential, entity value, or outgoing capture is
exported. The generated dataset stays in its ignored local directory.

## Scoring

Detection scores evaluate **resolved policy redaction spans**, after confidence,
allowlist, and overlap handling. They are not raw recognizer recall. Every label
is counted, including the deliberately allowlisted one, which may therefore be
a false negative for this policy metric. Exact matches require the same case,
message, entity type, start, and end. Overlap matches require the same case,
message, and entity type with any nonempty intersection. Both use maximum
one-to-one matching: a prediction cannot claim several true positives. Unmatched
predictions are false positives and unmatched labels are false negatives.
Precision is TP/(TP+FP), recall TP/(TP+FN), and F2 is
5TP/(5TP+4FN+FP). Undefined ratios are JSON null. Overlap credit is deliberately
optimistic and does not prove the whole identifier was protected.

Verbatim disclosure is measured against the actual fake upstream's captured
outgoing JSON, with string values decoded before comparison. For each message,
type, and labeled value, count its surviving literal occurrences, capped at the
original number of occurrences. Repeated values across messages stay separate.
Residual disclosure excludes configured allowlist values; total disclosure
includes them. Both rates divide by all 144 labeled occurrences. The separate
detector-reported allowlist counter records what the detector actually matched;
it can differ from configured values found verbatim below the threshold.
Blocked/failed cases remain in denominators and get zero utility credit; a case
that never forwards contributes zero outgoing disclosures. A captured request
still counts as exposure if its response subsequently fails.

The deterministic fake provider extracts Action/Contact lines from the sanitized
first message. Production restoration then runs before comparison with the
original fields. Whole-answer exact match compares the entire response,
including whitespace. Field exact match compares the two expected lines,
ignoring a final newline; missing lines lose credit and extra lines invalidate
field extraction. The unprotected copy baseline is 100% by construction. This
is a narrow extraction-and-restoration proxy, **not LLM or semantic utility**:
it does not measure summarization quality, reply quality, reasoning, or how a
real provider preserves tokens.

To control token-dependent detector context, this offline runner constructs a
fresh production `EphemeralSession` for every case and replaces its unused key
with a synthetic evaluation key derived from the dataset seed and case ID.
The same case uses the same key across thresholds. This injection stays inside
the evaluation module; runtime configuration and production key generation are
unchanged. Predictable evaluation keys must never protect real PII.

## Results

The table below is taken from the linked aggregate artifact. Counts describe
this synthetic sample, not a population estimate or universal protection claim.
| Threshold | Exact precision / recall / F2 | Residual / all labels | Allowlisted | Total verbatim / all labels | Copy/restore exact cases | Median / p95 ms |
| --- | --- | --- | --- | --- | --- | --- |
| 0.3 | 0.899 / 0.743 / 0.770 | 24/144 | 1 | 25/144 | 33/36 | 95.6 / 197.4 |
| 0.5 | 0.894 / 0.701 / 0.733 | 30/144 | 1 | 31/144 | 33/36 | 90.3 / 172.0 |
| 0.6 | 0.867 / 0.542 / 0.586 | 53/144 | 1 | 54/144 | 33/36 | 87.5 / 142.2 |

At threshold 0.5, the per-type exact policy scores and verbatim findings are:

| Type | Labels | TP / FP / FN | Precision | Recall | F2 | Residual disclosures |
| --- | --- | --- | --- | --- | --- | --- |
| ADDRESS | 12 | 5 / 0 / 7 | 1.000 | 0.417 | 0.472 | 3 |
| API_KEY | 6 | 6 / 0 / 0 | 1.000 | 1.000 | 1.000 | 0 |
| CREDIT_CARD | 6 | 6 / 0 / 0 | 1.000 | 1.000 | 1.000 | 0 |
| DATE_OF_BIRTH | 12 | 6 / 0 / 6 | 1.000 | 0.500 | 0.556 | 6 |
| EMAIL_ADDRESS | 30 | 23 / 0 / 7 | 1.000 | 0.767 | 0.804 | 6 |
| EMPLOYEE_ID | 6 | 6 / 0 / 0 | 1.000 | 1.000 | 1.000 | 0 |
| IP_ADDRESS | 6 | 6 / 0 / 0 | 1.000 | 1.000 | 1.000 | 0 |
| LOCATION | 6 | 6 / 1 / 0 | 0.857 | 1.000 | 0.968 | 0 |
| PERSON | 36 | 19 / 11 / 17 | 0.633 | 0.528 | 0.546 | 9 |
| PHONE_NUMBER | 12 | 6 / 0 / 6 | 1.000 | 0.500 | 0.556 | 6 |
| SECRET | 6 | 6 / 0 / 0 | 1.000 | 1.000 | 1.000 | 0 |
| US_SSN | 6 | 6 / 0 / 0 | 1.000 | 1.000 | 1.000 | 0 |

Every threshold forwarded all 36 requests with zero guard blocks, zero pipeline
errors, and zero unknown response tokens. Field extraction was 66/72 at each
point. Exact copy/restore failures and detector misses are retained in the
results. The artifact includes per-type overlap scores for all thresholds.

## Interpretation and limits

At 0.6, all 30 labeled email occurrences remained verbatim, including the
intentional exception. At 0.5, the non-allowlisted residuals were nine person
occurrences, six obfuscated emails, six lower-context phones, six ordinal birth
dates, and three unnumbered addresses. Lowering the threshold to 0.3 removed the
six phone disclosures in this sample. Partial masking can remove a full literal
value while still revealing part of it; this metric does not count those partial
fragments or inferential disclosures. Detection scores and literal leakage
therefore answer different questions. The Stage 1 guard shares the detector's
blind spots and does not guarantee that all PII is removed.

The pilot is small, templated, and used during development. Repeated entity
occurrences are dependent observations, and the synthetic type distribution is
artificial. The unassigned-area SSNs, example surname, deliberately difficult
formats, and fixed card value further limit generalization. These cases do not
establish performance on real identities, languages, external datasets, or
arbitrary prompts. No misses were removed to improve the metrics. The proxy
provides evidence for a narrow extraction/restoration operation; it cannot
support conclusions about general model utility or a universal privacy–utility
frontier.

Latency is wall time for preparation (including the final guard), fake HTTP,
restoration, and ephemeral cleanup. Separate detector scoring passes,
per-threshold detector setup, model load, and output-file writing are excluded.
There are 36 request timings per point; first-call, remaining 35-call, and stage
summaries use a nearest-rank p95. Pipeline initialization is recorded separately
and is not a disk-cold model benchmark. The machine was macOS arm64 with Python
3.14.8; sandbox restrictions prevented fresh CPU/RAM queries, recorded as null.
Other local work, including model smoke tests and application tests, may share
the machine. Thresholds ran sequentially with uncontrolled system load and OS
caches, so latency differences are indicative and do not establish a threshold
speed ranking. No network, provider-generation, or Stage 2 latency is measured.

Phase 6 remains responsible for independent held-out evaluation, the broader
0.2–0.9 sweep, Stage 1 versus Stage 1+Stage 2, semantic utility prompts/judging,
external dataset access/licensing/mappings, and full E1–E6 publication artifacts.
