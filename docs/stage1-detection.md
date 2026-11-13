# Stage 1 detector

Phase 3 task 1 provides `shield/detect/stage1.py`. The detector returns candidate
`DetectedSpan` objects with Python string offsets, entity types, confidence
scores and `stage1`; it retains no source values in the returned contracts.
It does not yet redact, tokenize, enforce allowlists/thresholds, resolve overlaps
or forward requests. Those are subsequent tasks. The chat route continues to
return 503 and makes no provider calls.

## Setup and explicit loading

```sh
uv sync --locked --extra stage1
uv run --locked --extra stage1 python -c 'from shield.detect.stage1 import Stage1Detector; print(Stage1Detector.load().capabilities)'
```

The optional dependency pins `en_core_web_lg` **3.8.0** from the official spaCy
GitHub release. `uv.lock` contains its wheel SHA-256. spaCy is constrained to the
3.8 series and locked at 3.8.16; Presidio is locked at 2.2.364. The source model
inventory and label set are documented by [spaCy](https://spacy.io/models/en).
The full test suite requires this extra. Model installation is explicit; an
unavailable or differently versioned model produces a static `DetectorUnavailable`
error. Runtime code never invokes a model downloader. Use `--inexact` with
`uv sync` to preserve unrelated environment packages.

`Stage1Detector.load()` loads the local English pipeline, excluding the parser
while keeping NER, tokenization and lemmatization for Presidio context scoring.
Constructing or starting the app does not initialize detection yet. A caller
can also pass an already-loaded English `Language` to the constructor; this
validates its NER component and labels without downloading a model.

## Verified recognizers

The registry is explicitly populated; it does not load all default recognizers.
Initialization verifies actual registered entity providers and required spaCy
NER labels. `capabilities` reports entity-to-provider names and `ner_labels`
reports the inspected model labels. Missing capabilities fail initialization.

| Entity | Provider and current policy |
| --- | --- |
| `PERSON` | spaCy `PERSON` through Presidio `SpacyRecognizer` |
| `LOCATION` | spaCy `GPE`, `LOC` and `FAC` mapped to `LOCATION` |
| `EMAIL_ADDRESS` | Presidio email patterns, local syntax matching without suffix-list validation |
| `PHONE_NUMBER` | Presidio phone recognizer, fixed US region baseline |
| `CREDIT_CARD` | Presidio credit-card patterns and built-in checksum validation |
| `US_SSN` | Presidio US SSN patterns and built-in invalidation rules |
| `IP_ADDRESS` | Presidio IPv4/IPv6 patterns and built-in validation |
| `ADDRESS` | Shield numbered-English-street pattern, score 0.6 |

The official model has no `ADDRESS` label; `LOCATION` alone is not street-address
coverage. The address baseline matches a number, one to six Latin-letter name
words, and a common street suffix such as Street, Road, Avenue, Lane or Drive.
It excludes unit/city/postcode extensions, PO boxes, rural descriptions,
multiline/international addresses and names outside that alphabet. It can
produce false positives. Configurable phone and location/address policies are
Phase 3 task 2. `FAC` includes named facilities, not only private addresses.

The stock Presidio email validator uses `tldextract`, which can fetch suffix
metadata and reject internal or synthetic domains. This detector reuses the
upstream pattern without that validator: dotted addresses such as
`synthetic@example.test` are detected locally, without network calls or suffix
cache writes. It deliberately accepts syntactically matched unknown suffixes.

NER confidence uses Presidio's default 0.85, not a calibrated probability.
Pattern scores and contextual boosts also come from Presidio. US SSN validation
rejects canonical placeholder values such as `123-45-6789`; synthetically seeded
cases use other invented values and are never submitted to an upstream.
Recognizer availability does not establish recall or a no-leakage guarantee.
Detector misses remain evaluation findings; English statistical NER does not
reliably recognize every invented name or address.

## Candidate behavior and failure handling

`detect(text)` asks only for the audited entity set and requests Presidio scores
from zero upward. It returns spans sorted by start, end, type and descending
score. Presidio's built-in validation, context enhancement and same-type duplicate
suppression still apply. Shield confidence/allowlist/overlap policy is task 3;
configuration thresholds are not applied by this raw detector. Empty text returns
an empty list. All result types, scores and bounds are validated against the
original source before returning; malformed results fail the complete call.

One detector instance serializes calls to its mutable NLP pipeline. Gateway
integration must run this synchronous work off the event loop. Runtime failures
raise a static `Stage1DetectionError` without source text or library exception
messages. Presidio's source logger is filtered only in the current detection
context because its debug context logs can contain source words. Decision traces
are disabled. No global logger levels are changed and unrelated contexts are
unaffected.

Each pattern gets independent compiled state. A small regex iterator wrapper
converts timeout into a detection failure before Presidio can swallow
`TimeoutError` and return partial results. This depends on the locked Presidio
pattern interface and is tested explicitly; library upgrades must rerun the
integration tests. Model execution remains synchronous and cannot be forcibly
interrupted by an async deadline. Request-level timeout handling remains separate.
