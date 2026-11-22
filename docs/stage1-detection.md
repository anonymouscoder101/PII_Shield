# Stage 1 detector

Phase 3 tasks 1–3 provide `shield/detect/stage1.py`. The detector returns candidate
`DetectedSpan` objects with Python string offsets, entity types, confidence
scores and `stage1`; it retains no source values in the returned contracts.
`detect(text)` returns raw candidates; `analyze(text)` applies shared confidence,
allowlist and overlap policy. Token substitution and the chat pipeline consume
these results before forwarding guarded payloads. See
[span resolution](span-resolution.md) for ordering and report semantics.

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
| `PHONE_NUMBER` | Presidio phone recognizer, configured regions (US by default) |
| `CREDIT_CARD` | Presidio credit-card patterns and built-in checksum validation |
| `US_SSN` | Presidio US SSN patterns and built-in invalidation rules |
| `IP_ADDRESS` | Presidio IPv4/IPv6 patterns and built-in validation |
| `ADDRESS` | Shield numbered-English-street pattern, score 0.6 |
| `DATE_OF_BIRTH` | Labeled calendar dates (ISO, slash numeric, English month names) |
| `API_KEY` | API/access-key assignments and selected key-prefix heuristics |
| `SECRET` | Secret/password/token assignments and Bearer credentials |
| `EMPLOYEE_ID` | Configured whole-identifier regex, enabled by default |

The official model has no `ADDRESS` label; `LOCATION` alone is not street-address
coverage. The address baseline matches a number, one to six Latin-letter name
words, and a common street suffix such as Street, Road, Avenue, Lane or Drive.
It excludes unit/city/postcode extensions, PO boxes, rural descriptions,
multiline/international addresses and names outside that alphabet. It can
produce false positives. Phone and location/address policy can be configured
as described below. `FAC` includes named facilities, not only private addresses.

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
score. Presidio's built-in validation and context enhancement still apply. The
candidate adapter preserves nested matches across patterns and recognizers until
Shield applies threshold/allowlist policy. Configuration thresholds are not applied by this raw
detector; call `analyze(text)` to apply the shared policy snapshot. Empty text returns
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


## Custom recognizers and coverage policy

`Stage1Detector.load(config=settings.detection)` and
`Stage1Detector(nlp, config=settings.detection)` both apply a validated
`DetectionConfig`. Configuration loading does not load a model. Defaults enable
all twelve entity types. Disabled types are removed from the requested entity set
and capability report, rather than being falsely advertised as active.

```yaml
detection:
  phone_regions: [US, GB]
  location_policy: all
  address_policy: street
  employee_id_enabled: true
  employee_id_pattern: '\bEMP-\d{4,8}\b'
```

`phone_regions` must be nonempty, unique, uppercase region codes supported by the
installed `phonenumbers` package. It controls interpretation of national numbers;
explicit international prefixes can be recognized regardless of default region.
`location_policy` is `all` (GPE/LOC/FAC), `places` (GPE/LOC), or `none`.
`address_policy` independently selects `street` or `none`. Disabling a type is an
intentional coverage reduction. The street baseline's limitations above remain.

`employee_id_pattern` defaults to whole identifiers like `EMP-123456`, with four
to eight digits. It is matched case-insensitively, preserving original text and
coordinates. Supply a regex whose complete match is the identifier; use
lookarounds or `\K` if labels should be excluded. The pattern is limited to 512
characters, compiled during configuration validation, and rejected if it matches
empty input. Other zero-width matches fail the scan at runtime instead of silently
reporting no employee IDs. Regex timeouts abort the scan. `employee_id_enabled:
false` disables this recognizer; its configured pattern is still validated.

Birth dates require a label such as `DOB`, `date of birth`, `birth date`, or
`born on`. Label separators can be whitespace, colon or equals. Dates are ISO
`YYYY-MM-DD`, slash-separated day/month/year or month/day/year with a four-digit
year, or day plus English month name and year. Calendar validation rejects
impossible dates and invalid leap days. Ambiguous slash order does not affect
masking because the original spelling is retained; no semantic date normalization
is done here. English month parsing is independent of process locale. A valid
labeled future or historical calendar date is still a candidate; there is no
age plausibility filter. Generic unlabeled dates are not birth dates.

API-key assignments recognize `api_key`/`access_key` (including space/hyphen/camel
variants). Prefix heuristics recognize `sk-`, `gh[pousr]_`, `github_pat_`, and
`AKIA` shapes with minimum lengths; this is not an exhaustive provider inventory
or a credential validity check. Assigned secrets include `secret`, `secret_key`,
`client_secret`, `api_secret`, `password`, `passwd`, `access_token`, `auth_token`,
and `aws_secret_access_key` variants. They require `:` or `=`. Bearer tokens
require whitespace after `Bearer` and at least eight token characters.

Assigned values can be double/single quoted (including spaces and escaped
characters), backtick quoted, or unquoted non-whitespace text. Bare values include
internal punctuation such as apostrophes, commas and semicolons; punctuation is
not a safe credential boundary. This conservative choice may also consume adjacent
syntax or another assignment without intervening whitespace. Quote values or use
whitespace to separate fields. Quoted values cannot span physical newlines.
Even short nonempty assigned values are candidates. Patterns return only the
value via `\K`, excluding labels and delimiters. Exact source spelling and
Unicode offsets are preserved. Ordinary prose, arbitrary unlabelled secret
strings, other provider formats, and malformed assignments may be missed;
false positives are also possible. No entropy-based secret discovery is claimed.

Custom pattern scores start at 0.85. Presidio upgrades calendar-validated DOB
scores to 1.0; these are heuristic scores, not probabilities. An API-shaped
secret may produce both `API_KEY` and `SECRET` candidates. `analyze(text)` applies
the shared threshold/allowlist policy and deterministic overlap resolution.
