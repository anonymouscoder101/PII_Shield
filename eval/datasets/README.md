# Datasets

[`fixtures/foundation.json`](fixtures/foundation.json) contains four hand-curated,
entirely synthetic examples introduced in Phase 1 task #5:

- Repeated person/email values across user and assistant messages, with system and
  developer instructions included in the conversation.
- Unicode names after an emoji, using Python string offsets.
- An invented employee ID, reserved example phone number, and fake API key.
- A clean negative with no labeled PII.

Each example contains `id`, `synthetic: true`, `request`, `sanitized_request`,
`entities`, and a controlled token-bearing `response`. Each entity records
`message_index`, `start`, `end`, `entity_type`, `value`, and `token`. Offsets are
half-open Python string indices into the original message content, not UTF-8 byte
or UTF-16 positions. Every repeated occurrence has a label; repeated values use
the same illustrative token. The fixture tokens are fixed examples, not computed
HMAC outputs. Clean examples can have responses without tokens.

The expected sanitized requests are ground truth for later protection tests;
they do not show that detection or substitution is implemented. These four cases
are development fixtures, not a measured detector evaluation or final holdout set.

Tests load and validate the fixture contracts and offsets, send each sanitized
request through the fake upstream, and verify its captured bytes and controlled
reply. To use a fixture response in a local test:

```python
import json
from pathlib import Path

import httpx

from shield.api import ChatCompletionResponse
from shield.fake_upstream import create_fake_upstream

case = json.loads(Path("eval/datasets/fixtures/foundation.json").read_text())[0]
reply = ChatCompletionResponse.model_validate(case["response"])
fake = create_fake_upstream(response_factory=lambda request: reply)

# Inside an async test/function:
async with httpx.AsyncClient(
    transport=httpx.ASGITransport(app=fake), base_url="http://fake"
) as client:
    response = await client.post("/v1/chat/completions", json=case["sanitized_request"])
assert response.status_code == 200
assert json.loads(fake.state.captures[0].body) == case["sanitized_request"]
```

The seeded generator is described below. External dataset loaders remain
later-phase work. Write generated local datasets to `generated/`, which is
ignored by Git.

## Seeded generator

Run `python -m scripts.generate_dataset` from the repository root in the project
environment. Defaults are seed 1729, 150 cases, and
`eval/datasets/generated/synthetic.json`; `--seed`, `--count`, and `--output`
are configurable. The output manifest records the generator schema/version,
seed, Faker version, locale, offset convention, and `synthetic_only: true`.
It has no clock-dependent fields: birthdays use explicit seeded year/month/day
ranges. The same seed/count and installed Faker version reproduce the manifest.

`cases` contains synthetic emails, tickets, and notes using six rotating
templates: contact email, technical support ticket, personal-detail note,
difficult contact formats, repeated conversation, and clean negative. Counts
that are multiples of six give equal template representation. With 24 or more
cases the tests verify all twelve configured Stage 1 types are represented.
Generation never drops a case because a detector misses it.

Each case has `id`, `synthetic`, `template`, an API-compatible `request`, and
`entities`. Entity records contain `message_index`, `start`, `end`, `entity_type`,
and `value`. They omit expected tokens: ephemeral tokens are random per request.
Every repeated occurrence receives its own label, including a prior assistant
message. Labels are collected while appending text, so emoji, combining marks,
and repeated substrings do not require ambiguous substring searches. Coordinates
are half-open Python Unicode string indices, matching the application contract.

All records are invented locally, without real records or credentials. Email
uses `.test`, IP uses `192.0.2.0/24`, US phone values use the fictional
202-555-0100–0199 range, cards use a published test value, employee IDs are
invented, and credentials contain `SYNTHETIC_ONLY`. Names use seeded Faker first
names with an example surname; Unicode examples and city names are synthetic
associations, not claims about real people. SSNs intentionally use unassigned
area 900: they test a sensitive-looking identifier without generating an
assignable SSN. A format/validity-aware recognizer may reject them. Type scores
therefore reflect this fixture construction rather than real-world prevalence.

Difficult cases include obfuscated email, ordinal birth dates, unnumbered
addresses, Unicode names, and lower-context phone numbers. Negatives include
version strings, short ratios, build numbers, and an employee-like non-match.
Action/Contact lines support a deterministic extraction/restoration proxy; they
are not an independent suite of generative utility prompts.

The original four foundation cases remain manually curated development fixtures.
Generated cases are also development/pilot data. Final holdouts, dataset
loaders, licensing review, and the broader Phase 6 prompt suite are deferred.
