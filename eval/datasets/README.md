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

Generators and external dataset loaders remain later-phase work. Write generated
local datasets to `generated/`, which is ignored by Git.
