# Offline synthetic round-trip demo

Run from the repository root. Install the locked environment and pinned English
spaCy model once (this installation requires network access):

```sh
uv sync --locked --extra stage1
```

After installation, the demo runs entirely offline:

```sh
.venv/bin/python -m demo.roundtrip
```

The command loads the actual Presidio/spaCy Stage 1 detector in `fast` mode and
sends two requests through the protected application. HTTPX `ASGITransport`
connects the application to an in-process fake provider; no listening server,
provider credentials, cloud service, Ollama installation, or vault is needed.
The fake provider echoes its sanitized input in two completion choices.

The output is a JSON transcript containing both JSON and buffered SSE exchanges.
For each exchange, inspect:

- `upstream_request`: the actual captured provider JSON with pseudonyms in every
  supported role (`system`, `developer`, `user`, `assistant`). The provider always
  receives `stream: false`, including for the SSE client request.
- `report`: five protected occurrences (two emails, one person, one phone number,
  and one employee ID), with no unknown response tokens.
- `response`: both choices restored to the original synthetic text. SSE is
  emitted after the complete upstream JSON response and restoration; the runner
  parses every JSON chunk and checks the choice indices, assistant roles, finish
  reasons, usage frame, and final `data: [DONE]` marker.

The top-level `checks_passed: true` means the checks completed. A failed request,
leaked fixture value, incomplete restoration, or invalid SSE exits nonzero.
The fixture is a demonstration of these detected values, not a recall guarantee
for arbitrary text. The fast-mode threshold also applies to detected candidates.

To keep a transcript locally, use the ignored captures directory:

```sh
mkdir -p demo/captures
.venv/bin/python -m demo.roundtrip > demo/captures/roundtrip.json
```

The transcript includes restored synthetic values for comparison. This runner
accepts no external input; do not replace its fixture with real personal data.
It writes no files unless output is redirected.

Run the integration test, which forbids outbound socket connections while using
the actual locally installed model:

```sh
.venv/bin/pytest tests/test_demo.py -q
```

The fake provider can also run independently with
`.venv/bin/python -m shield.fake_upstream` on `127.0.0.1:8001`. That command alone
exercises the provider; use the demo above for the protected round trip.
