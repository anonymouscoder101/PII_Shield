# Demo

Reserved for the scripted synthetic JSON and buffered SSE round-trip demo.
The current package scaffold does not forward requests or protect PII.

The synthetic upstream can already be run independently with
`uv run --locked python -m shield.fake_upstream` on `127.0.0.1:8001`.
See [the setup and curl example](../README.md#run-the-fake-upstream) and
[the labeled fixtures](../eval/datasets/README.md). This exercises the fake provider
only; the protected round trip and buffered SSE demo arrive in later phases.

Store any local captured exchanges under `captures/`, which is ignored by Git.
