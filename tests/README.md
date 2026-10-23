# Tests

`test_contracts.py` checks shared contract boundaries: Python Unicode offsets,
full digest length, masked mapping values, session lifetimes, separate allowlist
accounting, and nested error validation.

`test_config.py` checks YAML validation, threshold precedence, safe defaults,
relative vault paths, localhost binding, and CLI startup/error behavior without
starting a server or contacting an upstream.

Run `uv run --locked pytest`. Future integration tests will use a fake upstream;
all fixtures must use synthetic values. The detailed verification strategy is in
`IMPLEMENTATION_PLAN.md`.
