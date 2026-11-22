# Evaluation workspace

Phase 3 now includes a seeded synthetic dataset generator. The limited Phase 4
Stage 1 threshold pilot runs the real installed Presidio/spaCy detector against
an in-process fake upstream. It records detector misses, intentional allowlist
disclosures, extraction/restoration behavior, failures, and local latency.

From the repository root, after installing the locked development environment
and local Stage 1 model:

```bash
.venv/bin/python -m scripts.generate_dataset --seed 1729 --count 150 \
  --output eval/datasets/generated/synthetic-seed1729.json
.venv/bin/python -m scripts.generate_dataset --seed 1729 --count 36 \
  --output eval/datasets/generated/pilot-seed1729.json
.venv/bin/python -m scripts.pilot_stage1 \
  --dataset eval/datasets/generated/pilot-seed1729.json \
  --thresholds 0.3 0.5 0.6 --allowlist-first-email \
  --output eval/results/stage1-pilot.json
```

No network connection, provider credentials, Ollama server, or vault is needed.
The model must already be installed; the detector never downloads it. The pilot
calls the production preparation/guard, HTTP client, and restoration functions,
with HTTPX ASGI transport to the local fake provider. For reproducible comparisons,
only this offline runner uses seed-derived evaluation keys in fresh sessions;
production key generation stays random. It bypasses the public HTTP
route and explicitly omits Stage 2. Route, JSON/SSE, and failure behavior are
covered separately by the application integration tests and demo.

The generator output and local results are ignored by Git. Raw synthetic requests
and outgoing captures stay local; captures live only in memory and are cleared
between thresholds. `benchmarks/` contains a reviewed aggregate result with no
entity values or request/response text. The dataset hash is computed over sorted
JSON keys with UTF-8 Unicode content, rather than the pretty-printed file bytes.

See [datasets](datasets/README.md) for the ground-truth contract and
[the measured pilot](stage1-pilot.md) for scoring, results, and limitations. This
is catch-up evidence for the Phase 4 milestone, collected after Stage 2 was
implemented. Full Phase 6 E1–E6 comparisons, independent holdouts, semantic model
utility, external datasets, and publication plots remain future work.
