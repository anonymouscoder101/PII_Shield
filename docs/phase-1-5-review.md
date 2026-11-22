# Phases 1–5 completion review

This review compares the repository with the tasks, deliverables and acceptance
criteria in [the implementation plan](../IMPLEMENTATION_PLAN.md). It covers the
single-user text-only localhost build through contextual review. Phase 6's full
experiments, external dataset loaders, paper and poster remain separate work.

The identified implementation and deliverable gaps are closed. Final combined
verification: `.venv/bin/python -m pytest -q` reported **746 passed**;
`ruff check .`, `ruff format --check .` (101 files), and `git diff --check`
passed. The executable offline demo passed both delivery modes with five
protected occurrences each. Independent review rechecked cleanup ownership under
forced garbage collection and reproduced every non-latency aggregate in the
36-case threshold pilot. These checks establish the implemented scope, subject
to the measurement and runtime limits below.

## Coverage

| Phase | Implementation and evidence |
| --- | --- |
| 1: foundation | Strict nested contracts and supported API subset, validated configuration, environment credentials and non-echoed vault prompt, local fake upstream, bounded body upload and request processing. See `tests/test_contracts.py`, `test_config.py`, `test_api.py`, `test_credentials.py`, `test_fake_upstream.py`, `test_limits.py` and `test_session_access.py`. |
| 2: vault/session lifecycle | Versioned SQLite schema, full-digest uniqueness, Argon2id unlock verifier, domain-separated AES-GCM and wrapped session keys, ephemeral cleanup, persistent recovery/TTL/deletion and exclusive request leases. Tests exercise tampering, swapped metadata, journal/WAL plaintext absence and concurrent lifetime behavior. See `test_vault*.py`, `test_session_keys.py`, `test_persistent_sessions.py` and `test_session_concurrency.py`. |
| 3: detection/tokens | Pinned real spaCy model and audited recognizer registry, custom recognizers, threshold/allowlist/overlap policy, exact opaque identities, atomic collision extension, original-coordinate substitution and local analysis. See `test_stage1.py`, `test_custom_recognizers.py`, `test_span_resolution.py`, `test_pseudonym.py`, `test_token_allocation.py`, `test_substitution.py` and `test_analyze_api.py`. The [synthetic generator](../eval/datasets/README.md) supplies reproducible labeled data. |
| 4: protected proxy | Every supported role, registration before the exact-byte final guard, zero sends on protection failure, verified upstream transport, exact/tolerant active-session restoration, all choices, JSON/buffered SSE, counts-only reports/metrics and health. See `test_gateway.py`, `test_outgoing_guard.py`, `test_guard_blocking.py`, `test_upstream_client.py`, `test_rehydrate.py`, `test_chat_roundtrip.py`, `test_metrics.py` and `test_health.py`. The [offline demo](../demo/README.md) and [threshold pilot](../eval/README.md) complete the missing artifacts. |
| 5: contextual review | Pinned local Ollama/LangChain adapter, masked-only handoff, strict source map, structured quote/offset validation, additive-only merging, injection isolation, bounded output/deadlines, explicit fallback and independent fast mode. See `test_stage2_reviewer.py`, `test_review_source_map.py`, `test_review_validation.py`, `test_review_injection.py`, `test_review_transport.py`, `test_review_policy.py` and `test_modes.py`. [Local latency measurements](local-reviewer.md) record machine/model details. |

## Corrections made during review

The original audit found two runtime defects despite a passing test suite:

- A name-shaped secret could lose its opaque type during overlap resolution.
  For example, differently cased assigned passwords could become the same PERSON
  token and restore to the first password's spelling. Accepted `SECRET`, `API_KEY`
  and `EMPLOYEE_ID` candidates now take precedence within their overlap component.
  Highest confidence and the deterministic tie-break apply within that class;
  components without opaque candidates keep the original rule. Filtering still
  precedes merging. This validation-driven exception updates the plan's overlap
  decision and shares the exact-type set with normalization. Regressions cover
  lower-confidence opaque members, transitive overlap and the real model.
  Token derivation and vault formats do not change; older registered tokens remain
  readable, while newly resolved credentials receive their correct opaque type.
- Stage 2's timeout could fire during review and then wait indefinitely for
  reviewer cleanup. API mode processing now separates the deadline outcome from
  cleanup drain. Requests return the configured failure/fallback promptly while
  persistent leases remain held until cleanup finishes. Regression tests cover
  fail-closed/fail-open behavior, blocked cleanup, cancellation and lease release.

The labeled dataset generator, runnable offline JSON/SSE demo and small Stage 1
threshold/utility pilot were missing. They have been added with reproducible
commands and documented scoring. The pilot was performed as catch-up work after
Stage 2 implementation; the original milestone's chronology cannot be recovered.
Historical scaffold/future-task statements in the setup and technical guides
have been replaced with current behavior.

## Verification boundaries

The automated suite exercises real Stage 1 detection, real encryption/storage,
controlled fake upstreams and controlled reviewers. Generic API tests substitute
an empty local reviewer so the suite works without Ollama. This proves policy,
validation and lifetime behavior; it does not measure contextual recall or model
resistance to every injection. The local smoke check below supplements those
controlled tests. The threshold pilot uses a deterministic offline utility proxy,
not a live provider or human/judge assessment.

Detector misses and approved allowlist disclosures remain possible. Persistent
session deletion cannot invalidate old database backups, and Python cleanup does
not guarantee memory erasure. Restoration keeps the first observed spelling for
normalized entities. Windows-specific file locking has not been exercised on this
macOS host. See the linked technical guides for supported limits and deferred
scope.

## Local reviewer API smoke check

[Recorded aggregate results](benchmarks/stage2-api-smoke-2026-11-22.json) use the
cached `llama3.1:8b` model and the final structured-validation/API path. The first
call returned safe 503 `reviewer_unavailable` in 10.48 s with a 60 s review budget;
the failure subtype was not retained, so its cause is unknown. The warm call
returned 200 in 5.44 s within the default 10 s review budget. It retained two
Stage 1 detections and accepted no contextual additions. These two observations
verify a live adapter interaction and safe failure, without establishing
contextual recall, schema reliability or a cold-start latency distribution.
Concurrent development work makes these timings indicative.

After installing both extras and starting the local model as described in
[reviewer setup](local-reviewer.md), reproduce the API check from the repository
root. This uses fixed synthetic text and an in-process analysis client. The only
network connection is to local Ollama; nothing is sent to an upstream provider.
Model output and timings can differ between runs.

```sh
.venv/bin/python - <<'PY'
import asyncio
import time
from collections import Counter
import httpx
from shield.app import create_app
from shield.config import DetectionConfig, ShieldConfig

async def main():
    for budget in (60.0, 10.0):
        app = create_app(ShieldConfig(detection=DetectionConfig(
            mode="balanced", stage2_timeout_s=budget)))
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://shield.test",
            ) as client:
                start = time.perf_counter()
                response = await client.post("/shield/analyze", json={"text":
                    "Email synthetic.person@example.test. Note: the sole "
                    "lighthouse keeper on our fictional lunar outpost."})
                body = response.json()
                print({"status": response.status_code,
                       "elapsed_s": round(time.perf_counter() - start, 3),
                       "stage_counts": dict(Counter(
                           item["stage"] for item in body.get("spans", []))),
                       "error": body.get("error", {}).get("code")})
asyncio.run(main())
PY
```
