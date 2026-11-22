"""Scoring for the small Stage 1 pilot; raw cases stay local and unexported."""

import json
from collections import Counter, defaultdict
from contextlib import contextmanager


def _metrics(tp, fp, fn):
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "f2": 5 * tp / (5 * tp + 4 * fn + fp) if 5 * tp + 4 * fn + fp else None,
    }


def score_spans(labels, predicted, *, overlap=False):
    """One-to-one maximum bipartite matching, same message and entity type.

    Exact matching requires identical half-open bounds; overlap matching gives
    full credit to any nonempty intersection, so is an optimistic companion.
    Missing message_index means 0. Undefined ratios are JSON null, never 1.
    """
    types = sorted({item["entity_type"] for item in labels + predicted})
    per_type = {}
    for entity_type in types:
        truth = [item for item in labels if item["entity_type"] == entity_type]
        guesses = [item for item in predicted if item["entity_type"] == entity_type]
        edges = []
        for guess in guesses:
            candidates = []
            for index, label in enumerate(truth):
                same_message = guess.get("message_index", 0) == label.get(
                    "message_index", 0
                )
                bounds_match = (
                    max(guess["start"], label["start"])
                    < min(guess["end"], label["end"])
                    if overlap
                    else (guess["start"], guess["end"])
                    == (label["start"], label["end"])
                )
                if same_message and bounds_match:
                    candidates.append(index)
            edges.append(candidates)
        matched = {}

        def augment(guess_index, seen, edges=edges, matched=matched):
            for label_index in edges[guess_index]:
                if label_index in seen:
                    continue
                seen.add(label_index)
                if label_index not in matched or augment(matched[label_index], seen):
                    matched[label_index] = guess_index
                    return True
            return False

        tp = sum(augment(index, set()) for index in range(len(guesses)))
        per_type[entity_type] = _metrics(tp, len(guesses) - tp, len(truth) - tp)
    totals = [
        sum(item[key] for item in per_type.values()) for key in ("tp", "fp", "fn")
    ]
    return {"overall": _metrics(*totals), "per_type": per_type}


def score_disclosures(case, payload, *, allowlist=()):
    """Count labeled literal occurrences remaining in captured message strings.

    Match per message/type/value, cap at the original occurrence count. Do not
    confuse one surviving repeat with survival of every source occurrence.
    Configured allowlist values stay in the total denominator and total leaks.
    This measures full verbatim values, not partial or inferential disclosure.
    """
    messages = json.loads(payload)["messages"]
    grouped = Counter(
        (item["message_index"], item["entity_type"], item["value"])
        for item in case["entities"]
    )
    per_type = defaultdict(Counter)
    for (message_index, entity_type, value), count in grouped.items():
        disclosed = min(count, messages[message_index]["content"].count(value))
        counts = per_type[entity_type]
        counts["labeled_occurrences"] += count
        counts["verbatim_disclosed_occurrences"] += disclosed
        allowed = disclosed if value in allowlist else 0
        counts["intentional_allowlisted_occurrences"] += allowed
        counts["residual_non_allowlisted_occurrences"] += disclosed - allowed
    total = Counter()
    for counts in per_type.values():
        total.update(counts)
    for key in (
        "labeled_occurrences",
        "verbatim_disclosed_occurrences",
        "intentional_allowlisted_occurrences",
        "residual_non_allowlisted_occurrences",
    ):
        total.setdefault(key, 0)
    denominator = total["labeled_occurrences"]
    return {
        **total,
        "verbatim_disclosure_rate": total["verbatim_disclosed_occurrences"]
        / denominator
        if denominator
        else None,
        "residual_rate_all_labels": total["residual_non_allowlisted_occurrences"]
        / denominator
        if denominator
        else None,
        "per_type": {key: dict(value) for key, value in sorted(per_type.items())},
    }


def extract_task_fields(text):
    """A deterministic copy proxy, not an LLM or semantic utility evaluator."""
    return "\n".join(
        line for line in text.splitlines() if line.startswith(("Action: ", "Contact: "))
    )


def score_task_answer(answer, expected):
    """Score full response and exact Action/Contact lines (ignore final newline).

    Missing lines lose field credit; extra lines invalidate field extraction.
    """
    actual_lines, wanted_lines = answer.splitlines(), expected.splitlines()
    field_exact = (
        sum(line in actual_lines for line in wanted_lines)
        if len(actual_lines) <= len(wanted_lines)
        else 0
    )
    return {"whole_exact": int(answer == expected), "field_exact": field_exact}


@contextmanager
def evaluation_session(*, seed, case_id):
    """Control synthetic-only token identities without mutating runtime globals."""
    import hashlib

    from pydantic import SecretBytes

    from shield.session import EphemeralSession

    session = EphemeralSession()
    # Evaluation-only injection before any allocation. This is intentionally not
    # a production configuration option: predictable keys must never protect PII.
    session._key = SecretBytes(
        hashlib.sha256(
            json.dumps(["PII Shield synthetic evaluation v1", seed, case_id]).encode()
        ).digest()
    )
    try:
        yield session
    finally:
        session.close()


async def run_pilot(manifest, *, thresholds=(0.3, 0.5, 0.6), allowlist=()):
    """Run real Stage 1 + guard + fake HTTP transport + actual restoration.

    No app route/reviewer/vault/server/provider is used. Each case receives a
    fresh ephemeral session. Captures remain in memory, then are cleared. Only
    aggregate metrics, dataset hash, and configuration references are returned.
    """
    import hashlib
    import math
    import platform
    import statistics
    import subprocess
    from datetime import UTC, datetime
    from importlib.metadata import version
    from time import perf_counter

    import httpx

    from shield.api import (
        AssistantMessage,
        ChatCompletionRequest,
        ChatCompletionResponse,
        CompletionChoice,
    )
    from shield.config import DetectionConfig, UpstreamConfig
    from shield.contracts import ErrorCode
    from shield.delivery import restore_completion
    from shield.detect.stage1 import Stage1Detector
    from shield.errors import ShieldError
    from shield.fake_upstream import create_fake_upstream
    from shield.gateway import prepare_chat
    from shield.upstream import UpstreamClient

    if not manifest.get("synthetic_only") or not manifest.get("cases"):
        raise ValueError("pilot requires a nonempty generated synthetic manifest")
    if any(case.get("synthetic") is not True for case in manifest["cases"]):
        raise ValueError("pilot accepts synthetic cases only")
    thresholds = list(thresholds)
    if not thresholds:
        raise ValueError("pilot requires at least one threshold")
    configs = [
        DetectionConfig(mode="fast", threshold=value, allowlist=list(allowlist))
        for value in thresholds
    ]
    load_start = perf_counter()
    base = Stage1Detector.load(configs[0])
    model_load_s = perf_counter() - load_start
    nlp = base._analyzer.nlp_engine.nlp["en"]

    def provider(request):
        return ChatCompletionResponse(
            id="chatcmpl-offline-copy-proxy",
            object="chat.completion",
            created=0,
            model=request.model,
            choices=[
                CompletionChoice(
                    index=0,
                    message=AssistantMessage(
                        role="assistant",
                        content=extract_task_fields(request.messages[0].content),
                    ),
                    finish_reason="stop",
                )
            ],
        )

    def summary(samples):
        return {
            "samples": len(samples),
            "median_s": statistics.median(samples) if samples else None,
            "p95_nearest_rank_s": sorted(samples)[math.ceil(0.95 * len(samples)) - 1]
            if samples
            else None,
        }

    all_labels = []
    for case_index, case in enumerate(manifest["cases"]):
        for label in case["entities"]:
            all_labels.append(
                {**label, "message_index": (case_index, label["message_index"])}
            )
    rows = []
    for config in configs:
        setup_start = perf_counter()
        detector = Stage1Detector(nlp, config=config)
        setup_s = perf_counter() - setup_start
        fake = create_fake_upstream(response_factory=provider)
        durations, preparation, transport, restoration = [], [], [], []
        predictions = []
        disclosure = Counter()
        disclosure_types = defaultdict(Counter)
        outcomes = Counter()
        errors = Counter()
        whole_exact = field_exact = unknown_tokens = allowed_reported = 0
        async with UpstreamClient(
            UpstreamConfig(base_url="http://fake/v1"),
            transport=httpx.ASGITransport(app=fake),
        ) as client:
            for case_index, case in enumerate(manifest["cases"]):
                request = ChatCompletionRequest.model_validate(case["request"])
                for message_index, message in enumerate(request.messages):
                    # Detector scoring is separate from latency: source scans
                    # here are repeated by the timed protection pipeline below.
                    resolved = detector.analyze(message.content)
                    predictions.extend(
                        {
                            "message_index": (case_index, message_index),
                            "start": span.start,
                            "end": span.end,
                            "entity_type": span.entity_type.value,
                        }
                        for span in resolved.spans
                    )
                started = perf_counter()
                capture_before = len(fake.state.captures)
                try:
                    with evaluation_session(
                        seed=manifest["seed"], case_id=case["id"]
                    ) as session:
                        stage_start = perf_counter()
                        prepared = prepare_chat(request, session, detector)
                        preparation.append(perf_counter() - stage_start)
                        allowed_reported += prepared.report.allowlisted_disclosure_count
                        stage_start = perf_counter()
                        response = await client.complete(prepared.payload)
                        transport.append(perf_counter() - stage_start)
                        stage_start = perf_counter()
                        restored = restore_completion(response, session)
                        restoration.append(perf_counter() - stage_start)
                        answer = restored.completion.choices[0].message.content
                        expected = extract_task_fields(request.messages[0].content)
                        utility = score_task_answer(answer, expected)
                        whole_exact += utility["whole_exact"]
                        field_exact += utility["field_exact"]
                        unknown_tokens += restored.unknown_token_count
                        outcomes["successful_requests"] += 1
                except ShieldError as exc:
                    key = (
                        "blocked_requests"
                        if exc.code == ErrorCode.PROTECTION_BLOCKED
                        else "failed_requests"
                    )
                    outcomes[key] += 1
                    errors[exc.code.value] += 1
                except Exception:
                    # Static category only. Keep failed cases in denominators.
                    outcomes["failed_requests"] += 1
                    errors["local_pipeline_error"] += 1
                finally:
                    durations.append(perf_counter() - started)
                captures = fake.state.captures[capture_before:]
                if captures:
                    outcomes["forwarded_requests"] += 1
                    captured_payload = captures[-1].body
                else:
                    captured_payload = json.dumps(
                        {"messages": [{"content": ""} for _ in request.messages]}
                    ).encode()
                scored = score_disclosures(case, captured_payload, allowlist=allowlist)
                for key, value in scored.items():
                    if isinstance(value, int):
                        disclosure[key] += value
                for entity_type, counts in scored["per_type"].items():
                    disclosure_types[entity_type].update(counts)
        denominator = disclosure["labeled_occurrences"]
        case_count = len(manifest["cases"])
        rows.append(
            {
                "threshold": config.effective_threshold,
                "detector_setup_s": setup_s,
                "attempted_requests": case_count,
                **{
                    key: outcomes[key]
                    for key in (
                        "successful_requests",
                        "blocked_requests",
                        "failed_requests",
                        "forwarded_requests",
                    )
                },
                "captured_requests": len(fake.state.captures),
                "errors_by_static_category": dict(errors),
                "detection_exact": score_spans(all_labels, predictions),
                "detection_overlap": score_spans(all_labels, predictions, overlap=True),
                "detector_reported_allowlisted_disclosures": allowed_reported,
                "disclosure": {
                    **disclosure,
                    "verbatim_disclosure_rate": disclosure[
                        "verbatim_disclosed_occurrences"
                    ]
                    / denominator
                    if denominator
                    else None,
                    "residual_rate_all_labels": disclosure[
                        "residual_non_allowlisted_occurrences"
                    ]
                    / denominator
                    if denominator
                    else None,
                    "per_type": {
                        key: dict(value)
                        for key, value in sorted(disclosure_types.items())
                    },
                },
                "utility_proxy": {
                    "name": "deterministic Action/Contact extraction and restoration",
                    "is_llm_or_semantic_utility": False,
                    "denominator_cases": case_count,
                    "whole_answer_exact_cases": whole_exact,
                    "whole_answer_exact_rate": whole_exact / case_count,
                    "denominator_fields": 2 * case_count,
                    "field_exact_matches": field_exact,
                    "field_exact_match_rate": field_exact / (2 * case_count),
                    "unknown_response_tokens": unknown_tokens,
                    "unprotected_copy_baseline_rate_by_construction": 1.0,
                },
                "latency": {
                    **summary(durations),
                    "first_request_s": durations[0],
                    "warm_requests": summary(durations[1:]),
                    "preparation_including_guard": summary(preparation),
                    "fake_http_roundtrip": summary(transport),
                    "restoration": summary(restoration),
                },
            }
        )
        fake.state.captures.clear()
    machine = {
        "os": platform.platform(),
        "architecture": platform.machine(),
        "cpu": platform.processor(),
        "python": platform.python_version(),
    }
    if platform.system() == "Darwin":
        for key, sysctl in (
            ("cpu", "machdep.cpu.brand_string"),
            ("memory_bytes", "hw.memsize"),
        ):
            try:
                machine[key] = subprocess.check_output(
                    ["sysctl", "-n", sysctl], text=True, stderr=subprocess.DEVNULL
                ).strip()
            except OSError, subprocess.CalledProcessError:
                machine[key] = None
        if machine.get("memory_bytes") is not None:
            machine["memory_bytes"] = int(machine["memory_bytes"])
    return {
        "schema_version": 1,
        "measured_at_utc": datetime.now(UTC).isoformat(),
        "scope": (
            "Phase 4 Stage 1 catch-up pilot run after Stage 2 implementation; "
            "not Phase 6 evaluation"
        ),
        "stage2_enabled": False,
        "latency_notes": (
            "Wall time for preparation/guard, fake HTTP, restoration, cleanup; "
            "excludes detector scoring, pipeline load and per-threshold setup. "
            "Thresholds run sequentially; workload and OS caches uncontrolled."
        ),
        "provider": (
            "in-process ASGI fake upstream; deterministic copy proxy; "
            "no network/provider calls"
        ),
        "dataset": {
            "sha256": hashlib.sha256(
                json.dumps(manifest, sort_keys=True, ensure_ascii=False).encode()
            ).hexdigest(),
            "generator_version": manifest["generator_version"],
            "seed": manifest["seed"],
            "faker_version": manifest["faker_version"],
            "cases": len(manifest["cases"]),
            "negative_cases": sum(not case["entities"] for case in manifest["cases"]),
            "labeled_occurrences": len(all_labels),
            "per_type_occurrences": dict(
                sorted(Counter(label["entity_type"] for label in all_labels).items())
            ),
        },
        "configuration": {
            "phone_regions": configs[0].phone_regions,
            "location_policy": configs[0].location_policy,
            "address_policy": configs[0].address_policy,
            "employee_id_enabled": configs[0].employee_id_enabled,
            "mode": "fast",
            "token_keys": (
                "evaluation-only SHA-256 of JSON [domain, dataset seed, case ID]; "
                "same per case across thresholds; never used by runtime configuration"
            ),
            "allowlist_count": len(allowlist),
            "allowlist_entity_references": [
                {"case_id": case["id"], "entity_index": index}
                for case in manifest["cases"]
                for index, entity in enumerate(case["entities"])
                if entity["value"] in allowlist
            ],
        },
        "model": {
            "name": base.model_name,
            "version": base.model_version,
            "pipeline_load_s": model_load_s,
            "load_scope": "process-local initialization; OS caches uncontrolled",
        },
        "packages": {
            name: version(name)
            for name in (
                "presidio-analyzer",
                "spacy",
                "en-core-web-lg",
                "Faker",
                "httpx",
                "pii-shield",
            )
        },
        "machine": machine,
        "thresholds": rows,
    }
