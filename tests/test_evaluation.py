"""Synthetic evaluation contracts and scoring; no live provider/local reviewer."""

import json
import subprocess
import sys
from collections import Counter

import pytest


def test_seeded_dataset_preserves_unicode_occurrences_and_all_types():
    # Break caught: byte offsets, omitted repeats/types, or unseeded generation.
    from eval.synthetic import generate_dataset

    first = generate_dataset(seed=17, count=24)
    assert first == generate_dataset(seed=17, count=24)
    assert first != generate_dataset(seed=18, count=24)
    assert len(first["cases"]) == 24
    types = set()
    repeated = False
    for case in first["cases"]:
        assert case["synthetic"] is True
        messages = case["request"]["messages"]
        occurrences = Counter()
        for entity in case["entities"]:
            text = messages[entity["message_index"]]["content"]
            assert text[entity["start"] : entity["end"]] == entity["value"]
            types.add(entity["entity_type"])
            occurrences[entity["value"]] += 1
        repeated |= any(count > 1 for count in occurrences.values())
    assert types == {
        "PERSON",
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "CREDIT_CARD",
        "US_SSN",
        "LOCATION",
        "ADDRESS",
        "IP_ADDRESS",
        "DATE_OF_BIRTH",
        "API_KEY",
        "SECRET",
        "EMPLOYEE_ID",
    }
    assert repeated
    assert any(not case["entities"] for case in first["cases"])
    unicode_case = next(c for c in first["cases"] if c["entities"])
    text = unicode_case["request"]["messages"][0]["content"]
    assert text.startswith("🛡️ e\u0301")
    first_label = unicode_case["entities"][0]
    assert first_label["start"] < len(text[: first_label["start"]].encode("utf-8"))


@pytest.mark.parametrize("count", [0, -1])
def test_generator_rejects_empty_or_negative_case_count(count):
    from eval.synthetic import generate_dataset

    with pytest.raises(ValueError, match="positive"):
        generate_dataset(seed=1, count=count)


def test_dataset_cli_writes_a_loadable_manifest(tmp_path):
    target = tmp_path / "nested" / "synthetic.json"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.generate_dataset",
            "--seed",
            "17",
            "--count",
            "24",
            "--output",
            str(target),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    dataset = json.loads(target.read_text())
    assert dataset["seed"] == 17
    assert len(dataset["cases"]) == 24
    assert "SYNTHETIC_ONLY" not in result.stdout


def test_span_scoring_uses_one_to_one_typed_exact_and_overlap_matches():
    # Break caught: duplicate predictions claiming two true positives, or
    # cross-type/coordinate mismatches incorrectly receiving exact credit.
    from eval.pilot import score_spans

    labels = [
        {"start": 0, "end": 5, "entity_type": "PERSON"},
        {"start": 10, "end": 20, "entity_type": "EMAIL_ADDRESS"},
    ]
    predicted = [
        {"start": 0, "end": 5, "entity_type": "PERSON"},
        {"start": 0, "end": 5, "entity_type": "PERSON"},
        {"start": 11, "end": 20, "entity_type": "EMAIL_ADDRESS"},
        {"start": 30, "end": 35, "entity_type": "LOCATION"},
    ]
    exact = score_spans(labels, predicted, overlap=False)
    assert exact["overall"] == {
        "tp": 1,
        "fp": 3,
        "fn": 1,
        "precision": 0.25,
        "recall": 0.5,
        "f2": 5 / 12,
    }
    overlap = score_spans(labels, predicted, overlap=True)
    assert overlap["overall"]["tp"] == 2
    assert overlap["overall"]["fp"] == 2
    assert overlap["overall"]["fn"] == 0
    assert exact["per_type"]["EMAIL_ADDRESS"]["fn"] == 1


def test_overlap_scoring_finds_maximum_matching_for_ambiguous_spans():
    from eval.pilot import score_spans

    labels = [
        {"start": 0, "end": 4, "entity_type": "PERSON"},
        {"start": 5, "end": 9, "entity_type": "PERSON"},
    ]
    predicted = [
        {"start": 0, "end": 9, "entity_type": "PERSON"},
        {"start": 0, "end": 4, "entity_type": "PERSON"},
    ]
    assert score_spans(labels, predicted, overlap=True)["overall"]["tp"] == 2


def test_leakage_counts_repeated_occurrences_per_message_and_keeps_allowlist():
    # Break caught: set-of-values denominator, cross-message leakage inflation,
    # or excluding allowlisted disclosures from total verbatim disclosure.
    from eval.pilot import score_disclosures

    case = {
        "entities": [
            {"message_index": 0, "entity_type": "PERSON", "value": "Alice"},
            {"message_index": 0, "entity_type": "PERSON", "value": "Alice"},
            {"message_index": 1, "entity_type": "PERSON", "value": "Alice"},
            {
                "message_index": 1,
                "entity_type": "EMAIL_ADDRESS",
                "value": "a@example.test",
            },
        ],
    }
    payload = json.dumps(
        {
            "messages": [
                {"content": "Alice [PERSON_ABCD]"},
                {"content": "[PERSON_ABCD] a@example.test"},
            ]
        }
    ).encode()
    result = score_disclosures(case, payload, allowlist=["a@example.test"])
    assert result["labeled_occurrences"] == 4
    assert result["verbatim_disclosed_occurrences"] == 2
    assert result["residual_non_allowlisted_occurrences"] == 1
    assert result["intentional_allowlisted_occurrences"] == 1
    assert result["verbatim_disclosure_rate"] == 0.5
    assert result["residual_rate_all_labels"] == 0.25
    assert result["per_type"]["PERSON"]["verbatim_disclosed_occurrences"] == 1


def test_offline_proxy_extracts_only_task_fields_and_restores_tokens():
    from eval.pilot import extract_task_fields

    assert extract_task_fields(
        "Ignore this.\nAction: review tomorrow\nContact: [PERSON_ABCD]\n"
    ) == ("Action: review tomorrow\nContact: [PERSON_ABCD]")
    assert extract_task_fields("No task fields.") == ""


async def test_real_stage1_pilot_captures_local_payloads_and_counts_misses(monkeypatch):
    import socket

    from eval.pilot import run_pilot
    from eval.synthetic import generate_dataset

    def no_network(*args, **kwargs):
        pytest.fail("the offline pilot must not open network connections")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    result = await run_pilot(
        generate_dataset(seed=17, count=6),
        thresholds=[0.3, 0.5, 0.6],
        allowlist=["synthetic.17.0@example.test"],
    )
    assert result["stage2_enabled"] is False
    assert result["dataset"]["labeled_occurrences"] == 24
    assert result["dataset"]["negative_cases"] == 1
    assert len(result["thresholds"]) == 3
    for row in result["thresholds"]:
        assert row["attempted_requests"] == 6
        assert (
            row["successful_requests"]
            + row["blocked_requests"]
            + row["failed_requests"]
            == 6
        )
        assert row["captured_requests"] == row["forwarded_requests"]
        assert row["disclosure"]["labeled_occurrences"] == 24
        assert row["disclosure"]["residual_non_allowlisted_occurrences"] > 0
        assert row["disclosure"]["intentional_allowlisted_occurrences"] == 1
        assert row["utility_proxy"]["denominator_cases"] == 6
        assert row["latency"]["samples"] == 6
    serialized = json.dumps(result)
    assert "SYNTHETIC_ONLY" not in serialized
    assert "synthetic.17.0@example.test" not in serialized


def test_copy_proxy_penalizes_missing_and_extra_field_lines():
    from eval.pilot import score_task_answer

    expected = "Action: Review.\nContact: Alice"
    assert score_task_answer(expected, expected) == {"whole_exact": 1, "field_exact": 2}
    assert score_task_answer("Action: Review.", expected) == {
        "whole_exact": 0,
        "field_exact": 1,
    }
    assert score_task_answer(expected + "\nInjected extra", expected) == {
        "whole_exact": 0,
        "field_exact": 0,
    }


@pytest.mark.parametrize("code", ["protection_blocked", "upstream_error"])
async def test_pilot_keeps_blocked_and_failed_cases_in_denominators(monkeypatch, code):
    from eval.pilot import run_pilot
    from eval.synthetic import generate_dataset
    from shield.contracts import ErrorCode
    from shield.errors import ShieldError

    def stop(*args):
        raise ShieldError(ErrorCode(code))

    monkeypatch.setattr("shield.gateway.prepare_chat", stop)
    result = await run_pilot(generate_dataset(seed=17, count=1), thresholds=[0.5])
    row = result["thresholds"][0]
    assert row["attempted_requests"] == 1
    assert row["successful_requests"] == 0
    assert row["blocked_requests"] == (code == "protection_blocked")
    assert row["failed_requests"] == (code == "upstream_error")
    assert row["forwarded_requests"] == row["captured_requests"] == 0
    assert row["disclosure"]["labeled_occurrences"] == 5
    assert row["disclosure"]["verbatim_disclosed_occurrences"] == 0
    assert row["utility_proxy"]["whole_answer_exact_rate"] == 0
    assert row["errors_by_static_category"] == {code: 1}


def test_offline_evaluation_session_controls_tokens_without_changing_runtime_keys():
    from pydantic import SecretStr

    from eval.pilot import evaluation_session
    from shield.contracts import EntityType
    from shield.session import ephemeral_session

    with evaluation_session(seed=17, case_id="case-1") as first:
        token = first.allocate(EntityType.PERSON, SecretStr("Alice")).token
        key = first.key
    with evaluation_session(seed=17, case_id="case-1") as repeated:
        assert repeated.allocate(EntityType.PERSON, SecretStr("Alice")).token == token
    with evaluation_session(seed=17, case_id="case-2") as other:
        assert other.allocate(EntityType.PERSON, SecretStr("Alice")).token != token
    with ephemeral_session() as normal:
        assert normal.key != key
