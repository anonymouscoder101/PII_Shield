"""Bounded contextual batches fail closed unless fallback is explicitly enabled."""

import asyncio
import json

import httpx
import pytest
from pydantic import SecretStr
from test_review_validation import Detector

from shield.config import DetectionConfig
from shield.contracts import ErrorCode
from shield.errors import ShieldError
from shield.session import ephemeral_session


class Reviewer:
    def __init__(self, mode):
        self.mode = mode
        self.calls = 0

    async def review(self, text):
        self.calls += 1
        if self.mode == "timeout":
            await asyncio.Event().wait()
        if self.mode == "size":
            return SecretStr("x" * 1000)
        if self.mode == "schema":
            return SecretStr('{"private-reason":"untrusted"}')
        if self.mode == "unavailable":
            raise RuntimeError("private-reviewer-error")
        return SecretStr('{"spans":[]}')


@pytest.mark.parametrize("mode", ["timeout", "size", "schema", "unavailable"])
@pytest.mark.parametrize("policy", ["fail_closed", "fail_open"])
async def test_review_failures_obey_explicit_policy(mode, policy):
    from shield.detect.review_policy import review_with_policy

    config = DetectionConfig(
        stage2_timeout_s=0.02, stage2_max_output_bytes=100, on_stage2_failure=policy
    )
    with ephemeral_session() as state:
        if policy == "fail_closed":
            with pytest.raises(ShieldError) as error:
                await review_with_policy(
                    ("Alice works here",), state, Detector(), Reviewer(mode), config
                )
            assert error.value.code == ErrorCode.REVIEWER_UNAVAILABLE
        else:
            batch = await review_with_policy(
                ("Alice works here",), state, Detector(), Reviewer(mode), config
            )
            assert batch.outcome.status == "stage1_fallback"
            assert len(batch.plans) == 1 and batch.plans[0].additions == ()
            assert batch.plans[0].resolved.spans == (
                batch.stage1[0].replacements[0].span,
            )


async def test_any_failure_discards_all_partial_contextual_additions():
    from shield.detect.review_policy import review_with_policy

    class Partial:
        async def review(self, text):
            masked = text.get_secret_value()
            if "first" in masked:
                start = masked.index("first")
                return SecretStr(
                    json.dumps(
                        {
                            "spans": [
                                {
                                    "entity_type": "CONTEXTUAL",
                                    "text": "first",
                                    "start": start,
                                    "end": start + 5,
                                    "confidence": 1,
                                }
                            ]
                        }
                    )
                )
            raise RuntimeError("private")

    with ephemeral_session() as state:
        result = await review_with_policy(
            ("Alice first", "Alice second"),
            state,
            Detector(),
            Partial(),
            DetectionConfig(on_stage2_failure="fail_open"),
        )
        assert result.outcome.status == "stage1_fallback"
        assert all(not plan.additions for plan in result.plans)
        assert all(plan.resolved.report.protected_count == 1 for plan in result.plans)


async def test_cancellation_never_becomes_fail_open():
    from shield.detect.review_policy import review_with_policy

    entered = asyncio.Event()

    class Cancel:
        async def review(self, text):
            entered.set()
            await asyncio.Event().wait()

    with ephemeral_session() as state:
        task = asyncio.create_task(
            review_with_policy(
                ("Alice",),
                state,
                Detector(),
                Cancel(),
                DetectionConfig(on_stage2_failure="fail_open"),
            )
        )
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


@pytest.mark.parametrize("stream", [False, True])
@pytest.mark.parametrize(
    "review_mode,on_failure,status,outcome",
    [
        ("ok", "fail_closed", 200, "complete"),
        ("unavailable", "fail_open", 200, "stage1_fallback"),
        ("unavailable", "fail_closed", 503, "failed"),
    ],
)
async def test_success_and_fail_open_headers_and_metrics(
    caplog, stream, review_mode, on_failure, status, outcome
):
    import logging

    from shield.api import ChatCompletionRequest
    from shield.app import create_app
    from shield.delivery import completion_response
    from shield.detect.review_policy import review_with_policy
    from shield.fake_upstream import synthetic_response

    caplog.set_level(logging.INFO, logger="shield.metrics")
    app = create_app()
    continued = []

    @app.get("/policy-demo")
    async def demo():
        with ephemeral_session() as state:
            batch = await review_with_policy(
                ("Alice",),
                state,
                Detector(),
                Reviewer(review_mode),
                DetectionConfig(on_stage2_failure=on_failure),
            )
        continued.append(True)
        response = synthetic_response(
            ChatCompletionRequest.model_validate(
                {
                    "model": "synthetic",
                    "messages": [{"role": "user", "content": "synthetic"}],
                }
            )
        )
        return completion_response(
            response,
            stream=stream,
            include_usage=False,
            report=batch.plans[0].resolved.report,
            stage2=batch.outcome,
        )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as api:
        response = await api.get("/policy-demo")
    assert response.status_code == status
    if status == 200:
        assert response.headers["x-shield-stage2"] == outcome
        assert len(continued) == 1
        if outcome == "stage1_fallback":
            assert response.headers["x-shield-stage2-failure"] == "unavailable"
        else:
            assert "x-shield-stage2-failure" not in response.headers
    else:
        assert not continued
        assert response.headers["content-type"] == "application/json"
        assert response.json()["error"]["code"] == "reviewer_unavailable"
        assert "x-shield-stage2" not in response.headers
        assert "x-shield-report" not in response.headers
    (event,) = [
        json.loads(r.getMessage()) for r in caplog.records if r.name == "shield.metrics"
    ]
    assert event["stage2"] == {
        "status": outcome,
        "failure": None if outcome == "complete" else "unavailable",
    }
    assert "private-reviewer-error" not in caplog.text + response.text


async def test_aggregate_output_budget_counts_utf8_and_prevents_remaining_calls():
    from shield.detect.review_policy import review_with_policy

    class Sized:
        calls = 0

        async def review(self, text):
            self.calls += 1
            return SecretStr('{"spans":[]}')

    reviewer = Sized()
    with ephemeral_session() as state:
        result = await review_with_policy(
            ("Alice", "second", "third"),
            state,
            Detector(),
            reviewer,
            DetectionConfig(stage2_max_output_bytes=12, on_stage2_failure="fail_open"),
        )
        assert result.outcome.failure == "output_limit" and reviewer.calls == 1
    from shield.detect.review_limits import ReviewerOutputLimit, check_output

    with pytest.raises(ReviewerOutputLimit):
        check_output(SecretStr("é" * 5), 6)


async def test_validation_cannot_return_success_after_sync_deadline(monkeypatch):
    import time

    from shield.detect import review_policy

    original = review_policy.validate_review

    def delayed(*args, **kwargs):
        time.sleep(0.03)
        return original(*args, **kwargs)

    monkeypatch.setattr(review_policy, "validate_review", delayed)
    with ephemeral_session() as state:
        result = await review_policy.review_with_policy(
            ("Alice",),
            state,
            Detector(),
            Reviewer("ok"),
            DetectionConfig(stage2_timeout_s=0.01, on_stage2_failure="fail_open"),
        )
        assert (
            result.outcome.status == "stage1_fallback"
            and result.outcome.failure == "timeout"
        )


async def test_stage1_failures_never_fail_open():
    from shield.detect.review_policy import review_with_policy
    from shield.substitute import TokenSubstitutionError

    class Failed(Detector):
        def detect(self, text):
            raise RuntimeError("private detector failure")

    reviewer = Reviewer("ok")
    with ephemeral_session() as state:
        with pytest.raises(TokenSubstitutionError):
            await review_with_policy(
                ("Alice",),
                state,
                Failed(),
                reviewer,
                DetectionConfig(on_stage2_failure="fail_open"),
            )
        assert reviewer.calls == 0


async def test_lost_session_state_never_returns_fail_open_or_success():
    from shield.detect.review_policy import review_with_policy

    with ephemeral_session() as state:

        class Closed:
            async def review(self, text):
                state.close()
                return SecretStr('{"spans":[]}')

        with pytest.raises(ShieldError):
            await review_with_policy(
                ("Alice",),
                state,
                Detector(),
                Closed(),
                DetectionConfig(on_stage2_failure="fail_open"),
            )
