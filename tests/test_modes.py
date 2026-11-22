"""Mode orchestration with in-process reviewer/provider doubles only."""

import json
import re

import httpx
import pytest
from pydantic import SecretStr

from shield.app import create_app
from shield.config import DetectionConfig, ShieldConfig
from shield.contracts import DetectedSpan, EntityType
from shield.detect.resolve import SpanPolicy
from shield.fake_upstream import create_fake_upstream


class Detector:
    def __init__(self, config):
        self.policy = SpanPolicy(config)

    def detect(self, text):
        return [
            DetectedSpan(
                start=m.start(),
                end=m.end(),
                entity_type=EntityType.PERSON,
                confidence=0.95,
            )
            for m in re.finditer("Alice", text)
        ]


class Reviewer:
    def __init__(self, fail=False):
        self.seen, self.closed, self.fail = [], False, fail

    async def review(self, text):
        masked = text.get_secret_value()
        self.seen.append(masked)
        assert "Alice" not in masked
        if self.fail:
            raise RuntimeError("private reviewer failure")
        phrase = "the only cardiologist"
        spans = []
        if phrase in masked:
            start = masked.index(phrase)
            spans.append(
                {
                    "entity_type": "CONTEXTUAL",
                    "text": phrase,
                    "start": start,
                    "end": start + len(phrase),
                    "confidence": 0.9,
                }
            )
        return SecretStr(json.dumps({"spans": spans}))

    async def aclose(self):
        self.closed = True


@pytest.mark.parametrize("mode", ["balanced", "paranoid"])
@pytest.mark.parametrize("endpoint", ["chat", "analyze"])
async def test_stage2_applied_before_guard_and_delivery(mode, endpoint):
    reviewer = Reviewer()
    upstream = create_fake_upstream()
    app = create_app(
        ShieldConfig(detection=DetectionConfig(mode=mode)),
        detector_factory=Detector,
        reviewer_factory=lambda config: reviewer,
        upstream_transport=httpx.ASGITransport(app=upstream),
    )
    text = "Alice is the only cardiologist."
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as api:
        if endpoint == "chat":
            response = await api.post(
                "/v1/chat/completions",
                json={
                    "model": "synthetic",
                    "messages": [
                        {"role": role, "content": text}
                        for role in ("system", "developer", "user", "assistant")
                    ],
                },
            )
            assert response.status_code == 200
            sent = upstream.state.captures[0].body.decode()
            assert "Alice" not in sent and "the only cardiologist" not in sent
            assert "[PERSON_" in sent and "[CONTEXTUAL_" in sent
            assert len(reviewer.seen) == 4
            report = json.loads(response.headers["x-shield-report"])
            assert report["protected_counts"] == {"PERSON": 4, "CONTEXTUAL": 4}
        else:
            response = await api.post("/shield/analyze", json={"text": text})
            assert response.status_code == 200
            data = response.json()
            assert (
                "Alice" not in data["sanitized_text"]
                and "cardiologist" not in data["sanitized_text"]
            )
            assert [s["stage"] for s in data["spans"]] == ["stage1", "stage2"]
            assert (
                text[data["spans"][1]["start"] : data["spans"][1]["end"]]
                == "the only cardiologist"
            )
            assert not upstream.state.captures
        assert response.headers["x-shield-stage2"] == "complete"
        assert reviewer.closed


@pytest.mark.parametrize("endpoint", ["chat", "analyze"])
async def test_fast_never_constructs_or_probes_reviewer(endpoint):
    def forbidden(config):
        pytest.fail("Fast mode touched Ollama")

    app = create_app(
        ShieldConfig(detection=DetectionConfig(mode="fast")),
        detector_factory=Detector,
        reviewer_factory=forbidden,
        upstream_transport=httpx.ASGITransport(app=create_fake_upstream()),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as api:
        response = (
            await api.post("/shield/analyze", json={"text": "Alice"})
            if endpoint == "analyze"
            else await api.post(
                "/v1/chat/completions",
                json={
                    "model": "synthetic",
                    "messages": [{"role": "user", "content": "Alice"}],
                },
            )
        )
    assert response.status_code == 200 and "x-shield-stage2" not in response.headers


@pytest.mark.parametrize("policy", ["fail_closed", "fail_open"])
@pytest.mark.parametrize("stream", [False, True])
async def test_outage_policy_is_live_in_chat(policy, stream):
    upstream = create_fake_upstream()
    app = create_app(
        ShieldConfig(detection=DetectionConfig(on_stage2_failure=policy)),
        detector_factory=Detector,
        reviewer_factory=lambda config: Reviewer(fail=True),
        upstream_transport=httpx.ASGITransport(app=upstream),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as api:
        response = await api.post(
            "/v1/chat/completions",
            json={
                "model": "synthetic",
                "stream": stream,
                "messages": [{"role": "user", "content": "Alice"}],
            },
        )
    if policy == "fail_closed":
        assert response.status_code == 503 and not upstream.state.captures
        assert response.json()["error"]["code"] == "reviewer_unavailable"
        assert response.headers["content-type"] == "application/json"
    else:
        assert response.status_code == 200 and len(upstream.state.captures) == 1
        assert response.headers["x-shield-stage2"] == "stage1_fallback"
        assert "Alice" not in upstream.state.captures[0].body.decode()


async def test_final_guard_runs_after_contextual_masking_and_blocks_defects(
    monkeypatch,
):
    from shield import chat

    reviewer = Reviewer()
    upstream = create_fake_upstream()
    original = chat.finish_chat

    def defective(request, session, detector, results):
        assert "[CONTEXTUAL_" in results[0].sanitized_text
        broken = results[0].model_copy(
            update={"sanitized_text": request.messages[0].content}
        )
        return original(request, session, detector, (broken,))

    monkeypatch.setattr(chat, "finish_chat", defective)
    app = create_app(
        detector_factory=Detector,
        reviewer_factory=lambda config: reviewer,
        upstream_transport=httpx.ASGITransport(app=upstream),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as api:
        response = await api.post(
            "/v1/chat/completions",
            json={
                "model": "synthetic",
                "stream": True,
                "messages": [
                    {"role": "user", "content": "Alice is the only cardiologist"}
                ],
            },
        )
    assert response.status_code == 422 and not upstream.state.captures
    assert response.json()["error"]["code"] == "protection_blocked"
    assert reviewer.seen and reviewer.closed


async def test_fail_open_does_not_skip_outgoing_guard():
    upstream = create_fake_upstream()
    app = create_app(
        ShieldConfig(detection=DetectionConfig(on_stage2_failure="fail_open")),
        detector_factory=Detector,
        reviewer_factory=lambda config: Reviewer(fail=True),
        upstream_transport=httpx.ASGITransport(app=upstream),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as api:
        response = await api.post(
            "/v1/chat/completions",
            json={"model": "Alice", "messages": [{"role": "user", "content": "Alice"}]},
        )
    assert response.status_code == 422 and not upstream.state.captures


async def test_stage1_failure_prevents_reviewer_factory_and_upstream():
    upstream = create_fake_upstream()

    class Failed(Detector):
        def detect(self, text):
            raise RuntimeError("private detector error")

    def forbidden(config):
        pytest.fail("Reviewer constructed after failed Stage 1")

    app = create_app(
        detector_factory=Failed,
        reviewer_factory=forbidden,
        upstream_transport=httpx.ASGITransport(app=upstream),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as api:
        response = await api.post(
            "/v1/chat/completions",
            json={
                "model": "synthetic",
                "messages": [{"role": "user", "content": "Alice"}],
            },
        )
    assert response.status_code == 503 and not upstream.state.captures
    assert response.json()["error"]["code"] == "detection_failed"


async def test_cached_health_availability_never_constructs_reviewer():
    calls = []

    def factory(config):
        calls.append(config)
        return Reviewer()

    app = create_app(detector_factory=Detector, reviewer_factory=factory)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as api:
        assert not (await api.get("/shield/health")).json()["stage2_available"]
        assert not calls
        assert (
            await api.post("/shield/analyze", json={"text": "Alice"})
        ).status_code == 200
        assert (await api.get("/shield/health")).json()["stage2_available"]
        assert len(calls) == 1


async def test_persistent_contextual_mapping_committed_before_send_and_restored(
    tmp_path,
):
    import sqlite3

    from shield.config import Argon2Config, SessionsConfig, VaultConfig
    from shield.credentials import RuntimeCredentials
    from shield.fake_upstream import synthetic_response

    config = ShieldConfig(
        sessions=SessionsConfig(persistent_enabled=True),
        vault=VaultConfig(
            path=tmp_path / "vault.db",
            argon2=Argon2Config(memory_kib=32, time_cost=1, parallelism=1),
        ),
    )

    def echo(request):
        with sqlite3.connect(config.vault.path) as db:
            assert dict(
                db.execute(
                    "SELECT entity_type,COUNT(*) FROM entries GROUP BY entity_type"
                )
            ) == {"PERSON": 1, "CONTEXTUAL": 1}
        result = synthetic_response(request)
        choice = result.choices[0]
        return result.model_copy(
            update={
                "choices": [
                    choice.model_copy(
                        update={
                            "message": choice.message.model_copy(
                                update={"content": request.messages[0].content}
                            )
                        }
                    )
                ]
            }
        )

    app = create_app(
        config,
        RuntimeCredentials(vault_passphrase=SecretStr("synthetic")),
        detector_factory=Detector,
        reviewer_factory=lambda config: Reviewer(),
        upstream_transport=httpx.ASGITransport(app=create_fake_upstream(echo)),
    )
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as api:
            sid = (await api.post("/shield/sessions", json={})).json()["session_id"]
            for _ in range(2):
                response = await api.post(
                    "/v1/chat/completions",
                    headers={"X-Shield-Session": sid},
                    json={
                        "model": "synthetic",
                        "messages": [
                            {
                                "role": "assistant",
                                "content": "Alice is the only cardiologist",
                            }
                        ],
                    },
                )
                assert response.status_code == 200
                assert (
                    response.json()["choices"][0]["message"]["content"]
                    == "Alice is the only cardiologist"
                )
                assert response.headers["x-shield-session"] == sid


@pytest.mark.parametrize("endpoint", ["chat", "analyze"])
async def test_cancelled_review_keeps_lease_until_reviewer_cleanup(
    tmp_path, monkeypatch, endpoint
):
    import asyncio
    from contextlib import contextmanager
    from threading import Event

    from shield.config import Argon2Config, SessionsConfig, VaultConfig
    from shield.credentials import RuntimeCredentials

    entered, cleaning, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
    drained = Event()

    class Blocked(Reviewer):
        async def review(self, text):
            entered.set()
            await asyncio.Event().wait()

        async def aclose(self):
            cleaning.set()
            await release.wait()

    config = ShieldConfig(
        sessions=SessionsConfig(persistent_enabled=True),
        vault=VaultConfig(
            path=tmp_path / "vault.db",
            argon2=Argon2Config(memory_kib=32, time_cost=1, parallelism=1),
        ),
    )
    upstream = create_fake_upstream()
    app = create_app(
        config,
        RuntimeCredentials(vault_passphrase=SecretStr("synthetic")),
        detector_factory=Detector,
        reviewer_factory=lambda config: Blocked(),
        upstream_transport=httpx.ASGITransport(app=upstream),
    )
    async with app.router.lifespan_context(app):
        original = app.state.vault.use

        @contextmanager
        def captured(sid):
            try:
                with original(sid) as state:
                    yield state
            finally:
                drained.set()

        monkeypatch.setattr(app.state.vault, "use", captured)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as api:
            sid = (await api.post("/shield/sessions", json={})).json()["session_id"]
            payload = (
                {"text": "Alice"}
                if endpoint == "analyze"
                else {
                    "model": "synthetic",
                    "messages": [{"role": "user", "content": "Alice"}],
                }
            )
            path = (
                "/shield/analyze" if endpoint == "analyze" else "/v1/chat/completions"
            )
            task = asyncio.create_task(
                api.post(path, headers={"X-Shield-Session": sid}, json=payload)
            )
            try:
                await asyncio.wait_for(entered.wait(), 1)
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
                await asyncio.wait_for(cleaning.wait(), 1)
                assert not await asyncio.to_thread(drained.wait, 0.05)
                assert (await api.delete(f"/shield/sessions/{sid}")).status_code == 409
                assert not upstream.state.captures
            finally:
                release.set()
                await asyncio.to_thread(drained.wait, 1)
            assert (await api.delete(f"/shield/sessions/{sid}")).status_code == 204


async def test_close_cannot_publish_late_review_success():
    import time

    from shield.detect.review_policy import review_with_policy
    from shield.errors import ShieldError
    from shield.session import ephemeral_session

    class SlowClose(Reviewer):
        async def aclose(self):
            time.sleep(0.03)

    with ephemeral_session() as state:
        with pytest.raises(ShieldError) as error:
            await review_with_policy(
                ("Alice",),
                state,
                Detector(DetectionConfig()),
                SlowClose(),
                DetectionConfig(stage2_timeout_s=0.005),
                close_reviewer=True,
            )
        assert error.value.code.value == "reviewer_unavailable"


async def test_cleanup_fault_never_overrides_caller_cancellation():
    import asyncio

    from shield.detect.review_policy import review_with_policy
    from shield.session import ephemeral_session

    entered = asyncio.Event()

    class BrokenClose(Reviewer):
        async def review(self, text):
            entered.set()
            await asyncio.Event().wait()

        async def aclose(self):
            raise RuntimeError("private cleanup error")

    with ephemeral_session() as state:
        task = asyncio.create_task(
            review_with_policy(
                ("Alice",),
                state,
                Detector(DetectionConfig()),
                BrokenClose(),
                DetectionConfig(on_stage2_failure="fail_open"),
                close_reviewer=True,
            )
        )
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
