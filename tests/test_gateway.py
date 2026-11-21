"""Conversation preparation covers all roles using synthetic identifiers."""

import re

import httpx
import pytest

from shield.api import ChatCompletionRequest
from shield.app import create_app
from shield.config import DetectionConfig
from shield.contracts import DetectedSpan, EntityType
from shield.detect.resolve import SpanPolicy
from shield.fake_upstream import create_fake_upstream
from shield.session import ephemeral_session


class Detector:
    policy = SpanPolicy(DetectionConfig())

    def detect(self, text):
        return [
            DetectedSpan(
                start=m.start(),
                end=m.end(),
                entity_type=EntityType.PERSON,
                confidence=0.99,
            )
            for m in re.finditer(r"\bAlice\b", text)
        ]


def conversation():
    return ChatCompletionRequest.model_validate(
        {
            "model": "synthetic-model",
            "stream": True,
            "stream_options": {"include_usage": True},
            "temperature": 0.4,
            "n": 2,
            "messages": [
                {"role": role, "content": "Hello Alice"}
                for role in ("system", "developer", "user", "assistant", "user")
            ],
        }
    )


def test_prepare_every_role_and_repeated_restored_assistant_text():
    from shield.gateway import prepare_chat

    original = conversation()
    before = original.model_dump()
    with ephemeral_session() as session:
        prepared = prepare_chat(original, session, Detector())
        texts = [m.content for m in prepared.request.messages]
        assert len(set(texts)) == 1
        assert all("Alice" not in text and "[PERSON_" in text for text in texts)
        assert [m.role for m in prepared.request.messages] == [
            m.role for m in original.messages
        ]
        assert prepared.report.protected_count == 5
        assert len(session.mappings) == 1
        assert prepared.request.stream is False
        assert prepared.request.stream_options is None
        assert prepared.request.n == 2 and prepared.request.temperature == 0.4
        assert original.model_dump() == before
        assert "Hello" not in repr(prepared)


def test_unknown_token_in_later_message_preflights_before_allocating():
    from shield.gateway import prepare_chat
    from shield.substitute import UnknownSessionToken

    request = conversation()
    request.messages[-1] = request.messages[-1].model_copy(
        update={"content": "[PERSON_ABCD]"}
    )
    with ephemeral_session() as session:
        with pytest.raises(UnknownSessionToken):
            prepare_chat(request, session, Detector())
        assert not session.mappings


async def test_http_route_runs_detection_for_every_role_before_forwarding():
    seen = []

    class RecordingDetector(Detector):
        def detect(self, text):
            seen.append(text)
            return super().detect(text)

    app = create_app(
        detector_factory=lambda config: RecordingDetector(),
        upstream_transport=httpx.ASGITransport(app=create_fake_upstream()),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as api:
        response = await api.post(
            "/v1/chat/completions", json=conversation().model_dump()
        )
    assert response.status_code == 200
    assert seen[:5] == ["Hello Alice"] * 5
    assert "synthetic-model" in seen[5:]
    for role in ("system", "developer", "user", "assistant"):
        assert role in seen[5:]
    assert any("[PERSON_" in text for text in seen[5:])


def test_restored_assistant_and_known_token_share_identity():
    from pydantic import SecretStr

    from shield.gateway import prepare_chat

    with ephemeral_session() as session:
        token = session.allocate(EntityType.PERSON, SecretStr("Alice")).token
        request = ChatCompletionRequest.model_validate(
            {
                "model": "synthetic",
                "messages": [
                    {"role": "assistant", "content": "Alice"},
                    {"role": "user", "content": token},
                ],
            }
        )
        prepared = prepare_chat(request, session, Detector())
        assert [m.content for m in prepared.request.messages] == [token, token]
        assert prepared.report.protected_count == 1
        assert len(session.mappings) == 1


def test_allowlisted_disclosures_count_across_roles():
    from shield.gateway import prepare_chat

    detector = Detector()
    detector.policy = SpanPolicy(DetectionConfig(allowlist=["Alice"]))
    with ephemeral_session() as session:
        result = prepare_chat(conversation(), session, detector)
        assert result.report.protected_count == 0
        assert result.report.allowlisted_disclosure_count == 5
        assert all(m.content == "Hello Alice" for m in result.request.messages)
        assert not session.mappings
