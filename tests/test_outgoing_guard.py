"""The final scan uses decoded values from the exact serialized payload."""

import json

import pytest
from pydantic import SecretStr

from shield.api import ChatCompletionRequest
from shield.config import DetectionConfig
from shield.contracts import DetectedSpan, EntityType
from shield.detect.resolve import SpanPolicy
from shield.session import ephemeral_session


class Detector:
    def __init__(self, config=None):
        self.policy = SpanPolicy(config)
        self.seen = []

    def detect(self, text):
        self.seen.append(text)
        spans = []
        for word in ("Alice", "秘密", "line\nbreak"):
            start = text.find(word)
            if start >= 0:
                spans.append(
                    DetectedSpan(
                        start=start,
                        end=start + len(word),
                        entity_type=EntityType.PERSON,
                        confidence=0.99,
                    )
                )
        return spans


def test_guard_scans_decoded_model_and_nested_values_without_allocating():
    from shield.guard import scan_payload

    payload = json.dumps(
        {
            "model": "Alice",
            "messages": [
                {"role": "assistant", "content": '秘密 and line\nbreak "quoted" \\'}
            ],
        },
        ensure_ascii=True,
    ).encode()
    detector = Detector()
    with ephemeral_session() as state:
        report = scan_payload(payload, state, detector)
        assert report.remaining_counts == {EntityType.PERSON: 3}
        assert report.remaining_count == 3
        assert '秘密 and line\nbreak "quoted" \\' in detector.seen
        assert "Alice" in detector.seen
        assert not state.mappings
        assert "Alice" not in repr(report)


def test_guard_recognizes_only_owned_placeholders():
    from shield.guard import scan_payload
    from shield.substitute import UnknownSessionToken

    with ephemeral_session() as state:
        token = state.allocate(EntityType.PERSON, SecretStr("Alice")).token

        class TokenDetector(Detector):
            def detect(self, text):
                # An identifier detector would otherwise flag the token suffix.
                if text == token:
                    return [
                        DetectedSpan(
                            start=0,
                            end=len(text),
                            entity_type=EntityType.PERSON,
                            confidence=1.0,
                        )
                    ]
                return []

        report = scan_payload(
            json.dumps({"content": token}).encode(), state, TokenDetector()
        )
        assert report.remaining_count == 0
        assert len(state.mappings) == 1
        with pytest.raises(UnknownSessionToken):
            scan_payload(b'{"content":"[PERSON_ABCD]"}', state, Detector())


def test_guard_allowlist_and_threshold_use_same_policy():
    from shield.guard import scan_payload

    with ephemeral_session() as state:
        report = scan_payload(
            b'{"model":"Alice"}', state, Detector(DetectionConfig(allowlist=["Alice"]))
        )
        assert report.remaining_count == 0
        assert report.allowlisted_disclosure_counts == {EntityType.PERSON: 1}
        report = scan_payload(
            b'{"model":"Alice"}', state, Detector(DetectionConfig(threshold=1.0))
        )
        assert report.remaining_count == 0
        assert report.below_threshold_count == 1


def test_preparation_freezes_bytes_after_registration_and_scans_them():
    from shield.gateway import prepare_chat

    detector = Detector()
    request = ChatCompletionRequest.model_validate(
        {"model": "synthetic", "messages": [{"role": "user", "content": "Alice"}]}
    )
    with ephemeral_session() as state:
        prepared = prepare_chat(request, state, detector)
        body = json.loads(prepared.payload)
        token = body["messages"][0]["content"]
        assert state.has_token(token)
        assert prepared.guard.remaining_count == 0
        assert body["stream"] is False and "stream_options" not in body
        prepared.request.messages.clear()
        assert json.loads(prepared.payload) == body
        assert "Alice" not in repr(prepared)


@pytest.mark.parametrize("payload", [b"{", b"\xff"])
def test_scan_failures_are_static(payload):
    from shield.guard import scan_payload
    from shield.substitute import TokenSubstitutionError

    with ephemeral_session() as state:
        with pytest.raises(
            TokenSubstitutionError, match="Outgoing protection scan failed"
        ):
            scan_payload(payload, state, Detector())


def test_detector_failure_does_not_expose_text():
    from shield.guard import scan_payload
    from shield.substitute import TokenSubstitutionError

    class Failing(Detector):
        def detect(self, text):
            raise RuntimeError("Alice private failure")

    with ephemeral_session() as state:
        with pytest.raises(TokenSubstitutionError) as error:
            scan_payload(b'{"model":"Alice"}', state, Failing())
        assert "Alice" not in str(error.value)


def test_persistent_mappings_are_committed_before_guard(tmp_path):
    import sqlite3

    from shield.config import Argon2Config, VaultConfig
    from shield.gateway import prepare_chat
    from shield.persistent import PersistentSessions

    config = VaultConfig(
        path=tmp_path / "vault.db",
        argon2=Argon2Config(memory_kib=32, time_cost=1, parallelism=1),
    )
    observed = []

    class CommittedDetector(Detector):
        def detect(self, text):
            if "[PERSON_" in text:
                # An independent connection sees the commit during the guard.
                with sqlite3.connect(config.path) as db:
                    observed.append(
                        db.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
                    )
            return super().detect(text)

    request = ChatCompletionRequest.model_validate(
        {"model": "synthetic", "messages": [{"role": "assistant", "content": "Alice"}]}
    )
    with PersistentSessions.open(config, SecretStr("synthetic")) as service:
        sid = service.create().session_id
        with service.use(sid) as state:
            prepared = prepare_chat(request, state, CommittedDetector())
            token = json.loads(prepared.payload)["messages"][0]["content"]
            assert prepared.guard.remaining_count == 0
            assert state.has_token(token)
        assert observed == [1]
        assert (
            service.read_mapping(sid, token).original_value.get_secret_value()
            == "Alice"
        )
