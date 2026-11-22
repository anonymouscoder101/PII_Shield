"""The executable synthetic demo protects real model detections without sockets."""

import json
import socket

from shield.api import ChatCompletionChunk, ChatCompletionResponse


async def test_offline_demo_protects_all_roles_and_restores_json_and_buffered_sse(
    monkeypatch,
):
    # This catches a demo that bypasses Stage 1, forwards originals, uses a real
    # provider/local reviewer, or presents an SSE transcript without restoring it.
    from demo.roundtrip import run_demo

    def forbidden_connection(*args, **kwargs):
        raise AssertionError("The offline demo must never open a network socket")

    monkeypatch.setattr(socket.socket, "connect", forbidden_connection)
    result = await run_demo()

    assert result["mode"] == "fast"
    assert result["stage1_status"] == "loaded"
    assert len(result["exchanges"]) == 2
    expected_values = (
        "synthetic.person@example.test",
        "EMP-123456",
        "Alice Smith",
        "+1 202-555-0147",
    )
    expected_content = (
        "Synthetic email: synthetic.person@example.test.\n"
        "Internal ID: EMP-123456.\n"
        "Meet Alice Smith tomorrow. Phone: +1 202-555-0147.\n"
        "Reply to synthetic email: synthetic.person@example.test."
    )
    for exchange in result["exchanges"]:
        sent = exchange["upstream_request"]
        assert [message["role"] for message in sent["messages"]] == [
            "system",
            "developer",
            "user",
            "assistant",
        ]
        serialized = json.dumps(sent)
        assert all(value not in serialized for value in expected_values)
        assert all("[" in message["content"] for message in sent["messages"])
        assert sent["stream"] is False
        assert "stream_options" not in sent
        assert exchange["report"]["protected_counts"] == {
            "EMAIL_ADDRESS": 2,
            "EMPLOYEE_ID": 1,
            "PERSON": 1,
            "PHONE_NUMBER": 1,
        }
        assert exchange["report"]["protected_count"] == 5
        assert exchange["report"]["unknown_token_count"] == 0
        if exchange["delivery"] == "json":
            completion = ChatCompletionResponse.model_validate(exchange["response"])
            assert [choice.message.content for choice in completion.choices] == [
                expected_content,
                expected_content,
            ]
            assert [choice.finish_reason for choice in completion.choices] == [
                "stop",
                "length",
            ]
        else:
            assert exchange["delivery"] == "buffered_sse"
            frames = exchange["response"].strip().split("\n\n")
            assert frames[-1] == "data: [DONE]"
            assert sum(frame == "data: [DONE]" for frame in frames) == 1
            chunks = [
                ChatCompletionChunk.model_validate_json(frame.removeprefix("data: "))
                for frame in frames[:-1]
            ]
            choices = [choice for chunk in chunks for choice in chunk.choices]
            for index in (0, 1):
                assert (
                    "".join(
                        choice.delta.content or ""
                        for choice in choices
                        if choice.index == index
                    )
                    == expected_content
                )
                assert any(
                    choice.index == index and choice.delta.role == "assistant"
                    for choice in choices
                )
            assert [
                (choice.index, choice.finish_reason)
                for choice in choices
                if choice.finish_reason
            ] == [(0, "stop"), (1, "length")]
            assert sum(chunk.usage is not None for chunk in chunks) == 1
    assert {exchange["delivery"] for exchange in result["exchanges"]} == {
        "json",
        "buffered_sse",
    }
