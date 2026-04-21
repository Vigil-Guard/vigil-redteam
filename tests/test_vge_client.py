"""Tests for VGEClient payload construction (agent-metadata support)."""

from __future__ import annotations

import json

import httpx

from vigil_redteam.client.vge import VGEClient
from vigil_redteam.config import Config


def _make_client(handler) -> VGEClient:
    cfg = Config()
    cfg.api.base_url = "https://api.test"
    cfg.api.api_key = "vg_test_" + "x" * 40
    cfg.api.verify_tls = False
    cfg.runner.rps = 0  # disable rate limiter in tests
    cfg.runner.retries = 0

    client = VGEClient(cfg)
    client._client.close()
    client._client = httpx.Client(transport=httpx.MockTransport(handler))
    return client


def _ok_response(data: dict) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "requestId": "req-1",
            "decision": "ALLOWED",
            "score": 0,
            "threatLevel": "LOW",
            "categories": [],
            "branches": {},
            "latencyMs": 1,
            **data,
        },
    )


def test_detect_without_metadata_does_not_send_metadata_key():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content.decode("utf-8"))
        return _ok_response({})

    client = _make_client(handler)
    client.detect("hello")

    assert captured["body"] == {"prompt": "hello"}
    assert "metadata" not in captured["body"]


def test_detect_with_metadata_includes_envelope_in_payload():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content.decode("utf-8"))
        return _ok_response({})

    envelope = {
        "sessionId": "s1",
        "promptId": "p1",
        "agentPlatform": "vigil-redteam",
        "agentVersion": "0.1.0",
        "toolName": "search",
    }

    client = _make_client(handler)
    client.detect("hello", envelope)

    assert captured["body"]["prompt"] == "hello"
    assert captured["body"]["metadata"] == envelope


def test_detect_with_none_metadata_is_identical_to_no_metadata():
    captured: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(json.loads(request.content.decode("utf-8")))
        return _ok_response({})

    client = _make_client(handler)
    client.detect("a")
    client.detect("a", None)

    assert captured[0] == captured[1] == {"prompt": "a"}


def test_detect_with_empty_metadata_does_not_send_metadata_key():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content.decode("utf-8"))
        return _ok_response({})

    client = _make_client(handler)
    client.detect("x", {})

    assert "metadata" not in captured["body"]


def test_detect_without_tool_does_not_send_tool_key():

    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content.decode("utf-8"))
        return _ok_response({})

    client = _make_client(handler)
    client.detect("hello", tool=None)

    assert captured["body"] == {"prompt": "hello"}
    assert "tool" not in captured["body"]


def test_detect_with_tool_forwards_tool_data():
    from vigil_redteam.schema.scenario import ToolContext, ToolResultContext

    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content.decode("utf-8"))
        return _ok_response({})

    tool = ToolContext(
        name="search_web",
        id="tool-123",
        vendor="anthropic",
        args={"query": "python"},
        result=ToolResultContext(content={"results": []}, is_error=False, duration_ms=50),
    )

    client = _make_client(handler)
    client.detect("hello", tool=tool)

    assert captured["body"]["prompt"] == "hello"
    assert captured["body"]["tool"]["name"] == "search_web"
    assert captured["body"]["tool"]["id"] == "tool-123"
    assert captured["body"]["tool"]["vendor"] == "anthropic"
    assert captured["body"]["tool"]["args"] == {"query": "python"}
    assert captured["body"]["tool"]["result"]["content"] == {"results": []}
    assert captured["body"]["tool"]["result"]["isError"] is False
    assert captured["body"]["tool"]["result"]["durationMs"] == 50


def test_detect_with_partial_tool_still_serializes():
    from vigil_redteam.schema.scenario import ToolContext

    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content.decode("utf-8"))
        return _ok_response({})

    tool = ToolContext(name="just_name")

    client = _make_client(handler)
    client.detect("hello", tool=tool)

    assert captured["body"]["tool"]["name"] == "just_name"
    assert "id" not in captured["body"]["tool"]
    assert "vendor" not in captured["body"]["tool"]
    assert "args" not in captured["body"]["tool"]
    assert "result" not in captured["body"]["tool"]
