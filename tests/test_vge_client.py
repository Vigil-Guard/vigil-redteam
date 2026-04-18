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
            "decision": "ALLOW",
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
