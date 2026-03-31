"""VGE API client — direct httpx wrapper with rate limiting.

Uses httpx directly (not the vigil-guard SDK) for maximum control
over response parsing, branch score extraction, and error handling.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

import httpx

from vigil_redteam.config import Config
from vigil_redteam.schema.result import BranchScores


@dataclass
class DetectionResponse:
    """Parsed VGE detection response."""

    request_id: str
    decision: str
    score: float
    threat_level: str
    categories: list[str]
    branches: BranchScores
    decision_reason: str | None
    latency_ms: float
    raw: dict


class RateLimiter:
    """Thread-safe token-bucket rate limiter."""

    def __init__(self, rps: float):
        self._interval = 1.0 / rps if rps > 0 else 0
        self._last_call = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        if self._interval == 0:
            return
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_call
            if elapsed < self._interval:
                time.sleep(self._interval - elapsed)
            self._last_call = time.monotonic()


class VGEClient:
    """Vigil Guard Enterprise API client for test execution."""

    def __init__(self, cfg: Config):
        self._base_url = cfg.api.base_url.rstrip("/")
        self._api_key = cfg.api.api_key
        self._timeout = cfg.api.timeout
        self._retries = cfg.runner.retries
        self._rate_limiter = RateLimiter(cfg.runner.rps)

        self._client = httpx.Client(
            timeout=httpx.Timeout(cfg.api.timeout),
            verify=cfg.api.verify_tls,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
        )

    def detect(self, prompt: str) -> DetectionResponse:
        """Send prompt to /v1/guard/input and return parsed response."""
        self._rate_limiter.wait()

        url = f"{self._base_url}/v1/guard/input"
        payload = {"prompt": prompt}

        last_error: Exception | None = None
        for attempt in range(1 + self._retries):
            try:
                resp = self._client.post(url, json=payload)
                resp.raise_for_status()
                return self._parse_response(resp.json())
            except (httpx.HTTPStatusError, httpx.TransportError) as e:
                last_error = e
                if attempt < self._retries:
                    time.sleep(min(2**attempt, 10))

        raise last_error  # type: ignore[misc]

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> VGEClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    @staticmethod
    def _parse_response(data: dict) -> DetectionResponse:
        branches_raw = data.get("branches", {}) or {}

        heuristics_score = None
        if h := branches_raw.get("heuristics"):
            heuristics_score = h.get("score")

        semantic_score = None
        if s := branches_raw.get("semantic"):
            semantic_score = s.get("score")

        llm_guard_score = None
        if lg := branches_raw.get("llmGuard"):
            llm_guard_score = lg.get("score")

        pii_detected = None
        if p := branches_raw.get("pii"):
            pii_detected = p.get("detected")

        content_mod_score = None
        if cm := branches_raw.get("contentMod"):
            content_mod_score = cm.get("score")

        return DetectionResponse(
            request_id=data.get("requestId", ""),
            decision=data.get("decision", "UNKNOWN"),
            score=data.get("score", 0),
            threat_level=data.get("threatLevel", "NONE"),
            categories=data.get("categories", []),
            branches=BranchScores(
                heuristics=heuristics_score,
                semantic=semantic_score,
                llm_guard=llm_guard_score,
                pii_detected=pii_detected,
                content_mod=content_mod_score,
            ),
            decision_reason=data.get("decisionReason"),
            latency_ms=data.get("latencyMs", 0),
            raw=data,
        )
