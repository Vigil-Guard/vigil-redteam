"""VGE API client — direct httpx wrapper with rate limiting.

Uses httpx directly (not the vigil-guard SDK) for maximum control
over response parsing, branch score extraction, and error handling.

Response Parsing:
- Branch fields tolerate null values for optional fields (explanations, categories, triggered_categories, enabled, available, explanation).
- Use branch helper methods for safe defaults: heuristics.get_explanations(), scope_drift.is_enabled(), etc.
- scope_drift uses 0-1 scale (similarity), while other detectors use 0-100. Metrics reporting normalizes for comparison.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

import httpx

from vigil_redteam.config import Config
from vigil_redteam.schema.result import (
    BranchScores,
    ContentModBranch,
    HeuristicsBranch,
    LlmGuardBranch,
    PiiBranch,
    ScopeDriftBranch,
    SemanticBranch,
)
from vigil_redteam.schema.scenario import ToolContext


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

    def detect(
        self,
        prompt: str,
        metadata: dict[str, str | int | float | bool] | None = None,
        tool: ToolContext | None = None,
    ) -> DetectionResponse:
        """Send prompt to /v1/guard/input and return parsed response.

        `metadata` is an optional experimental envelope used for manual validation
        of agent context logging (PRD_28). When None or empty, no `metadata` key is
        included in the payload, so baseline runs stay byte-identical.

        `tool` is an optional tool invocation context forwarded to VGE API.
        """
        self._rate_limiter.wait()

        url = f"{self._base_url}/v1/guard/input"
        payload: dict[str, object] = {"prompt": prompt}
        if metadata:
            payload["metadata"] = metadata
        if tool:
            tool_data: dict[str, object] = {"name": tool.name}
            if tool.id is not None:
                tool_data["id"] = tool.id
            if tool.vendor is not None:
                tool_data["vendor"] = tool.vendor
            if tool.args is not None:
                tool_data["args"] = tool.args
            if tool.result is not None:
                result_data: dict[str, object] = {"content": tool.result.content}
                if tool.result.is_error is not None:
                    result_data["isError"] = tool.result.is_error
                if tool.result.duration_ms is not None:
                    result_data["durationMs"] = tool.result.duration_ms
                tool_data["result"] = result_data
            payload["tool"] = tool_data

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

        # Parse heuristics branch
        raw_h = branches_raw.get("heuristics") or {}
        heuristics = HeuristicsBranch(
            score=raw_h.get("score"),
            threat_level=raw_h.get("threatLevel"),
            explanations=raw_h.get("explanations"),
        )

        # Parse semantic branch
        raw_s = branches_raw.get("semantic") or {}
        semantic = SemanticBranch(
            score=raw_s.get("score"),
            attack_similarity=raw_s.get("attackSimilarity"),
            safe_similarity=raw_s.get("safeSimilarity"),
            matched_category=raw_s.get("matchedCategory"),
        )

        # Parse LLM guard branch
        raw_lg = branches_raw.get("llmGuard") or {}
        llm_guard = LlmGuardBranch(
            score=raw_lg.get("score"),
            verdict=raw_lg.get("verdict"),
            model_used=raw_lg.get("modelUsed"),
        )

        # Parse PII branch
        raw_p = branches_raw.get("pii") or {}
        pii = PiiBranch(
            detected=raw_p.get("detected"),
            entity_count=raw_p.get("entityCount"),
            categories=raw_p.get("categories"),
        )

        # Parse content mod branch
        raw_cm = branches_raw.get("contentMod") or {}
        content_mod = ContentModBranch(
            score=raw_cm.get("score"),
            confidence=raw_cm.get("confidence"),
            triggered_categories=raw_cm.get("triggeredCategories"),
            detected_language=raw_cm.get("detectedLanguage"),
        )

        # Parse scope drift branch
        raw_sd = branches_raw.get("scopeDrift") or {}
        scope_drift = ScopeDriftBranch(
            enabled=raw_sd.get("enabled"),
            available=raw_sd.get("available"),
            drift_score=raw_sd.get("driftScore"),
            level=raw_sd.get("level"),
            explanation=raw_sd.get("explanation"),
            latency_ms=raw_sd.get("latencyMs"),
        )

        return DetectionResponse(
            request_id=data.get("requestId", ""),
            decision=data.get("decision", "ALLOWED"),
            score=data.get("score", 0),
            threat_level=data.get("threatLevel", "NONE"),
            categories=data.get("categories", []),
            branches=BranchScores(
                heuristics=heuristics,
                semantic=semantic,
                llm_guard=llm_guard,
                pii=pii,
                content_mod=content_mod,
                scope_drift=scope_drift,
            ),
            decision_reason=data.get("decisionReason"),
            latency_ms=data.get("latencyMs", 0),
            raw=data,
        )
