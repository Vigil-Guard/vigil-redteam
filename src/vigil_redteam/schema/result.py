"""TestResult — outcome of running a single scenario against VGE."""

from __future__ import annotations

from pydantic import BaseModel

from vigil_redteam.schema.enums import FailureType, Verdict
from vigil_redteam.schema.scenario import TestScenario


class BranchScores(BaseModel):
    """Per-branch scores extracted from VGE API response."""

    heuristics: float | None = None
    semantic: float | None = None
    llm_guard: float | None = None
    pii_detected: bool | None = None
    content_mod: float | None = None

    model_config = {"extra": "ignore"}


class TestResult(BaseModel):
    """Result of running one TestScenario through the VGE pipeline."""

    scenario: TestScenario

    # API response fields
    actual_verdict: Verdict | None = None
    actual_score: float | None = None
    actual_threat_level: str | None = None
    actual_categories: list[str] = []
    branch_scores: BranchScores = BranchScores()
    decision_reason: str | None = None
    request_id: str | None = None

    # Outcome
    passed: bool = False
    failure_type: FailureType | None = None
    error: str | None = None
    latency_ms: float = 0.0

    # Raw response for debugging
    raw_response: dict | None = None

    model_config = {"extra": "ignore"}
