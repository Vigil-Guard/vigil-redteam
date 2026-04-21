"""TestResult — outcome of running a single scenario against VGE."""

from __future__ import annotations

from pydantic import BaseModel, Field

from vigil_redteam.schema.enums import FailureType, Verdict
from vigil_redteam.schema.scenario import TestScenario


class HeuristicsBranch(BaseModel):
    """Heuristics detection branch response."""

    score: float | None = None
    threat_level: str | None = None
    explanations: list[str] | None = None

    model_config = {"extra": "ignore"}

    def get_explanations(self) -> list[str]:
        """Get explanations list, defaulting to empty if None."""
        return self.explanations or []


class SemanticBranch(BaseModel):
    """Semantic detection branch response."""

    score: float | None = None
    attack_similarity: float | None = None
    safe_similarity: float | None = None
    matched_category: str | None = None

    model_config = {"extra": "ignore"}


class PiiBranch(BaseModel):
    """PII detection branch response."""

    detected: bool | None = None
    entity_count: int | None = None
    categories: list[str] | None = None

    model_config = {"extra": "ignore"}

    def get_categories(self) -> list[str]:
        """Get categories list, defaulting to empty if None."""
        return self.categories or []


class LlmGuardBranch(BaseModel):
    """LLM Guard detection branch response."""

    score: float | None = None
    verdict: str | None = None
    model_used: str | None = None

    model_config = {"extra": "ignore"}


class ContentModBranch(BaseModel):
    """Content moderation detection branch response."""

    score: float | None = None
    confidence: float | None = None
    triggered_categories: list[str] | None = None
    detected_language: str | None = None

    model_config = {"extra": "ignore"}

    def get_triggered_categories(self) -> list[str]:
        """Get triggered categories list, defaulting to empty if None."""
        return self.triggered_categories or []


class ScopeDriftBranch(BaseModel):
    """Scope drift detection branch response."""

    enabled: bool | None = None
    available: bool | None = None
    drift_score: float | None = None
    level: str | None = None
    explanation: str | None = None
    latency_ms: float | None = None

    model_config = {"extra": "ignore"}

    def is_enabled(self) -> bool:
        """Check if scope drift is enabled, defaulting to False if None."""
        return self.enabled or False

    def is_available(self) -> bool:
        """Check if scope drift is available, defaulting to False if None."""
        return self.available or False

    def get_explanation(self) -> str:
        """Get explanation string, defaulting to empty if None."""
        return self.explanation or ""


class BranchScores(BaseModel):
    """Per-branch scores extracted from VGE API response."""

    heuristics: HeuristicsBranch = Field(default_factory=HeuristicsBranch)
    semantic: SemanticBranch = Field(default_factory=SemanticBranch)
    llm_guard: LlmGuardBranch = Field(default_factory=LlmGuardBranch)
    pii: PiiBranch = Field(default_factory=PiiBranch)
    content_mod: ContentModBranch = Field(default_factory=ContentModBranch)
    scope_drift: ScopeDriftBranch = Field(default_factory=ScopeDriftBranch)

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
