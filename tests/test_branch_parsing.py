"""Tests for VGE API response branch parsing with new nested structure."""

from __future__ import annotations

from vigil_redteam.client.vge import VGEClient
from vigil_redteam.schema.result import (
    BranchScores,
    ContentModBranch,
    HeuristicsBranch,
    LlmGuardBranch,
    PiiBranch,
    ScopeDriftBranch,
    SemanticBranch,
)


class TestBranchParsing:
    """Table-driven tests for VGE response branch parsing."""

    def test_parse_full_response_with_all_branches(self):
        """Parse response with all branches populated."""
        data = {
            "requestId": "req-1",
            "decision": "BLOCKED",
            "score": 85,
            "threatLevel": "HIGH",
            "categories": ["PROMPT_INJECTION"],
            "latencyMs": 150,
            "branches": {
                "heuristics": {
                    "score": 90,
                    "threatLevel": "HIGH",
                    "explanations": ["Pattern match: command_injection", "Entropy analysis"],
                },
                "semantic": {
                    "score": 75,
                    "attackSimilarity": 0.85,
                    "safeSimilarity": 0.1,
                    "matchedCategory": "prompt_injection",
                },
                "llmGuard": {
                    "score": 95,
                    "verdict": "ATTACK DETECTED",
                    "modelUsed": "onnx-v1.2",
                },
                "pii": {
                    "detected": True,
                    "entityCount": 2,
                    "categories": ["EMAIL", "PHONE"],
                },
                "contentMod": {
                    "score": 45,
                    "confidence": 0.88,
                    "triggeredCategories": ["VIOLENCE"],
                    "detectedLanguage": "en",
                },
                "scopeDrift": {
                    "enabled": True,
                    "available": True,
                    "driftScore": 0.25,
                    "level": "NEAR_SCOPE",
                    "explanation": "Topic slightly off-domain",
                    "latencyMs": 50,
                },
            },
        }

        response = VGEClient._parse_response(data)

        assert response.decision == "BLOCKED"
        assert response.score == 85
        assert response.threat_level == "HIGH"

        # Check heuristics
        assert response.branches.heuristics.score == 90
        assert response.branches.heuristics.threat_level == "HIGH"
        assert response.branches.heuristics.explanations is not None
        assert len(response.branches.heuristics.explanations) == 2
        assert "Pattern match" in response.branches.heuristics.explanations[0]

        # Check semantic
        assert response.branches.semantic.score == 75
        assert response.branches.semantic.attack_similarity == 0.85
        assert response.branches.semantic.safe_similarity == 0.1
        assert response.branches.semantic.matched_category == "prompt_injection"

        # Check llm_guard
        assert response.branches.llm_guard.score == 95
        assert response.branches.llm_guard.verdict == "ATTACK DETECTED"
        assert response.branches.llm_guard.model_used == "onnx-v1.2"

        # Check pii
        assert response.branches.pii.detected is True
        assert response.branches.pii.entity_count == 2
        assert response.branches.pii.categories is not None
        assert "EMAIL" in response.branches.pii.categories

        # Check content_mod
        assert response.branches.content_mod.score == 45
        assert response.branches.content_mod.confidence == 0.88
        assert response.branches.content_mod.triggered_categories is not None
        assert "VIOLENCE" in response.branches.content_mod.triggered_categories
        assert response.branches.content_mod.detected_language == "en"

        # Check scope_drift
        assert response.branches.scope_drift.enabled is True
        assert response.branches.scope_drift.available is True
        assert response.branches.scope_drift.drift_score == 0.25
        assert response.branches.scope_drift.level == "NEAR_SCOPE"
        assert response.branches.scope_drift.latency_ms == 50

    def test_parse_response_with_missing_branches(self):
        """Parse response where some branches are missing."""
        data = {
            "requestId": "req-2",
            "decision": "ALLOWED",
            "score": 15,
            "threatLevel": "LOW",
            "categories": [],
            "latencyMs": 80,
            "branches": {
                "heuristics": {"score": 10},
                # semantic missing
                # llmGuard missing
                "pii": {"detected": False},
                # contentMod missing
                # scopeDrift missing
            },
        }

        response = VGEClient._parse_response(data)

        assert response.decision == "ALLOWED"

        # Populated branches have values
        assert response.branches.heuristics.score == 10
        assert response.branches.pii.detected is False

        # Missing branches have None fields
        assert response.branches.semantic.score is None
        assert response.branches.semantic.attack_similarity is None
        assert response.branches.llm_guard.score is None
        assert response.branches.content_mod.score is None
        assert response.branches.scope_drift.enabled is None
        # Use helper method to get default
        assert response.branches.scope_drift.is_enabled() is False

    def test_parse_response_with_sanitized_decision(self):
        """Parse response with SANITIZED decision."""
        data = {
            "requestId": "req-3",
            "decision": "SANITIZED",
            "score": 35,
            "threatLevel": "MEDIUM",
            "categories": ["PII_DETECTED"],
            "latencyMs": 200,
            "branches": {
                "pii": {"detected": True, "entityCount": 1, "categories": ["SSN"]},
            },
        }

        response = VGEClient._parse_response(data)

        assert response.decision == "SANITIZED"
        assert response.branches.pii.detected is True
        assert response.branches.pii.entity_count == 1
        assert response.branches.pii.categories is not None
        assert "SSN" in response.branches.pii.categories

    def test_parse_response_defaults_for_empty_branches(self):
        """Parse response with empty branches dict."""
        data = {
            "requestId": "req-4",
            "decision": "ALLOWED",
            "score": 5,
            "threatLevel": "LOW",
            "categories": [],
            "latencyMs": 50,
            "branches": {},
        }

        response = VGEClient._parse_response(data)

        # All branches should exist with default values
        assert isinstance(response.branches, BranchScores)
        assert isinstance(response.branches.heuristics, HeuristicsBranch)
        assert isinstance(response.branches.semantic, SemanticBranch)
        assert isinstance(response.branches.llm_guard, LlmGuardBranch)
        assert isinstance(response.branches.pii, PiiBranch)
        assert isinstance(response.branches.content_mod, ContentModBranch)
        assert isinstance(response.branches.scope_drift, ScopeDriftBranch)

        # Fields are None when not provided
        assert response.branches.heuristics.score is None
        assert response.branches.heuristics.threat_level is None
        assert response.branches.heuristics.explanations is None
        # Use helper methods to get defaults
        assert response.branches.heuristics.get_explanations() == []

        # Scope drift fields are None when not provided
        assert response.branches.scope_drift.enabled is None
        assert response.branches.scope_drift.available is None
        assert response.branches.scope_drift.explanation is None
        # Use helper methods to get defaults
        assert response.branches.scope_drift.is_enabled() is False
        assert response.branches.scope_drift.is_available() is False
        assert response.branches.scope_drift.get_explanation() == ""

    def test_parse_response_fallback_decision_is_allowed(self):
        """Parse response without decision field defaults to ALLOWED."""
        data = {
            "requestId": "req-5",
            "score": 0,
            "threatLevel": "LOW",
            "categories": [],
            "latencyMs": 20,
            "branches": {},
        }

        response = VGEClient._parse_response(data)

        assert response.decision == "ALLOWED"

    def test_parse_response_preserves_raw_dict(self):
        """Parse response preserves raw dict for debugging."""
        data = {
            "requestId": "req-6",
            "decision": "BLOCKED",
            "score": 88,
            "threatLevel": "HIGH",
            "categories": ["ATTACK"],
            "latencyMs": 100,
            "branches": {},
            "customField": "preserved",
        }

        response = VGEClient._parse_response(data)

        assert response.raw == data
        assert response.raw["customField"] == "preserved"
