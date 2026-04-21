"""Tests for failure type classification."""

from __future__ import annotations

from vigil_redteam.client.vge import DetectionResponse
from vigil_redteam.runner.comparator import compare
from vigil_redteam.schema.enums import FailureType
from vigil_redteam.schema.result import (
    BranchScores,
)
from vigil_redteam.schema.scenario import TestScenario


def _make_scenario(
    category: str = "instruction_override",
    subcategory: str = "ignore_previous",
    expected_verdict: str = "block",
    mutation_family: str | None = "literal",
) -> TestScenario:
    return TestScenario(
        id="cmp_001",
        category=category,
        subcategory=subcategory,
        language="en",
        channel="chat",
        user_input="test",
        expected_verdict=expected_verdict,
        expected_severity=5,
        tier="golden",
        source="test",
        mutation_family=mutation_family,
    )


def _make_response(decision: str = "BLOCKED", score: float = 80) -> DetectionResponse:
    from vigil_redteam.schema.result import HeuristicsBranch, SemanticBranch

    return DetectionResponse(
        request_id="req-1",
        decision=decision,
        score=score,
        threat_level="HIGH",
        categories=["PROMPT_INJECTION"],
        branches=BranchScores(
            heuristics=HeuristicsBranch(score=80),
            semantic=SemanticBranch(score=70),
        ),
        decision_reason="test",
        latency_ms=100,
        raw={},
    )


def test_correct_block():
    scenario = _make_scenario(expected_verdict="block")
    result = compare(scenario, _make_response("BLOCKED"))
    assert result.passed
    assert result.failure_type is None


def test_correct_allow():
    scenario = _make_scenario(
        expected_verdict="allow", category="safe_risky_lookalike", subcategory="benign_admin"
    )
    result = compare(scenario, _make_response("ALLOWED", 10))
    assert result.passed


def test_false_negative_direct():
    scenario = _make_scenario()
    result = compare(scenario, _make_response("ALLOWED", 10))
    assert not result.passed
    assert result.failure_type == FailureType.FN_DIRECT


def test_false_negative_obfuscated():
    scenario = _make_scenario(category="obfuscation", subcategory="base64")
    result = compare(scenario, _make_response("ALLOWED", 10))
    assert result.failure_type == FailureType.FN_OBFUSCATED


def test_false_negative_semantic():
    scenario = _make_scenario(category="semantic_evasion", subcategory="roleplay")
    result = compare(scenario, _make_response("ALLOWED", 10))
    assert result.failure_type == FailureType.FN_SEMANTIC


def test_false_negative_multiturn():
    scenario = _make_scenario(category="multiturn_slowburn", subcategory="staged_trust")
    result = compare(scenario, _make_response("ALLOWED", 10))
    assert result.failure_type == FailureType.FN_MULTITURN


def test_false_negative_mutation():
    scenario = _make_scenario(mutation_family="base64")
    result = compare(scenario, _make_response("ALLOWED", 10))
    assert result.failure_type == FailureType.FN_OBFUSCATED


def test_false_positive_business():
    scenario = _make_scenario(
        category="safe_risky_lookalike",
        subcategory="benign_admin",
        expected_verdict="allow",
    )
    result = compare(scenario, _make_response("BLOCKED"))
    assert result.failure_type == FailureType.FP_BUSINESS


def test_false_positive_code():
    scenario = _make_scenario(
        category="safe_risky_lookalike",
        subcategory="code_resembling_attack",
        expected_verdict="allow",
    )
    result = compare(scenario, _make_response("BLOCKED"))
    assert result.failure_type == FailureType.FP_CODE


def test_false_positive_security_research():
    scenario = _make_scenario(
        category="safe_risky_lookalike",
        subcategory="security_testing",
        expected_verdict="allow",
    )
    result = compare(scenario, _make_response("BLOCKED"))
    assert result.failure_type == FailureType.FP_SECURITY_RESEARCH


def test_sanitized_counts_as_block():
    scenario = _make_scenario(expected_verdict="block")
    result = compare(scenario, _make_response("SANITIZED"))
    assert result.passed
