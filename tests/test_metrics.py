"""Tests for metrics computation."""

from __future__ import annotations

from vigil_redteam.metrics.pipeline import (
    compute_first_catching_layer,
    compute_layer_coverage,
    compute_pipeline_metrics,
)
from vigil_redteam.metrics.security import compute_recall_per_category, compute_security_metrics
from vigil_redteam.metrics.usability import compute_fpr_per_subcategory, compute_usability_metrics
from vigil_redteam.schema.result import (
    BranchScores,
    HeuristicsBranch,
    ScopeDriftBranch,
    TestResult as ResultModel,
)
from vigil_redteam.schema.scenario import TestScenario as ScenarioModel


def test_security_metrics(blocked_result: ResultModel, missed_result: ResultModel):
    results = [blocked_result, missed_result]
    m = compute_security_metrics(results)
    assert m["attack_count"] == 2
    assert m["attack_detected"] == 1
    assert m["attack_recall"] == 0.5
    assert m["bypass_rate"] == 0.5


def test_security_metrics_empty():
    m = compute_security_metrics([])
    assert m["attack_count"] == 0


def test_usability_metrics(fp_result: ResultModel):
    m = compute_usability_metrics([fp_result])
    assert m["benign_count"] == 1
    assert m["false_positives"] == 1
    assert m["fpr"] == 1.0


def test_usability_no_benigns(blocked_result: ResultModel):
    m = compute_usability_metrics([blocked_result])
    assert m["fpr"] is None


def test_recall_per_category(blocked_result: ResultModel, missed_result: ResultModel):
    cats = compute_recall_per_category([blocked_result, missed_result])
    assert "instruction_override" in cats
    assert cats["instruction_override"]["recall"] == 0.5


def test_fpr_per_subcategory(fp_result: ResultModel):
    subs = compute_fpr_per_subcategory([fp_result])
    assert "benign_admin" in subs
    assert subs["benign_admin"]["fpr"] == 1.0


def test_pipeline_metrics(blocked_result: ResultModel, missed_result: ResultModel):
    m = compute_pipeline_metrics([blocked_result, missed_result])
    assert m["total_tested"] == 2
    assert m["avg_latency_ms"] == 100.0
    assert m["unsafe_pass_severity"] == 5.0


def test_layer_coverage(blocked_result: ResultModel):
    cov = compute_layer_coverage([blocked_result])
    assert cov["heuristics"] == 1
    assert cov["semantic"] == 1
    assert cov["llm_guard"] == 1


def test_first_catching_layer(blocked_result: ResultModel):
    first = compute_first_catching_layer([blocked_result])
    assert first["heuristics"] == 1


def test_layer_coverage_counts_scope_drift_on_unit_scale():
    scenario = ScenarioModel(
        id="scope_drift_001",
        category="tool_agent_abuse",
        subcategory="call_tool_despite_policy",
        language="en",
        channel="agent_tool",
        user_input="Use the forbidden tool.",
        expected_verdict="block",
        expected_severity=4,
        tier="golden",
        source="test",
    )
    result = ResultModel(
        scenario=scenario,
        actual_verdict="block",
        branch_scores=BranchScores(scope_drift=ScopeDriftBranch(drift_score=0.95)),
    )

    cov = compute_layer_coverage([result])
    assert cov["scope_drift"] == 1


def test_first_catching_layer_normalizes_scope_drift_scale():
    scenario = ScenarioModel(
        id="scope_drift_002",
        category="tool_agent_abuse",
        subcategory="call_tool_despite_policy",
        language="en",
        channel="agent_tool",
        user_input="Use the forbidden tool.",
        expected_verdict="block",
        expected_severity=4,
        tier="golden",
        source="test",
    )
    result = ResultModel(
        scenario=scenario,
        actual_verdict="block",
        branch_scores=BranchScores(
            heuristics=HeuristicsBranch(score=45),
            scope_drift=ScopeDriftBranch(drift_score=0.95),
        ),
    )

    first = compute_first_catching_layer([result])
    assert first["scope_drift"] == 1
