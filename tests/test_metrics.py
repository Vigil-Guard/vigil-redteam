"""Tests for metrics computation."""

from __future__ import annotations

from vigil_redteam.metrics.pipeline import (
    compute_first_catching_layer,
    compute_layer_coverage,
    compute_pipeline_metrics,
)
from vigil_redteam.metrics.security import compute_recall_per_category, compute_security_metrics
from vigil_redteam.metrics.usability import compute_fpr_per_subcategory, compute_usability_metrics
from vigil_redteam.schema.result import TestResult


def test_security_metrics(blocked_result: TestResult, missed_result: TestResult):
    results = [blocked_result, missed_result]
    m = compute_security_metrics(results)
    assert m["attack_count"] == 2
    assert m["attack_detected"] == 1
    assert m["attack_recall"] == 0.5
    assert m["bypass_rate"] == 0.5


def test_security_metrics_empty():
    m = compute_security_metrics([])
    assert m["attack_count"] == 0


def test_usability_metrics(fp_result: TestResult):
    m = compute_usability_metrics([fp_result])
    assert m["benign_count"] == 1
    assert m["false_positives"] == 1
    assert m["fpr"] == 1.0


def test_usability_no_benigns(blocked_result: TestResult):
    m = compute_usability_metrics([blocked_result])
    assert m["fpr"] is None


def test_recall_per_category(blocked_result: TestResult, missed_result: TestResult):
    cats = compute_recall_per_category([blocked_result, missed_result])
    assert "instruction_override" in cats
    assert cats["instruction_override"]["recall"] == 0.5


def test_fpr_per_subcategory(fp_result: TestResult):
    subs = compute_fpr_per_subcategory([fp_result])
    assert "benign_admin" in subs
    assert subs["benign_admin"]["fpr"] == 1.0


def test_pipeline_metrics(blocked_result: TestResult, missed_result: TestResult):
    m = compute_pipeline_metrics([blocked_result, missed_result])
    assert m["total_tested"] == 2
    assert m["avg_latency_ms"] == 100.0
    assert m["unsafe_pass_severity"] == 5.0


def test_layer_coverage(blocked_result: TestResult):
    cov = compute_layer_coverage([blocked_result])
    assert cov["heuristics"] == 1
    assert cov["semantic"] == 1
    assert cov["llm_guard"] == 1


def test_first_catching_layer(blocked_result: TestResult):
    first = compute_first_catching_layer([blocked_result])
    assert first["heuristics"] == 1
