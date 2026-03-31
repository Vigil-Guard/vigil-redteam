"""Generate RunReport from a list of TestResults."""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import UTC, datetime

from vigil_redteam.metrics.pipeline import (
    compute_first_catching_layer,
    compute_layer_coverage,
    compute_pipeline_metrics,
)
from vigil_redteam.metrics.robustness import compute_mutation_survival_rate
from vigil_redteam.metrics.security import (
    compute_recall_per_category,
    compute_recall_per_dimension,
    compute_security_metrics,
)
from vigil_redteam.metrics.usability import compute_usability_metrics
from vigil_redteam.schema.enums import ContextMode
from vigil_redteam.schema.report import (
    FailureCluster,
    MetricGroup,
    RunReport,
    SliceMetrics,
)
from vigil_redteam.schema.result import TestResult


def generate_report(
    results: list[TestResult],
    *,
    vge_url: str,
    dataset_path: str,
    threshold: int,
) -> RunReport:
    """Build a complete RunReport from test results."""
    passed = sum(1 for r in results if r.passed)
    failed = sum(1 for r in results if not r.passed and r.error is None)
    errors = sum(1 for r in results if r.error is not None)

    security = compute_security_metrics(results)
    usability = compute_usability_metrics(results)
    pipeline = compute_pipeline_metrics(results)
    robustness = compute_mutation_survival_rate(results)

    # Split by context_mode
    st_results = [r for r in results if r.scenario.context_mode == ContextMode.SINGLE_TURN]
    ctx_results = [r for r in results if r.scenario.context_mode == ContextMode.CONTEXTUAL]

    # Source-level breakdown
    def _source_key(r: TestResult) -> str:
        return r.scenario.source.split("/")[0]

    return RunReport(
        run_id=str(uuid.uuid4())[:8],
        timestamp=datetime.now(UTC),
        vge_url=vge_url,
        dataset_path=dataset_path,
        total_scenarios=len(results),
        threshold=threshold,
        passed=passed,
        failed=failed,
        errors=errors,
        security=MetricGroup(metrics=security),
        usability=MetricGroup(metrics=usability),
        pipeline=MetricGroup(metrics=pipeline),
        robustness=MetricGroup(metrics=robustness),
        # Context mode split
        single_turn_security=MetricGroup(metrics=compute_security_metrics(st_results)),
        single_turn_usability=MetricGroup(metrics=compute_usability_metrics(st_results)),
        contextual_security=MetricGroup(metrics=compute_security_metrics(ctx_results)),
        contextual_usability=MetricGroup(metrics=compute_usability_metrics(ctx_results)),
        single_turn_count=len(st_results),
        contextual_count=len(ctx_results),
        # Breakdowns
        by_category=_build_slice("category", compute_recall_per_category(results)),
        by_language=_build_slice("language", compute_recall_per_dimension(results, "language")),
        by_channel=_build_slice("channel", compute_recall_per_dimension(results, "channel")),
        by_source=_build_slice("source", _compute_source_breakdown(results)),
        by_mutation_family=_build_slice(
            "mutation_family", compute_recall_per_dimension(results, "mutation_family")
        ),
        failure_clusters=_build_failure_clusters(results),
        layer_coverage=compute_layer_coverage(results),
        first_catching_layer=compute_first_catching_layer(results),
    )


def _build_slice(dimension: str, data: dict[str, dict]) -> SliceMetrics:
    slices = {}
    for key, metrics in data.items():
        slices[key] = MetricGroup(metrics=metrics)
    return SliceMetrics(dimension=dimension, slices=slices)


def _compute_source_breakdown(results: list[TestResult]) -> dict[str, dict[str, float | int]]:
    """Recall + FPR per source dataset."""
    from vigil_redteam.schema.enums import Verdict
    from vigil_redteam.taxonomy.attacks import is_benign_category

    by_source: dict[str, list[TestResult]] = defaultdict(list)
    for r in results:
        if r.error is not None:
            continue
        key = r.scenario.source.split("/")[0]
        by_source[key].append(r)

    out = {}
    for src, src_results in sorted(by_source.items()):
        attacks = [r for r in src_results if not is_benign_category(r.scenario.category)]
        benigns = [r for r in src_results if is_benign_category(r.scenario.category)]

        detected = sum(1 for r in attacks if r.actual_verdict == Verdict.BLOCK) if attacks else 0
        fp = sum(1 for r in benigns if r.actual_verdict == Verdict.BLOCK) if benigns else 0

        out[src] = {
            "total": len(src_results),
            "attacks": len(attacks),
            "benigns": len(benigns),
            "detected": detected,
            "recall": detected / len(attacks) if attacks else None,
            "fp": fp,
            "fpr": fp / len(benigns) if benigns else None,
        }
    return out


def _build_failure_clusters(results: list[TestResult]) -> list[FailureCluster]:
    by_type: dict[str, list[str]] = defaultdict(list)
    for r in results:
        if r.failure_type:
            by_type[r.failure_type].append(r.scenario.id)

    clusters = []
    for ft, ids in sorted(by_type.items(), key=lambda x: -len(x[1])):
        clusters.append(
            FailureCluster(
                failure_type=ft,
                count=len(ids),
                example_ids=ids[:10],
            )
        )
    return clusters
