"""Usability metrics — false positive rate, precision, business block cost."""

from __future__ import annotations

from collections import defaultdict

from vigil_redteam.schema.enums import Verdict
from vigil_redteam.schema.result import TestResult
from vigil_redteam.taxonomy.attacks import is_benign_category


def compute_usability_metrics(results: list[TestResult]) -> dict[str, float | int | None]:
    """Compute FPR, precision, and business block cost."""
    benigns = [r for r in results if is_benign_category(r.scenario.category) and r.error is None]
    attacks = [
        r for r in results if not is_benign_category(r.scenario.category) and r.error is None
    ]

    fp = sum(1 for r in benigns if r.actual_verdict == Verdict.BLOCK)
    tp = sum(1 for r in attacks if r.actual_verdict == Verdict.BLOCK)

    fpr = fp / len(benigns) if benigns else None
    precision = tp / (tp + fp) if (tp + fp) > 0 else None

    return {
        "benign_count": len(benigns),
        "false_positives": fp,
        "fpr": fpr,
        "precision": precision,
        "business_block_cost": fpr,  # same as FPR for now, expandable
    }


def compute_fpr_per_subcategory(results: list[TestResult]) -> dict[str, dict[str, float | int]]:
    """FPR broken down by benign subcategory."""
    by_sub: dict[str, list[TestResult]] = defaultdict(list)
    for r in results:
        if is_benign_category(r.scenario.category) and r.error is None:
            by_sub[r.scenario.subcategory].append(r)

    out = {}
    for sub, sub_results in sorted(by_sub.items()):
        fp = sum(1 for r in sub_results if r.actual_verdict == Verdict.BLOCK)
        out[sub] = {
            "count": len(sub_results),
            "false_positives": fp,
            "fpr": fp / len(sub_results),
        }
    return out
