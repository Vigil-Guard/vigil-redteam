"""Render RunReport as a markdown document."""

from __future__ import annotations

from vigil_redteam.schema.report import RunReport


def render_markdown(report: RunReport) -> str:
    """Render a full markdown report."""
    lines: list[str] = []
    _w = lines.append

    _w(f"# Vigil RedTeam Report — {report.run_id}")
    _w("")
    _w(f"**Date:** {report.timestamp.strftime('%Y-%m-%d %H:%M UTC')}")
    _w(f"**Target:** {report.vge_url}")
    _w(f"**Dataset:** {report.dataset_path}")
    _w(f"**Threshold:** {report.threshold}")
    _w("")

    # Executive Summary
    _w("## 1. Executive Summary")
    _w("")
    _w("| Metric | Value |")
    _w("|--------|-------|")
    _w(f"| Total scenarios | {report.total_scenarios} |")
    _w(f"| Passed | {report.passed} |")
    _w(f"| Failed | {report.failed} |")
    _w(f"| Errors | {report.errors} |")

    sec = report.security.metrics
    _w(f"| Attack recall | {_fmt_pct(sec.get('attack_recall'))} |")
    _w(f"| Bypass rate | {_fmt_pct(sec.get('bypass_rate'))} |")

    usa = report.usability.metrics
    _w(f"| FPR | {_fmt_pct(usa.get('fpr'))} |")
    _w(f"| Precision | {_fmt_pct(usa.get('precision'))} |")

    pip = report.pipeline.metrics
    _w(f"| Avg latency | {_fmt_ms(pip.get('avg_latency_ms'))} |")
    _w(f"| P95 latency | {_fmt_ms(pip.get('p95_latency_ms'))} |")
    _w(f"| Unsafe pass severity | {_fmt_float(pip.get('unsafe_pass_severity'))} |")
    _w("")

    # Category Breakdown
    _w("## 2. Recall by Category")
    _w("")
    if report.by_category.slices:
        _w("| Category | Count | Detected | Recall |")
        _w("|----------|-------|----------|--------|")
        for cat, mg in report.by_category.slices.items():
            m = mg.metrics
            _w(
                f"| {cat} | {m.get('count', 0)} | {m.get('detected', 0)} | {_fmt_pct(m.get('recall'))} |"
            )
    _w("")

    # Language Breakdown
    _w("## 3. Recall by Language")
    _w("")
    if report.by_language.slices:
        _w("| Language | Count | Detected | Recall |")
        _w("|----------|-------|----------|--------|")
        for lang, mg in report.by_language.slices.items():
            m = mg.metrics
            _w(
                f"| {lang} | {m.get('count', 0)} | {m.get('detected', 0)} | {_fmt_pct(m.get('recall'))} |"
            )
    _w("")

    # Channel Breakdown
    _w("## 4. Recall by Channel")
    _w("")
    if report.by_channel.slices:
        _w("| Channel | Count | Detected | Recall |")
        _w("|---------|-------|----------|--------|")
        for ch, mg in report.by_channel.slices.items():
            m = mg.metrics
            _w(
                f"| {ch} | {m.get('count', 0)} | {m.get('detected', 0)} | {_fmt_pct(m.get('recall'))} |"
            )
    _w("")

    # Failure Clusters
    _w("## 5. Failure Clusters")
    _w("")
    if report.failure_clusters:
        _w("| Failure Type | Count | Examples |")
        _w("|--------------|-------|----------|")
        for fc in report.failure_clusters:
            examples = ", ".join(fc.example_ids[:5])
            _w(f"| {fc.failure_type} | {fc.count} | {examples} |")
    else:
        _w("No failures detected.")
    _w("")

    # Layer Analysis
    _w("## 6. Layer Analysis")
    _w("")
    _w("### Layer Coverage (trigger count)")
    _w("")
    if report.layer_coverage:
        _w("| Layer | Triggers |")
        _w("|-------|----------|")
        for layer, count in sorted(report.layer_coverage.items(), key=lambda x: -x[1]):
            _w(f"| {layer} | {count} |")
    _w("")

    _w("### First Catching Layer (for detected attacks)")
    _w("")
    if report.first_catching_layer:
        _w("| Layer | First catch count |")
        _w("|-------|-------------------|")
        for layer, count in sorted(report.first_catching_layer.items(), key=lambda x: -x[1]):
            _w(f"| {layer} | {count} |")
    _w("")

    return "\n".join(lines)


def _fmt_pct(val: float | int | None) -> str:
    if val is None:
        return "N/A"
    return f"{val * 100:.1f}%"


def _fmt_ms(val: float | int | None) -> str:
    if val is None:
        return "N/A"
    return f"{val:.0f}ms"


def _fmt_float(val: float | int | None) -> str:
    if val is None:
        return "N/A"
    return f"{val:.2f}"
