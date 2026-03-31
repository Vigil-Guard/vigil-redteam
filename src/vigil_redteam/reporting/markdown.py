"""Render RunReport as a markdown document."""

from __future__ import annotations

from vigil_redteam.schema.report import RunReport


def render_markdown(report: RunReport) -> str:
    """Render a full markdown report with single_turn/contextual split."""
    lines: list[str] = []
    _w = lines.append

    _w(f"# Vigil RedTeam Report — {report.run_id}")
    _w("")
    _w(f"**Date:** {report.timestamp.strftime('%Y-%m-%d %H:%M UTC')}")
    _w(f"**Target:** {report.vge_url}")
    _w(f"**Dataset:** {report.dataset_path}")
    _w(f"**Threshold:** {report.threshold}")
    _w("")

    # Context mode warning
    if report.contextual_count > 0:
        _w("> **Note:** This run includes contextual scenarios whose verdict depends on")
        _w("> system_context or conversation state that VGE API cannot receive.")
        _w("> **Only single_turn metrics are valid for arbiter calibration.**")
        _w("> Contextual metrics are diagnostic only.")
        _w("")

    # 1. Executive Summary — split view
    _w("## 1. Executive Summary")
    _w("")
    _w("| Metric | Overall | Single-turn (arbiter gate) | Contextual (diagnostic) |")
    _w("|--------|---------|---------------------------|------------------------|")
    _w(
        f"| Scenarios | {report.total_scenarios} | {report.single_turn_count} | {report.contextual_count} |"
    )

    sec = report.security.metrics
    st_sec = report.single_turn_security.metrics
    ctx_sec = report.contextual_security.metrics
    _w(
        f"| Attack recall | {_fmt_pct(sec.get('attack_recall'))} | {_fmt_pct(st_sec.get('attack_recall'))} | {_fmt_pct(ctx_sec.get('attack_recall'))} |"
    )
    _w(
        f"| Bypass rate | {_fmt_pct(sec.get('bypass_rate'))} | {_fmt_pct(st_sec.get('bypass_rate'))} | {_fmt_pct(ctx_sec.get('bypass_rate'))} |"
    )

    usa = report.usability.metrics
    st_usa = report.single_turn_usability.metrics
    ctx_usa = report.contextual_usability.metrics
    _w(
        f"| FPR | {_fmt_pct(usa.get('fpr'))} | {_fmt_pct(st_usa.get('fpr'))} | {_fmt_pct(ctx_usa.get('fpr'))} |"
    )
    _w(
        f"| Precision | {_fmt_pct(usa.get('precision'))} | {_fmt_pct(st_usa.get('precision'))} | {_fmt_pct(ctx_usa.get('precision'))} |"
    )

    pip = report.pipeline.metrics
    _w(f"| Avg latency | {_fmt_ms(pip.get('avg_latency_ms'))} | — | — |")
    _w(f"| P95 latency | {_fmt_ms(pip.get('p95_latency_ms'))} | — | — |")
    _w(f"| Unsafe pass severity | {_fmt_float(pip.get('unsafe_pass_severity'))} | — | — |")
    _w("")

    # 2. By Source
    _w("## 2. Metrics by Source")
    _w("")
    if report.by_source.slices:
        _w("| Source | Total | Attacks | Recall | Benigns | FPR |")
        _w("|--------|-------|---------|--------|---------|-----|")
        for src, mg in report.by_source.slices.items():
            m = mg.metrics
            _w(
                f"| {src} | {m.get('total', 0)} | {m.get('attacks', 0)} | {_fmt_pct(m.get('recall'))} | {m.get('benigns', 0)} | {_fmt_pct(m.get('fpr'))} |"
            )
    _w("")

    # 3. Recall by Category
    _w("## 3. Recall by Category")
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

    # 4. Recall by Language
    _w("## 4. Recall by Language")
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

    # 5. Failure Clusters
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

    # 6. Layer Analysis
    _w("## 6. Layer Analysis")
    _w("")
    if report.layer_coverage:
        _w("| Layer | Triggers | First catch |")
        _w("|-------|----------|-------------|")
        for layer, count in sorted(report.layer_coverage.items(), key=lambda x: -x[1]):
            first = report.first_catching_layer.get(layer, 0)
            _w(f"| {layer} | {count} | {first} |")
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
