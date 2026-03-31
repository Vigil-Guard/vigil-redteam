"""CLI interface for vigil-redteam."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from vigil_redteam.config import load_config, require_api_key
from vigil_redteam.reporting.generator import generate_report
from vigil_redteam.reporting.markdown import render_markdown
from vigil_redteam.runner.executor import execute_run
from vigil_redteam.schema.scenario import validate_dataset


@click.group()
@click.version_option(package_name="vigil-redteam")
def main() -> None:
    """Vigil RedTeam — adversarial testing framework for Vigil Guard."""


@main.command()
@click.option("--dataset", default="golden", help="Dataset tier: golden, coverage, or path to dir")
@click.option("--category", default=None, help="Comma-separated attack categories to include")
@click.option("--channel", default=None, help="Comma-separated channels to include")
@click.option("--language", default=None, help="Comma-separated languages to include")
@click.option("--concurrency", default=None, type=int, help="Override concurrency from config")
@click.option("--limit", default=None, type=int, help="Max scenarios to run")
@click.option("--config", "config_path", default=None, type=click.Path(exists=True))
@click.option("--output", default=None, help="Output file path for results JSON")
def run(
    dataset: str,
    category: str | None,
    channel: str | None,
    language: str | None,
    concurrency: int | None,
    limit: int | None,
    config_path: str | None,
    output: str | None,
) -> None:
    """Run test scenarios against VGE API."""
    cfg = load_config(Path(config_path) if config_path else None)
    require_api_key(cfg)

    if concurrency:
        cfg.runner.concurrency = concurrency

    dataset_dir = _resolve_dataset_dir(dataset, cfg)
    if not dataset_dir.exists():
        click.echo(f"Error: dataset directory not found: {dataset_dir}", err=True)
        sys.exit(1)

    categories = category.split(",") if category else None
    channels = channel.split(",") if channel else None
    languages = language.split(",") if language else None

    results = execute_run(
        cfg,
        dataset_dir,
        categories=categories,
        channels=channels,
        languages=languages,
        limit=limit,
    )

    if not results:
        return

    report = generate_report(
        results,
        vge_url=cfg.api.base_url,
        dataset_path=str(dataset_dir),
        threshold=cfg.runner.threshold,
    )

    # Save results JSON
    results_dir = Path(cfg.reporting.results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)
    ts = report.timestamp.strftime("%Y%m%d_%H%M%S")
    results_file = Path(output) if output else results_dir / f"run_{ts}.json"

    results_data = {
        "report": report.model_dump(mode="json"),
        "results": [r.model_dump(mode="json") for r in results],
    }
    results_file.write_text(json.dumps(results_data, indent=2, default=str))
    click.echo(f"Results saved to {results_file}")

    # Save markdown report
    reports_dir = Path(cfg.reporting.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    md_file = reports_dir / f"report_{ts}.md"
    md_file.write_text(render_markdown(report))
    click.echo(f"Report saved to {md_file}")

    # Print summary
    click.echo("")
    sec = report.security.metrics
    usa = report.usability.metrics
    click.echo(
        f"Pass: {report.passed}/{report.total_scenarios}  "
        f"Recall: {_pct(sec.get('attack_recall'))}  "
        f"FPR: {_pct(usa.get('fpr'))}  "
        f"Errors: {report.errors}"
    )


@main.command()
@click.argument("path", type=click.Path(exists=True))
def validate(path: str) -> None:
    """Validate JSONL dataset files."""
    p = Path(path)
    files = list(p.glob("*.jsonl")) if p.is_dir() else [p]

    total_errors = 0
    for f in sorted(files):
        errors = validate_dataset(f)
        if errors:
            for err in errors:
                click.echo(f"  ERROR: {err}", err=True)
            total_errors += len(errors)
        else:
            click.echo(f"  OK: {f.name}")

    if total_errors:
        click.echo(f"\n{total_errors} validation error(s) found.", err=True)
        sys.exit(1)
    else:
        click.echo(f"\nAll {len(files)} file(s) valid.")


@main.command("report")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True))
def report_cmd(input_path: str) -> None:
    """Generate markdown report from a results JSON file."""
    data = json.loads(Path(input_path).read_text())
    from vigil_redteam.schema.report import RunReport

    report = RunReport.model_validate(data["report"])
    md = render_markdown(report)
    click.echo(md)


@main.command()
@click.option("--baseline", required=True, type=click.Path(exists=True))
@click.option("--current", required=True, type=click.Path(exists=True))
def diff(baseline: str, current: str) -> None:
    """Compare two test runs and show regressions/improvements."""
    from vigil_redteam.schema.report import RunReport

    base_data = json.loads(Path(baseline).read_text())
    curr_data = json.loads(Path(current).read_text())

    base_report = RunReport.model_validate(base_data["report"])
    curr_report = RunReport.model_validate(curr_data["report"])

    click.echo(f"Baseline: {base_report.run_id} ({base_report.timestamp.strftime('%Y-%m-%d')})")
    click.echo(f"Current:  {curr_report.run_id} ({curr_report.timestamp.strftime('%Y-%m-%d')})")
    click.echo("")

    _diff_metric(
        "Attack recall",
        base_report.security.metrics,
        curr_report.security.metrics,
        "attack_recall",
        higher_is_better=True,
    )
    _diff_metric(
        "Bypass rate",
        base_report.security.metrics,
        curr_report.security.metrics,
        "bypass_rate",
        higher_is_better=False,
    )
    _diff_metric(
        "FPR",
        base_report.usability.metrics,
        curr_report.usability.metrics,
        "fpr",
        higher_is_better=False,
    )
    _diff_metric(
        "Precision",
        base_report.usability.metrics,
        curr_report.usability.metrics,
        "precision",
        higher_is_better=True,
    )
    _diff_metric(
        "Avg latency",
        base_report.pipeline.metrics,
        curr_report.pipeline.metrics,
        "avg_latency_ms",
        higher_is_better=False,
    )
    _diff_metric(
        "Unsafe pass severity",
        base_report.pipeline.metrics,
        curr_report.pipeline.metrics,
        "unsafe_pass_severity",
        higher_is_better=False,
    )


def _diff_metric(label: str, base: dict, curr: dict, key: str, *, higher_is_better: bool) -> None:
    b = base.get(key)
    c = curr.get(key)
    if b is None or c is None:
        click.echo(f"  {label}: N/A")
        return

    delta = c - b
    if abs(delta) < 0.001:
        marker = "="
    elif (delta > 0) == higher_is_better:
        marker = "+"
    else:
        marker = "REGRESSION"

    if isinstance(b, float) and abs(b) <= 1:
        click.echo(f"  {label}: {b * 100:.1f}% -> {c * 100:.1f}% ({delta * 100:+.1f}%) [{marker}]")
    else:
        click.echo(f"  {label}: {b:.1f} -> {c:.1f} ({delta:+.1f}) [{marker}]")


@main.command("mutate")
@click.option("--input", "input_path", default=None, type=click.Path(exists=True))
@click.option("--mutators", default=None, help="Comma-separated mutator names (default: all)")
@click.option("--output", default=None, help="Output JSONL path")
@click.option("--list-mutators", "show_list", is_flag=True, help="List available mutators")
def mutate_cmd(
    input_path: str | None, mutators: str | None, output: str | None, show_list: bool
) -> None:
    """Generate mutation variants from a dataset."""
    import vigil_redteam.mutation.mutators  # noqa: F401 — registers all mutators
    from vigil_redteam.mutation.engine import MutationEngine
    from vigil_redteam.mutation.registry import list_mutators as _list_mutators
    from vigil_redteam.schema.scenario import load_scenarios, load_scenarios_from_dir

    if show_list:
        for name in _list_mutators():
            click.echo(f"  {name}")
        return

    if not input_path:
        click.echo("Error: --input is required (or use --list-mutators)", err=True)
        sys.exit(1)

    p = Path(input_path)
    scenarios = load_scenarios_from_dir(p) if p.is_dir() else load_scenarios(p)
    click.echo(f"Loaded {len(scenarios)} base scenarios")

    mutator_names = mutators.split(",") if mutators else None
    engine = MutationEngine(mutator_names)

    variants = engine.mutate_batch(scenarios, mode="independent")
    click.echo(f"Generated {len(variants)} mutation variants")

    out_path = Path(output) if output else Path("datasets/mutation/generated.jsonl")
    engine.write_mutations(variants, out_path)
    click.echo(f"Written to {out_path}")


@main.group("import")
def import_group() -> None:
    """Import external datasets to unified format."""


@import_group.command("pangea")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True))
@click.option("--output", required=True, type=click.Path())
@click.option("--projection", default="last_user", type=click.Choice(["last_user", "full_context"]))
def import_pangea(input_path: str, output: str, projection: str) -> None:
    """Import Pangea benchmark dataset."""
    from vigil_redteam.importers.pangea import PangeaImporter

    importer = PangeaImporter(projection=projection)
    scenarios = importer.import_records(Path(input_path))
    importer.write_jsonl(scenarios, Path(output))
    click.echo(f"Imported {len(scenarios)} scenarios to {output}")


@import_group.command("golden")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True))
@click.option("--output", required=True, type=click.Path())
def import_golden(input_path: str, output: str) -> None:
    """Import VGE golden dataset (simple {text, category} format)."""
    from vigil_redteam.importers.golden import GoldenImporter

    importer = GoldenImporter()
    scenarios = importer.import_records(Path(input_path))
    importer.write_jsonl(scenarios, Path(output))
    click.echo(f"Imported {len(scenarios)} scenarios to {output}")


@import_group.command("spml")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True))
@click.option("--output", required=True, type=click.Path())
def import_spml(input_path: str, output: str) -> None:
    """Import SPML dataset (system prompt + user prompt + injection degree)."""
    from vigil_redteam.importers.spml import SPMLImporter

    importer = SPMLImporter()
    scenarios = importer.import_records(Path(input_path))
    importer.write_jsonl(scenarios, Path(output))
    click.echo(f"Imported {len(scenarios)} scenarios to {output}")


@import_group.command("hackaprompt")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True))
@click.option("--output", required=True, type=click.Path())
def import_hackaprompt(input_path: str, output: str) -> None:
    """Import HackAPrompt competition data (parquet)."""
    from vigil_redteam.importers.hackaprompt import HackAPromptImporter

    importer = HackAPromptImporter()
    scenarios = importer.import_records(Path(input_path))
    importer.write_jsonl(scenarios, Path(output))
    click.echo(f"Imported {len(scenarios)} scenarios to {output}")


@import_group.command("systemchat")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True))
@click.option("--output", required=True, type=click.Path())
def import_systemchat(input_path: str, output: str) -> None:
    """Import SystemChat multi-turn conversations (benign)."""
    from vigil_redteam.importers.systemchat import SystemChatImporter

    importer = SystemChatImporter()
    scenarios = importer.import_records(Path(input_path))
    importer.write_jsonl(scenarios, Path(output))
    click.echo(f"Imported {len(scenarios)} scenarios to {output}")


@import_group.command("enterprise")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True))
@click.option("--output", required=True, type=click.Path())
def import_enterprise(input_path: str, output: str) -> None:
    """Import Enterprise categorized attack prompts."""
    from vigil_redteam.importers.enterprise import EnterpriseImporter

    importer = EnterpriseImporter()
    scenarios = importer.import_records(Path(input_path))
    importer.write_jsonl(scenarios, Path(output))
    click.echo(f"Imported {len(scenarios)} scenarios to {output}")


@import_group.command("oasst2")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True))
@click.option("--output", required=True, type=click.Path())
@click.option("--language", default="pl", help="Language filter (ISO 639-1)")
def import_oasst2(input_path: str, output: str, language: str) -> None:
    """Import OASST2 messages as benign hard negatives."""
    from vigil_redteam.importers.oasst2 import OASST2Importer

    importer = OASST2Importer(language=language)
    scenarios = importer.import_records(Path(input_path))
    importer.write_jsonl(scenarios, Path(output))
    click.echo(f"Imported {len(scenarios)} scenarios to {output}")


def _resolve_dataset_dir(dataset: str, cfg) -> Path:
    p = Path(dataset)
    if p.is_dir():
        return p

    dirs = {
        "golden": cfg.datasets.golden_dir,
        "coverage": cfg.datasets.coverage_dir,
        "mutation": cfg.datasets.mutation_dir,
    }
    return Path(dirs.get(dataset, dataset))


def _pct(val: float | int | None) -> str:
    if val is None:
        return "N/A"
    return f"{val * 100:.1f}%"
