"""Test executor — runs scenarios against VGE API concurrently."""

from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from vigil_redteam.client.vge import VGEClient
from vigil_redteam.config import Config
from vigil_redteam.runner.comparator import compare, make_error_result
from vigil_redteam.runner.filters import filter_scenarios
from vigil_redteam.schema.result import TestResult
from vigil_redteam.schema.scenario import TestScenario, load_scenarios_from_dir


def execute_run(
    cfg: Config,
    dataset_dir: Path,
    *,
    categories: list[str] | None = None,
    channels: list[str] | None = None,
    languages: list[str] | None = None,
    context_modes: list[str] | None = None,
    limit: int | None = None,
) -> list[TestResult]:
    """Load scenarios, filter, and execute against VGE API.

    Returns list of TestResult objects ready for metrics computation.
    """
    scenarios = load_scenarios_from_dir(dataset_dir)
    scenarios = filter_scenarios(
        scenarios,
        categories=categories,
        channels=channels,
        languages=languages,
        context_modes=context_modes,
    )

    if limit and limit < len(scenarios):
        scenarios = scenarios[:limit]

    if not scenarios:
        print("No scenarios to run after filtering.", file=sys.stderr)
        return []

    print(f"Running {len(scenarios)} scenarios (concurrency={cfg.runner.concurrency})")

    results: list[TestResult] = []
    completed = 0

    with VGEClient(cfg) as client:
        with ThreadPoolExecutor(max_workers=cfg.runner.concurrency) as pool:
            futures = {
                pool.submit(_run_single, client, scenario): scenario for scenario in scenarios
            }

            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                completed += 1

                if completed % 10 == 0 or completed == len(scenarios):
                    _print_progress(completed, len(scenarios), results)

    results.sort(key=lambda r: r.scenario.id)
    return results


def _run_single(client: VGEClient, scenario: TestScenario) -> TestResult:
    """Execute a single scenario and return the result."""
    try:
        response = client.detect(scenario.user_input, scenario.metadata)
        return compare(scenario, response)
    except Exception as e:
        return make_error_result(scenario, str(e))


def _print_progress(completed: int, total: int, results: list[TestResult]) -> None:
    passed = sum(1 for r in results if r.passed)
    failed = sum(1 for r in results if not r.passed and r.error is None)
    errors = sum(1 for r in results if r.error is not None)
    pct = (completed / total) * 100
    print(f"  [{pct:5.1f}%] {completed}/{total}  pass={passed} fail={failed} err={errors}")
