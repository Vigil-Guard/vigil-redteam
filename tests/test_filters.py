"""Tests for scenario filtering."""

from __future__ import annotations

from vigil_redteam.runner.filters import filter_scenarios
from vigil_redteam.schema.scenario import TestScenario


def test_filter_by_category(attack_scenario: TestScenario, benign_scenario: TestScenario):
    filtered = filter_scenarios(
        [attack_scenario, benign_scenario],
        categories=["instruction_override"],
    )
    assert len(filtered) == 1
    assert filtered[0].id == "test_atk_001"


def test_filter_by_language(attack_scenario: TestScenario, benign_scenario: TestScenario):
    filtered = filter_scenarios(
        [attack_scenario, benign_scenario],
        languages=["en"],
    )
    assert len(filtered) == 2


def test_filter_combined(attack_scenario: TestScenario, benign_scenario: TestScenario):
    filtered = filter_scenarios(
        [attack_scenario, benign_scenario],
        categories=["safe_risky_lookalike"],
        languages=["en"],
    )
    assert len(filtered) == 1
    assert filtered[0].id == "test_safe_001"


def test_no_filters(attack_scenario: TestScenario, benign_scenario: TestScenario):
    filtered = filter_scenarios([attack_scenario, benign_scenario])
    assert len(filtered) == 2
