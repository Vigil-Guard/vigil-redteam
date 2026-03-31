"""Import SPML dataset — system prompt + user prompt pairs with injection degree."""

from __future__ import annotations

import csv
import random
from pathlib import Path

from vigil_redteam.importers.base import BaseImporter
from vigil_redteam.schema.enums import AttackCategory, Channel, Tier, Verdict
from vigil_redteam.schema.scenario import TestScenario

_DEGREE_TO_SEVERITY = {
    "0": 0,
    "1": 1,
    "2": 2,
    "3": 3,
    "4": 4,
    "5": 4,
    "7": 5,
    "10": 5,
}

_DEGREE_TO_CATEGORY = {
    "0": AttackCategory.SAFE_RISKY_LOOKALIKE,
    "1": AttackCategory.INSTRUCTION_OVERRIDE,
    "2": AttackCategory.INSTRUCTION_OVERRIDE,
    "3": AttackCategory.SEMANTIC_EVASION,
    "4": AttackCategory.SEMANTIC_EVASION,
    "5": AttackCategory.INSTRUCTION_OVERRIDE,
    "7": AttackCategory.INSTRUCTION_OVERRIDE,
    "10": AttackCategory.INSTRUCTION_OVERRIDE,
}

_DEGREE_TO_SUBCATEGORY = {
    "0": "benign_admin",
    "1": "hierarchy_conflict",
    "2": "hierarchy_conflict",
    "3": "indirect_phrasing",
    "4": "indirect_phrasing",
    "5": "ignore_previous",
    "7": "ignore_previous",
    "10": "ignore_previous",
}


class SPMLImporter(BaseImporter):
    """Import SPML CSV with stratified sampling by injection degree."""

    def __init__(self, budget: dict[str, int] | None = None):
        self._budget = budget or {
            "0": 150,  # benign
            "3": 50,
            "4": 50,  # subtle attacks
            "5": 75,
            "7": 75,  # strong attacks
        }

    def import_records(self, input_path: Path) -> list[TestScenario]:
        by_degree: dict[str, list[dict]] = {}

        with input_path.open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                degree = row.get("Degree", "").strip()
                if degree in self._budget:
                    by_degree.setdefault(degree, []).append(row)

        scenarios = []
        idx = 0
        for degree, limit in sorted(self._budget.items()):
            pool = by_degree.get(degree, [])
            random.seed(42)
            sample = random.sample(pool, min(limit, len(pool)))

            for row in sample:
                scenario = self._convert(row, idx)
                if scenario:
                    scenarios.append(scenario)
                    idx += 1

        return scenarios

    @staticmethod
    def _convert(row: dict, index: int) -> TestScenario | None:
        system_prompt = row.get("System Prompt", "").strip()
        user_input = row.get("User Prompt", "").strip()
        degree = row.get("Degree", "0").strip()
        is_injection = row.get("Prompt injection", "0").strip() == "1"

        if not user_input:
            return None

        category = _DEGREE_TO_CATEGORY.get(degree, AttackCategory.INSTRUCTION_OVERRIDE)
        subcategory = _DEGREE_TO_SUBCATEGORY.get(degree, "ignore_previous")
        severity = _DEGREE_TO_SEVERITY.get(degree, 3)
        verdict = Verdict.BLOCK if is_injection else Verdict.ALLOW

        return TestScenario(
            id=f"spml_{index:05d}",
            category=category,
            subcategory=subcategory,
            language="en",
            channel=Channel.CHAT,
            user_input=user_input,
            system_context=system_prompt if system_prompt else None,
            expected_verdict=verdict,
            expected_severity=severity,
            expected_triggered_layers=["semantic", "llm_guard"] if is_injection else [],
            tier=Tier.COVERAGE,
            source=f"spml/degree_{degree}",
            notes=f"injection_degree={degree}",
        )
