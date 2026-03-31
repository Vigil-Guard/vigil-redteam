"""Import HackAPrompt competition data — real attack attempts with success labels."""

from __future__ import annotations

import random
from pathlib import Path

from vigil_redteam.importers.base import BaseImporter
from vigil_redteam.schema.enums import AttackCategory, Channel, Tier, Verdict
from vigil_redteam.schema.scenario import TestScenario


class HackAPromptImporter(BaseImporter):
    """Import HackAPrompt parquet with stratified sampling by success/failure."""

    def __init__(self, success_budget: int = 100, failure_budget: int = 50):
        self._success_budget = success_budget
        self._failure_budget = failure_budget

    def import_records(self, input_path: Path) -> list[TestScenario]:
        import pandas as pd

        df = pd.read_parquet(input_path)

        # Filter to rows with actual user_input
        df = df[df["user_input"].notna() & (df["user_input"].str.len() > 10)]
        # Remove very long inputs (>2000 chars) — noisy
        df = df[df["user_input"].str.len() < 2000]

        random.seed(42)

        scenarios = []
        idx = 0

        # Successful attacks — stratified by level
        successes = df[df["correct"] == True]  # noqa: E712
        if len(successes) > 0:
            levels = sorted(successes["level"].unique())
            per_level = max(1, self._success_budget // len(levels))
            for level in levels:
                level_rows = successes[successes["level"] == level]
                sample = level_rows.sample(n=min(per_level, len(level_rows)), random_state=42)
                for _, row in sample.iterrows():
                    s = self._convert(row, idx, is_success=True)
                    if s:
                        scenarios.append(s)
                        idx += 1

        # Failed attacks — stratified by level
        failures = df[df["correct"] == False]  # noqa: E712
        if len(failures) > 0:
            levels = sorted(failures["level"].unique())
            per_level = max(1, self._failure_budget // len(levels))
            for level in levels:
                level_rows = failures[failures["level"] == level]
                sample = level_rows.sample(n=min(per_level, len(level_rows)), random_state=42)
                for _, row in sample.iterrows():
                    s = self._convert(row, idx, is_success=False)
                    if s:
                        scenarios.append(s)
                        idx += 1

        return scenarios

    @staticmethod
    def _convert(row, index: int, is_success: bool) -> TestScenario | None:
        user_input = str(row.get("user_input", "")).strip()
        if not user_input or len(user_input) < 5:
            return None

        level = int(row.get("level", 0))
        model = str(row.get("model", "unknown"))
        prompt = str(row.get("prompt", ""))

        # All HackAPrompt entries are attacks — they should be blocked
        # Higher levels = more sophisticated attacks
        severity = min(5, 3 + level // 3)

        category = _level_to_category(level)
        subcategory = _level_to_subcategory(level)

        return TestScenario(
            id=f"hap_{index:05d}",
            category=category,
            subcategory=subcategory,
            language="en",
            channel=Channel.CHAT,
            user_input=user_input,
            system_context=prompt[:500] if prompt else None,
            expected_verdict=Verdict.BLOCK,
            expected_severity=severity,
            expected_triggered_layers=[],
            tier=Tier.COVERAGE,
            source=f"hackaprompt/level_{level}/{'success' if is_success else 'failure'}",
            notes=f"model={model} correct={is_success}",
        )


def _level_to_category(level: int) -> AttackCategory:
    """All HackAPrompt levels are jailbreak attempts to make the model
    output a specific phrase. Levels differ in defense complexity, not attack type."""
    if level <= 2:
        return AttackCategory.INSTRUCTION_OVERRIDE
    if level <= 5:
        return AttackCategory.SEMANTIC_EVASION
    return AttackCategory.OBFUSCATION


def _level_to_subcategory(level: int) -> str:
    """Map competition levels to subcategories based on actual attack patterns."""
    if level <= 1:
        return "ignore_previous"
    if level == 2:
        return "hierarchy_conflict"
    if level <= 4:
        return "indirect_phrasing"
    if level == 5:
        return "roleplay"
    if level <= 7:
        return "code_wrapped"
    return "mixed_language"
