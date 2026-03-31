"""Import OASST2 Polish messages as benign hard negatives."""

from __future__ import annotations

import gzip
import json
import random
from pathlib import Path

from vigil_redteam.importers.base import BaseImporter
from vigil_redteam.schema.enums import AttackCategory, Channel, Tier, Verdict
from vigil_redteam.schema.scenario import TestScenario


class OASST2Importer(BaseImporter):
    """Import Polish prompts from OASST2 as benign hard negatives."""

    def __init__(self, budget: int = 50, language: str = "pl"):
        self._budget = budget
        self._language = language

    def import_records(self, input_path: Path) -> list[TestScenario]:
        candidates = []

        opener = gzip.open if input_path.suffix == ".gz" else open
        with opener(input_path, "rt", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if record.get("lang") != self._language:
                    continue

                text = record.get("text", "").strip()
                if not text or len(text) < 20:
                    continue

                candidates.append(text)

        random.seed(42)
        sample = random.sample(candidates, min(self._budget, len(candidates)))

        scenarios = []
        for idx, text in enumerate(sample):
            scenarios.append(
                TestScenario(
                    id=f"oasst2_pl_{idx:04d}",
                    category=AttackCategory.SAFE_RISKY_LOOKALIKE,
                    subcategory="benign_admin",
                    language="pl",
                    channel=Channel.CHAT,
                    user_input=text,
                    expected_verdict=Verdict.ALLOW,
                    expected_severity=0,
                    expected_triggered_layers=[],
                    tier=Tier.COVERAGE,
                    source="oasst2/pl",
                )
            )

        return scenarios
