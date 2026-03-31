"""Import VGE golden datasets (simple {text, category} format) to unified JSONL."""

from __future__ import annotations

import json
from pathlib import Path

from vigil_redteam.importers.base import BaseImporter
from vigil_redteam.schema.enums import AttackCategory, Channel, Tier, Verdict
from vigil_redteam.schema.scenario import TestScenario


class GoldenImporter(BaseImporter):
    """Convert VGE datasets/golden/ JSONL to unified TestScenario format."""

    def import_records(self, input_path: Path) -> list[TestScenario]:
        scenarios = []
        with input_path.open() as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                scenario = self._convert(record, i, input_path.stem)
                scenarios.append(scenario)
        return scenarios

    def _convert(self, record: dict, index: int, filename: str) -> TestScenario:
        text = record.get("text", "")
        category_raw = record.get("category", "").upper()

        if category_raw == "MALICIOUS":
            return TestScenario(
                id=f"vge_golden_{filename}_{index:04d}",
                category=AttackCategory.INSTRUCTION_OVERRIDE,
                subcategory="imported",
                language="en",
                channel=Channel.CHAT,
                user_input=text,
                expected_verdict=Verdict.BLOCK,
                expected_severity=4,
                tier=Tier.COVERAGE,
                source=f"vge_golden/{filename}",
            )

        return TestScenario(
            id=f"vge_golden_{filename}_{index:04d}",
            category=AttackCategory.SAFE_RISKY_LOOKALIKE,
            subcategory="benign_admin",
            language="en",
            channel=Channel.CHAT,
            user_input=text,
            expected_verdict=Verdict.ALLOW,
            expected_severity=0,
            tier=Tier.COVERAGE,
            source=f"vge_golden/{filename}",
        )
