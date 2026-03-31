"""Import Enterprise prompt dataset — 49K categorized attack prompts."""

from __future__ import annotations

import json
import random
from pathlib import Path

from vigil_redteam.importers.base import BaseImporter
from vigil_redteam.schema.enums import AttackCategory, Channel, Tier, Verdict
from vigil_redteam.schema.scenario import TestScenario

_CAT_MAP = {
    "JAILBREAK_ROLEPLAY": (AttackCategory.SEMANTIC_EVASION, "roleplay"),
    "INSTRUCTION_OVERRIDE": (AttackCategory.INSTRUCTION_OVERRIDE, "ignore_previous"),
    "PARTIAL_EXTRACTION": (AttackCategory.DATA_EXFILTRATION, "show_hidden_context"),
    "SENSITIVE_DISCLOSURE": (AttackCategory.DATA_EXFILTRATION, "reveal_secrets"),
    "CODE_INJECTION": (AttackCategory.TOOL_AGENT_ABUSE, "command_execution"),
    "MULTILINGUAL_ATTACK": (AttackCategory.OBFUSCATION, "mixed_language"),
    "PROMPT_LEAKING": (AttackCategory.DATA_EXFILTRATION, "dump_memory"),
    "CONTEXT_MANIPULATION": (AttackCategory.CONTEXT_INCONSISTENCY, "business_msg_hidden_override"),
    "PAYLOAD_SPLITTING": (AttackCategory.OBFUSCATION, "code_wrapped"),
    "ADVERSARIAL_SUFFIX": (AttackCategory.OBFUSCATION, "homoglyphs"),
    "AUTHORITY_APPEAL": (AttackCategory.INSTRUCTION_OVERRIDE, "act_as_admin"),
    "FEW_SHOT_ATTACK": (AttackCategory.SEMANTIC_EVASION, "indirect_phrasing"),
    "REFUSAL_SUPPRESSION": (AttackCategory.SEMANTIC_EVASION, "euphemistic"),
    "GOAL_HIJACKING": (AttackCategory.INSTRUCTION_OVERRIDE, "hierarchy_conflict"),
    "CBRNE": (AttackCategory.SEMANTIC_EVASION, "research_pretext"),
}


class EnterpriseImporter(BaseImporter):
    """Import enterprise dataset with stratified sampling across categories."""

    def __init__(self, budget: int = 200):
        self._budget = budget

    def import_records(self, input_path: Path) -> list[TestScenario]:
        by_cat: dict[str, list[dict]] = {}

        with input_path.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                row = json.loads(line)
                cat = row.get("category", "UNKNOWN")
                if cat in _CAT_MAP:
                    by_cat.setdefault(cat, []).append(row)

        # Stratified sampling — proportional to sqrt(count) to boost rare categories
        import math

        weights = {cat: math.sqrt(len(rows)) for cat, rows in by_cat.items()}
        total_weight = sum(weights.values())

        scenarios = []
        idx = 0
        random.seed(42)

        for cat, rows in sorted(by_cat.items()):
            n = max(1, round(self._budget * weights[cat] / total_weight))
            sample = random.sample(rows, min(n, len(rows)))

            for row in sample:
                s = self._convert(row, idx, cat)
                if s:
                    scenarios.append(s)
                    idx += 1

        return scenarios[: self._budget]

    @staticmethod
    def _convert(row: dict, index: int, ent_category: str) -> TestScenario | None:
        prompt = row.get("prompt", "").strip()
        if not prompt or len(prompt) < 10:
            return None
        if len(prompt) > 2000:
            prompt = prompt[:2000]

        attack_cat, subcategory = _CAT_MAP.get(
            ent_category, (AttackCategory.INSTRUCTION_OVERRIDE, "ignore_previous")
        )

        return TestScenario(
            id=f"ent_{index:05d}",
            category=attack_cat,
            subcategory=subcategory,
            language="en",
            channel=Channel.CHAT,
            user_input=prompt,
            expected_verdict=Verdict.BLOCK,
            expected_severity=4,
            expected_triggered_layers=["heuristics", "semantic"],
            tier=Tier.COVERAGE,
            source=f"enterprise/{ent_category}",
        )
