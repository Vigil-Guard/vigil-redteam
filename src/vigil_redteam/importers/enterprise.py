"""Import Enterprise prompt dataset — 49K categorized attack prompts.

Uses content-based classification instead of trusting source categories,
since source labels (e.g. CONTEXT_MANIPULATION) often don't match actual content.
"""

from __future__ import annotations

import json
import math
import random
from pathlib import Path

from vigil_redteam.importers.base import BaseImporter
from vigil_redteam.schema.enums import AttackCategory, Channel, Tier, Verdict
from vigil_redteam.schema.scenario import TestScenario

# Source categories to sample from (all are attacks)
_SAMPLE_CATEGORIES = {
    "JAILBREAK_ROLEPLAY",
    "INSTRUCTION_OVERRIDE",
    "PARTIAL_EXTRACTION",
    "SENSITIVE_DISCLOSURE",
    "CODE_INJECTION",
    "MULTILINGUAL_ATTACK",
    "PROMPT_LEAKING",
    "CONTEXT_MANIPULATION",
    "PAYLOAD_SPLITTING",
    "ADVERSARIAL_SUFFIX",
    "AUTHORITY_APPEAL",
    "FEW_SHOT_ATTACK",
    "REFUSAL_SUPPRESSION",
    "GOAL_HIJACKING",
}

# Content-based classification keywords
_OVERRIDE_KW = (
    "ignore",
    "disregard",
    "forget",
    "override",
    "bypass",
    "new instructions",
    "from now on",
    "you are now",
    "reset",
    "developer mode",
    "maintenance mode",
)
_EXFIL_KW = (
    "secret",
    "api key",
    "password",
    "credential",
    "token",
    "dump",
    "export all",
    "reveal",
    "show me your",
    "print your",
    "output your",
    "share your config",
)
_ROLEPLAY_KW = (
    "roleplay",
    "pretend",
    "act as",
    "character named",
    "persona",
    "dan ",
    "jailbreak",
    "no restrictions",
    "without limitations",
    "unrestricted",
)
_OBFUSCATION_KW = (
    "base64",
    "decode this",
    "hex",
    "encode",
    "translate this encoded",
)


class EnterpriseImporter(BaseImporter):
    """Import enterprise dataset with content-based classification."""

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
                if cat in _SAMPLE_CATEGORIES:
                    by_cat.setdefault(cat, []).append(row)

        weights = {cat: math.sqrt(len(rows)) for cat, rows in by_cat.items()}
        total_weight = sum(weights.values())

        scenarios = []
        idx = 0
        random.seed(42)

        for cat, rows in sorted(by_cat.items()):
            n = max(1, round(self._budget * weights[cat] / total_weight))
            sample = random.sample(rows, min(n, len(rows)))

            for row in sample:
                s = self._convert(row, idx)
                if s:
                    scenarios.append(s)
                    idx += 1

        return scenarios[: self._budget]

    @staticmethod
    def _convert(row: dict, index: int) -> TestScenario | None:
        prompt = row.get("prompt", "").strip()
        if not prompt or len(prompt) < 10:
            return None
        if len(prompt) > 2000:
            prompt = prompt[:2000]

        source_cat = row.get("category", "UNKNOWN")
        category, subcategory = _classify_by_content(prompt)
        severity = _estimate_severity(prompt, category)
        layers = _estimate_layers(prompt, category)

        return TestScenario(
            id=f"ent_{index:05d}",
            category=category,
            subcategory=subcategory,
            language="en",
            channel=Channel.CHAT,
            user_input=prompt,
            expected_verdict=Verdict.BLOCK,
            expected_severity=severity,
            expected_triggered_layers=layers,
            tier=Tier.COVERAGE,
            source=f"enterprise/{source_cat}",
        )


def _classify_by_content(text: str) -> tuple[AttackCategory, str]:
    """Classify based on actual prompt content, not source label."""
    text_lower = text.lower()

    if any(kw in text_lower for kw in _ROLEPLAY_KW):
        return AttackCategory.SEMANTIC_EVASION, "roleplay"

    if any(kw in text_lower for kw in _EXFIL_KW):
        return AttackCategory.DATA_EXFILTRATION, "reveal_secrets"

    if any(kw in text_lower for kw in _OVERRIDE_KW):
        return AttackCategory.INSTRUCTION_OVERRIDE, "ignore_previous"

    if any(kw in text_lower for kw in _OBFUSCATION_KW):
        return AttackCategory.OBFUSCATION, "code_wrapped"

    if any(kw in text_lower for kw in ("select * from", "drop table", "; rm -", "import os")):
        return AttackCategory.TOOL_AGENT_ABUSE, "command_execution"

    return AttackCategory.INSTRUCTION_OVERRIDE, "ignore_previous"


def _estimate_severity(text: str, category: AttackCategory) -> int:
    """Estimate severity based on content aggressiveness."""
    text_lower = text.lower()

    if any(kw in text_lower for kw in ("api key", "password", "credential", "drop table")):
        return 5
    if any(kw in text_lower for kw in ("ignore all", "disregard all", "override all")):
        return 5
    if category == AttackCategory.SEMANTIC_EVASION:
        return 4
    if category == AttackCategory.OBFUSCATION:
        return 3
    return 4


def _estimate_layers(text: str, category: AttackCategory) -> list[str]:
    """Estimate which detection layers should trigger based on content."""
    text_lower = text.lower()
    layers = []

    if any(
        kw in text_lower for kw in ("ignore", "disregard", "override", "jailbreak", "system prompt")
    ):
        layers.append("heuristics")

    if category in (
        AttackCategory.SEMANTIC_EVASION,
        AttackCategory.DATA_EXFILTRATION,
        AttackCategory.CONTEXT_INCONSISTENCY,
    ):
        layers.append("semantic")

    if category in (AttackCategory.OBFUSCATION, AttackCategory.SEMANTIC_EVASION):
        layers.append("llm_guard")

    if not layers:
        layers = ["heuristics", "semantic"]

    return layers
