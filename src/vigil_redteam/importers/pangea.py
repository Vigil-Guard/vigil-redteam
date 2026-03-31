"""Import Pangea benchmark datasets to unified JSONL format.

Pangea records have: {label: [str], messages: [{role, content}], source, lang, benchmark_group}
"""

from __future__ import annotations

import json
from pathlib import Path

from vigil_redteam.importers.base import BaseImporter
from vigil_redteam.schema.enums import AttackCategory, Channel, Tier, Verdict
from vigil_redteam.schema.scenario import TestScenario

_MALICIOUS_LABELS = frozenset(
    {
        "injection",
        "malicious",
        "malicious-prompt",
        "jailbreak",
        "harmful",
        "unsafe",
        "not conform",
        "multi-shot",
        "direct",
        "adversarial_suffix",
        "adversarial_prefix",
        "direct_auto",
    }
)

_BENIGN_LABELS = frozenset(
    {
        "benign",
        "benign_auto",
        "conform",
        "safe",
    }
)


class PangeaImporter(BaseImporter):
    """Convert Pangea JSONL to unified TestScenario format."""

    def __init__(self, projection: str = "last_user"):
        self._projection = projection

    def import_records(self, input_path: Path) -> list[TestScenario]:
        scenarios = []
        with input_path.open() as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                scenario = self._convert(record, i)
                if scenario:
                    scenarios.append(scenario)
        return scenarios

    def _convert(self, record: dict, index: int) -> TestScenario | None:
        labels = set(record.get("label", []))
        messages = record.get("messages", [])
        source = record.get("source", "pangea")
        lang = record.get("lang", "en") or "en"
        group = record.get("benchmark_group", "unknown")

        is_malicious = bool(labels & _MALICIOUS_LABELS)
        is_benign = bool(labels & _BENIGN_LABELS) or not is_malicious

        user_input = self._extract_input(messages)
        if not user_input:
            return None

        system_context = self._extract_system(messages)

        if is_malicious:
            category = self._guess_attack_category(user_input, labels)
            verdict = Verdict.BLOCK
            severity = 4
        else:
            category = AttackCategory.SAFE_RISKY_LOOKALIKE
            verdict = Verdict.ALLOW
            severity = 0

        return TestScenario(
            id=f"pangea_{index:05d}",
            category=category,
            subcategory=self._guess_subcategory(category, labels),
            language=lang,
            channel=Channel.CHAT,
            user_input=user_input,
            system_context=system_context,
            expected_verdict=verdict,
            expected_severity=severity,
            expected_triggered_layers=[],
            tier=Tier.COVERAGE,
            source=f"pangea/{source}",
            notes=f"group={group} labels={','.join(sorted(labels))}",
        )

    def _extract_input(self, messages: list[dict]) -> str:
        if self._projection == "last_user":
            for msg in reversed(messages):
                if msg.get("role") == "user":
                    return msg["content"]
            return messages[-1]["content"] if messages else ""

        parts = []
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if role == "system":
                parts.append(f"[SYSTEM] {content}")
            else:
                parts.append(content)
        return "\n".join(parts)

    @staticmethod
    def _extract_system(messages: list[dict]) -> str | None:
        for msg in messages:
            if msg.get("role") == "system":
                return msg["content"]
        return None

    @staticmethod
    def _guess_attack_category(text: str, labels: set[str]) -> AttackCategory:
        text_lower = text.lower()
        if any(kw in text_lower for kw in ("ignore", "zignoruj", "disregard", "override")):
            return AttackCategory.INSTRUCTION_OVERRIDE
        if any(kw in text_lower for kw in ("reveal", "secret", "api key", "password", "dump")):
            return AttackCategory.DATA_EXFILTRATION
        if "jailbreak" in labels or "roleplay" in text_lower or "dan" in text_lower:
            return AttackCategory.SEMANTIC_EVASION
        return AttackCategory.INSTRUCTION_OVERRIDE

    @staticmethod
    def _guess_subcategory(category: AttackCategory, labels: set[str]) -> str:
        if category == AttackCategory.SAFE_RISKY_LOOKALIKE:
            return "benign_admin"
        if category == AttackCategory.INSTRUCTION_OVERRIDE:
            return "ignore_previous"
        if category == AttackCategory.DATA_EXFILTRATION:
            return "reveal_secrets"
        if category == AttackCategory.SEMANTIC_EVASION:
            return "roleplay"
        return "unknown"
