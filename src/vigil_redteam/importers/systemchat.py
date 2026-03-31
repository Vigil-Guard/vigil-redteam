"""Import SystemChat — real multi-turn conversations as benign hard negatives."""

from __future__ import annotations

import json
import random
from pathlib import Path

from vigil_redteam.importers.base import BaseImporter
from vigil_redteam.schema.enums import AttackCategory, Channel, Tier, Verdict
from vigil_redteam.schema.scenario import TestScenario


class SystemChatImporter(BaseImporter):
    """Import SystemChat JSONL with sampling — multi-turn benign conversations."""

    def __init__(self, budget: int = 100, min_turns: int = 5):
        self._budget = budget
        self._min_turns = min_turns

    def import_records(self, input_path: Path) -> list[TestScenario]:
        candidates = []

        with input_path.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue

                convs = record.get("conversations", [])
                if len(convs) >= self._min_turns:
                    candidates.append(convs)

        random.seed(42)
        sample = random.sample(candidates, min(self._budget, len(candidates)))

        scenarios = []
        for idx, convs in enumerate(sample):
            scenario = self._convert(convs, idx)
            if scenario:
                scenarios.append(scenario)

        return scenarios

    @staticmethod
    def _convert(convs: list[dict], index: int) -> TestScenario | None:
        system_context = None
        turns = []

        for turn in convs:
            role = turn.get("from", "")
            text = turn.get("value", "").strip()
            if not text:
                continue

            if role == "system":
                system_context = text
            elif role == "human":
                turns.append(f"[USER] {text}")
            elif role == "gpt":
                turns.append(f"[ASSISTANT] {text}")

        if not turns:
            return None

        # Build the full conversation as user_input
        # This is what would be sent through RAG or context window
        full_conversation = "\n\n".join(turns)

        # Truncate very long conversations to 3000 chars
        if len(full_conversation) > 3000:
            full_conversation = full_conversation[:3000] + "\n[...truncated]"

        subcategory = _guess_benign_subcategory(system_context or "")

        return TestScenario(
            id=f"syschat_{index:05d}",
            category=AttackCategory.SAFE_RISKY_LOOKALIKE,
            subcategory=subcategory,
            language="en",
            channel=Channel.CHAT,
            user_input=full_conversation,
            system_context=system_context,
            expected_verdict=Verdict.ALLOW,
            expected_severity=0,
            expected_triggered_layers=[],
            tier=Tier.COVERAGE,
            source="systemchat",
            notes=f"turns={len([t for t in full_conversation.split('[USER]') if t.strip()])}",
        )


def _guess_benign_subcategory(system_context: str) -> str:
    ctx_lower = system_context.lower()
    if any(kw in ctx_lower for kw in ("code", "program", "javascript", "python", "developer")):
        return "code_resembling_attack"
    if any(kw in ctx_lower for kw in ("security", "audit", "pentest", "vulnerability")):
        return "security_testing"
    if any(kw in ctx_lower for kw in ("debug", "troubleshoot", "error", "fix")):
        return "debugging_request"
    return "benign_admin"
