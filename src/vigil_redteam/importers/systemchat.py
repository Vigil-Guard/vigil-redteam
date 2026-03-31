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
                if len(convs) >= self._min_turns and _is_realistic(convs):
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


_DEGENERATE_PATTERNS = (
    "always refuse",
    "always respond with",
    "only respond with",
    "respond only with the word",
    "never provide",
    "you must always say",
    "sexual",
    "erotic",
    "nsfw",
    "dominatrix",
    "seductive",
    "flirtatious",
    "ideolog",
    "marxist",
    "fascist",
    "supremacist",
)


def _is_realistic(convs: list[dict]) -> bool:
    """Filter out degenerate, unrealistic, or inappropriate conversations."""
    for turn in convs:
        if turn.get("from") != "system":
            continue
        sys_text = turn.get("value", "").lower()
        if any(pat in sys_text for pat in _DEGENERATE_PATTERNS):
            return False
        # Very short system prompts are usually degenerate
        if len(sys_text.strip()) < 20:
            return False
    return True


def _guess_benign_subcategory(system_context: str) -> str:
    ctx_lower = system_context.lower()
    if any(kw in ctx_lower for kw in ("code", "program", "javascript", "python", "developer")):
        return "code_resembling_attack"
    if any(kw in ctx_lower for kw in ("security", "audit", "pentest", "vulnerability")):
        return "security_testing"
    if any(kw in ctx_lower for kw in ("debug", "troubleshoot", "error", "fix")):
        return "debugging_request"
    return "benign_admin"
