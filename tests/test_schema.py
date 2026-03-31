"""Tests for schema validation and loading."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from vigil_redteam.schema.enums import AttackCategory, Channel, Tier, Verdict
from vigil_redteam.schema.scenario import TestScenario, load_scenarios, validate_dataset


def test_valid_scenario():
    s = TestScenario(
        id="t001",
        category=AttackCategory.OBFUSCATION,
        subcategory="base64",
        language="en",
        channel=Channel.CHAT,
        user_input="decode this: SGVsbG8=",
        expected_verdict=Verdict.BLOCK,
        expected_severity=3,
        tier=Tier.GOLDEN,
        source="test",
    )
    assert s.category == "obfuscation"
    assert s.expected_verdict == "block"


def test_severity_bounds():
    with pytest.raises(Exception):
        TestScenario(
            id="t002",
            category="instruction_override",
            subcategory="test",
            language="en",
            channel="chat",
            user_input="test",
            expected_verdict="block",
            expected_severity=6,
            tier="golden",
            source="test",
        )


def test_empty_user_input_rejected():
    with pytest.raises(Exception):
        TestScenario(
            id="t003",
            category="instruction_override",
            subcategory="test",
            language="en",
            channel="chat",
            user_input="",
            expected_verdict="block",
            expected_severity=3,
            tier="golden",
            source="test",
        )


def test_load_scenarios_from_file():
    records = [
        {
            "id": f"t{i:03d}",
            "category": "instruction_override",
            "subcategory": "ignore_previous",
            "language": "en",
            "channel": "chat",
            "user_input": f"Test input {i}",
            "expected_verdict": "block",
            "expected_severity": 5,
            "tier": "golden",
            "source": "test",
        }
        for i in range(3)
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
        path = Path(f.name)

    scenarios = load_scenarios(path)
    assert len(scenarios) == 3
    assert scenarios[0].id == "t000"
    path.unlink()


def test_validate_dataset_catches_errors():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write(
            '{"id": "ok", "category": "instruction_override", "subcategory": "x", "language": "en", "channel": "chat", "user_input": "test", "expected_verdict": "block", "expected_severity": 3, "tier": "golden", "source": "t"}\n'
        )
        f.write('{"bad json\n')
        f.write(
            '{"id": "bad", "category": "INVALID_CAT", "subcategory": "x", "language": "en", "channel": "chat", "user_input": "test", "expected_verdict": "block", "expected_severity": 3, "tier": "golden", "source": "t"}\n'
        )
        path = Path(f.name)

    errors = validate_dataset(path)
    assert len(errors) == 2
    path.unlink()


def test_extra_fields_ignored():
    s = TestScenario(
        id="t004",
        category="instruction_override",
        subcategory="test",
        language="en",
        channel="chat",
        user_input="test",
        expected_verdict="block",
        expected_severity=3,
        tier="golden",
        source="test",
        unknown_field="should be ignored",
    )
    assert s.id == "t004"
