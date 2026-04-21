"""TestScenario — the core JSONL record for adversarial test cases."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from vigil_redteam.schema.enums import AttackCategory, Channel, ContextMode, Tier, Verdict


class ToolResultContext(BaseModel):
    """Tool execution result context."""

    content: Any
    is_error: bool | None = Field(None, alias="isError")
    duration_ms: int | None = Field(None, alias="durationMs")

    model_config = {"extra": "ignore", "populate_by_name": True}


class ToolContext(BaseModel):
    """Tool invocation context for VGE API."""

    name: str = Field(min_length=1, max_length=128)
    id: str | None = Field(None, max_length=128)
    vendor: str | None = None
    args: Any | None = None
    result: ToolResultContext | None = None

    model_config = {"extra": "ignore"}


class TestScenario(BaseModel):
    """A single adversarial test case.

    Only `user_input` is sent to VGE API as the `prompt` field.
    All other fields are metadata for filtering, grouping, and reporting.

    context_mode:
      - single_turn: verdict is determinable from user_input alone.
        These scenarios are valid for arbiter calibration.
      - contextual: verdict depends on system_context, external_context,
        or conversation state that VGE API cannot receive.
        These scenarios are diagnostic only — not valid as arbiter gate.
    """

    id: str
    category: AttackCategory
    subcategory: str
    language: str = Field(description="ISO 639-1 code: pl, en, mixed")
    channel: Channel
    user_input: str = Field(min_length=1)
    external_context: str | None = None
    system_context: str | None = None
    context_mode: ContextMode = ContextMode.SINGLE_TURN
    expected_verdict: Verdict
    expected_severity: int = Field(ge=0, le=5)
    expected_triggered_layers: list[str] = Field(default_factory=list)
    mutation_family: str | None = None
    tier: Tier
    source: str
    notes: str = ""
    metadata: dict[str, str | int | float | bool] | None = Field(
        default=None,
        description=(
            "Optional API metadata envelope sent as POST /v1/guard/input `metadata`. "
            "Experimental; used for manual validation of agent context logging (PRD_28)."
        ),
    )
    tool: ToolContext | None = Field(
        default=None,
        description="Optional tool invocation context forwarded to VGE API.",
    )

    model_config = {"extra": "ignore"}


def load_scenarios(path: Path) -> list[TestScenario]:
    """Load TestScenario records from a JSONL file."""
    scenarios = []
    with path.open() as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                scenarios.append(TestScenario.model_validate(data))
            except Exception as e:
                raise ValueError(f"{path}:{line_num}: {e}") from e
    return scenarios


def load_scenarios_from_dir(directory: Path) -> list[TestScenario]:
    """Load all JSONL files from a directory."""
    scenarios = []
    for jsonl_file in sorted(directory.glob("*.jsonl")):
        scenarios.extend(load_scenarios(jsonl_file))
    return scenarios


def validate_dataset(path: Path) -> list[str]:
    """Validate a JSONL file and return list of errors (empty = valid)."""
    errors = []
    with path.open() as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                TestScenario.model_validate(data)
            except json.JSONDecodeError as e:
                errors.append(f"{path}:{line_num}: invalid JSON: {e}")
            except Exception as e:
                errors.append(f"{path}:{line_num}: {e}")
    return errors
