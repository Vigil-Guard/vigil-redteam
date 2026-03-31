"""Base importer interface."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path

from vigil_redteam.schema.scenario import TestScenario


class BaseImporter(ABC):
    """Convert an external dataset format to unified TestScenario JSONL."""

    @abstractmethod
    def import_records(self, input_path: Path) -> list[TestScenario]: ...

    def write_jsonl(self, scenarios: list[TestScenario], output_path: Path) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w") as f:
            for s in scenarios:
                f.write(json.dumps(s.model_dump(mode="json"), ensure_ascii=False) + "\n")
