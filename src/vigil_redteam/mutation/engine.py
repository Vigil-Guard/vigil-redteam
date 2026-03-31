"""Mutation engine — generate adversarial variants from base scenarios."""

from __future__ import annotations

import json
from pathlib import Path

from vigil_redteam.mutation.registry import Mutator, get_mutator, list_mutators
from vigil_redteam.schema.enums import Tier
from vigil_redteam.schema.scenario import TestScenario


class MutationEngine:
    """Apply mutators to scenarios and produce variant datasets.

    Supports two modes:
    - independent: each mutator applied separately (N variants per mutator)
    - chain: mutators composed sequentially (1 variant per chain)
    """

    def __init__(self, mutator_names: list[str] | None = None):
        if mutator_names:
            self._mutators = {name: get_mutator(name) for name in mutator_names}
        else:
            self._mutators = {name: get_mutator(name) for name in list_mutators()}

    def mutate_independent(self, scenario: TestScenario) -> list[TestScenario]:
        """Apply each mutator independently, yielding one variant per mutator."""
        variants = []
        for name, mutator in self._mutators.items():
            variant = self._apply(scenario, name, mutator)
            variants.append(variant)
        return variants

    def mutate_chain(self, scenario: TestScenario, chain: list[str]) -> TestScenario:
        """Apply mutators in sequence, returning a single chained variant."""
        text = scenario.user_input
        for name in chain:
            mutator = get_mutator(name)
            text = mutator(text)

        chain_name = "+".join(chain)
        return self._build_variant(scenario, text, chain_name)

    def mutate_batch(
        self,
        scenarios: list[TestScenario],
        *,
        mode: str = "independent",
        chain: list[str] | None = None,
    ) -> list[TestScenario]:
        """Generate mutations for a list of scenarios."""
        all_variants: list[TestScenario] = []

        for scenario in scenarios:
            if mode == "independent":
                all_variants.extend(self.mutate_independent(scenario))
            elif mode == "chain" and chain:
                all_variants.append(self.mutate_chain(scenario, chain))

        return all_variants

    def write_mutations(self, variants: list[TestScenario], output_path: Path) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w") as f:
            for v in variants:
                f.write(json.dumps(v.model_dump(mode="json"), ensure_ascii=False) + "\n")

    @staticmethod
    def _apply(scenario: TestScenario, mutator_name: str, mutator: Mutator) -> TestScenario:
        mutated_text = mutator(scenario.user_input)
        return MutationEngine._build_variant(scenario, mutated_text, mutator_name)

    @staticmethod
    def _build_variant(
        scenario: TestScenario, mutated_text: str, mutation_name: str
    ) -> TestScenario:
        data = scenario.model_dump()
        data["user_input"] = mutated_text
        data["mutation_family"] = mutation_name
        data["tier"] = Tier.MUTATION
        data["id"] = f"{scenario.id}_mut_{mutation_name.replace('+', '_')}"
        data["source"] = f"mutation/{mutation_name}({scenario.source})"
        return TestScenario.model_validate(data)
