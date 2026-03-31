"""Filter scenarios by category, channel, language, and tier."""

from __future__ import annotations

from vigil_redteam.schema.scenario import TestScenario


def filter_scenarios(
    scenarios: list[TestScenario],
    *,
    categories: list[str] | None = None,
    channels: list[str] | None = None,
    languages: list[str] | None = None,
    tiers: list[str] | None = None,
    subcategories: list[str] | None = None,
) -> list[TestScenario]:
    """Return scenarios matching all provided filters (AND logic)."""
    filtered = scenarios

    if categories:
        cat_set = set(categories)
        filtered = [s for s in filtered if s.category in cat_set]

    if channels:
        ch_set = set(channels)
        filtered = [s for s in filtered if s.channel in ch_set]

    if languages:
        lang_set = set(languages)
        filtered = [s for s in filtered if s.language in lang_set]

    if tiers:
        tier_set = set(tiers)
        filtered = [s for s in filtered if s.tier in tier_set]

    if subcategories:
        sub_set = set(subcategories)
        filtered = [s for s in filtered if s.subcategory in sub_set]

    return filtered
