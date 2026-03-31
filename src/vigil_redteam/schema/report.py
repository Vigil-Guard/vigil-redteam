"""RunReport — aggregate metrics and metadata from a test run."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class MetricGroup(BaseModel):
    """Named group of metrics (security, usability, pipeline)."""

    metrics: dict[str, float | int | None] = Field(default_factory=dict)


class SliceMetrics(BaseModel):
    """Metrics broken down by a single dimension."""

    dimension: str
    slices: dict[str, MetricGroup] = Field(default_factory=dict)


class FailureCluster(BaseModel):
    """Group of related failures."""

    failure_type: str
    count: int
    example_ids: list[str] = Field(default_factory=list)
    pattern: str = ""


class RunReport(BaseModel):
    """Complete report from a test run."""

    # Metadata
    run_id: str
    timestamp: datetime
    vge_url: str
    dataset_path: str
    total_scenarios: int
    threshold: int

    # Summary
    passed: int
    failed: int
    errors: int

    # Metric groups
    security: MetricGroup = MetricGroup()
    usability: MetricGroup = MetricGroup()
    robustness: MetricGroup = MetricGroup()
    pipeline: MetricGroup = MetricGroup()

    # Context mode split (single_turn is arbiter gate, contextual is diagnostic)
    single_turn_security: MetricGroup = MetricGroup()
    single_turn_usability: MetricGroup = MetricGroup()
    contextual_security: MetricGroup = MetricGroup()
    contextual_usability: MetricGroup = MetricGroup()
    single_turn_count: int = 0
    contextual_count: int = 0

    # Breakdowns
    by_category: SliceMetrics = SliceMetrics(dimension="category")
    by_language: SliceMetrics = SliceMetrics(dimension="language")
    by_channel: SliceMetrics = SliceMetrics(dimension="channel")
    by_source: SliceMetrics = SliceMetrics(dimension="source")
    by_mutation_family: SliceMetrics = SliceMetrics(dimension="mutation_family")

    # Failure analysis
    failure_clusters: list[FailureCluster] = Field(default_factory=list)

    # Layer analysis
    layer_coverage: dict[str, int] = Field(default_factory=dict)
    first_catching_layer: dict[str, int] = Field(default_factory=dict)

    model_config = {"extra": "ignore"}
