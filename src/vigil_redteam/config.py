"""Configuration loader — TOML file + environment variable overrides."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # type: ignore[no-redef]


@dataclass
class ApiConfig:
    base_url: str = "https://api.vigilguard"
    api_key: str = ""
    verify_tls: bool = False
    timeout: int = 30


@dataclass
class RunnerConfig:
    concurrency: int = 8
    rps: float = 10.0
    retries: int = 2
    threshold: int = 40


@dataclass
class DatasetConfig:
    golden_dir: str = "datasets/golden"
    coverage_dir: str = "datasets/coverage"
    mutation_dir: str = "datasets/mutation"


@dataclass
class ReportingConfig:
    results_dir: str = "results"
    reports_dir: str = "reports"


@dataclass
class Config:
    api: ApiConfig = field(default_factory=ApiConfig)
    runner: RunnerConfig = field(default_factory=RunnerConfig)
    datasets: DatasetConfig = field(default_factory=DatasetConfig)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)


def load_config(config_path: Path | None = None) -> Config:
    """Load configuration from TOML file with env var overrides.

    Env overrides:
        VGE_API_URL -> api.base_url
        VGE_API_KEY -> api.api_key (required for runs)
        VIGIL_SKIP_TLS_VERIFY=1 -> api.verify_tls = False
    """
    cfg = Config()

    toml_path = config_path or _find_config()
    if toml_path and toml_path.exists():
        with toml_path.open("rb") as f:
            data = tomllib.load(f)
        _apply_toml(cfg, data)

    _apply_env(cfg)
    return cfg


def _find_config() -> Path | None:
    for name in ("redteam.toml", "redteam.toml.example"):
        p = Path(name)
        if p.exists():
            return p
    return None


def _apply_toml(cfg: Config, data: dict) -> None:
    if "api" in data:
        api = data["api"]
        if "base_url" in api:
            cfg.api.base_url = api["base_url"]
        if "verify_tls" in api:
            cfg.api.verify_tls = api["verify_tls"]
        if "timeout" in api:
            cfg.api.timeout = api["timeout"]

    if "runner" in data:
        runner = data["runner"]
        if "concurrency" in runner:
            cfg.runner.concurrency = runner["concurrency"]
        if "rps" in runner:
            cfg.runner.rps = runner["rps"]
        if "retries" in runner:
            cfg.runner.retries = runner["retries"]
        if "threshold" in runner:
            cfg.runner.threshold = runner["threshold"]

    if "datasets" in data:
        ds = data["datasets"]
        if "golden_dir" in ds:
            cfg.datasets.golden_dir = ds["golden_dir"]
        if "coverage_dir" in ds:
            cfg.datasets.coverage_dir = ds["coverage_dir"]
        if "mutation_dir" in ds:
            cfg.datasets.mutation_dir = ds["mutation_dir"]

    if "reporting" in data:
        rpt = data["reporting"]
        if "results_dir" in rpt:
            cfg.reporting.results_dir = rpt["results_dir"]
        if "reports_dir" in rpt:
            cfg.reporting.reports_dir = rpt["reports_dir"]


def _apply_env(cfg: Config) -> None:
    if url := os.environ.get("VGE_API_URL"):
        cfg.api.base_url = url
    if key := os.environ.get("VGE_API_KEY"):
        cfg.api.api_key = key
    if os.environ.get("VIGIL_SKIP_TLS_VERIFY") == "1":
        cfg.api.verify_tls = False


def require_api_key(cfg: Config) -> None:
    """Exit with error if API key is not configured."""
    if not cfg.api.api_key:
        print("Error: VGE_API_KEY environment variable is required.", file=sys.stderr)
        sys.exit(1)
