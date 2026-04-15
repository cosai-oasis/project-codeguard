"""
Configuration for the CodeGuard benchmarking system.

Loads API credentials from .env (OPENAI_API_KEY, OPENAI_BASE_URL only).
All other config comes from the YAML scenarios file.
CLI arguments can override YAML values.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import yaml
from dotenv import load_dotenv

import httpx

from benchmarks.models import BenchmarkConfig, BenchmarkFile, ModelPricing, Scenario

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BENCHMARKS_DIR = Path(__file__).resolve().parent
SKILLS_DIR = PROJECT_ROOT / "skills" / "secure-coding"
SCENARIOS_DIR = BENCHMARKS_DIR / "scenarios"
RESULTS_DIR = BENCHMARKS_DIR / "results"
DOCKER_DIR = BENCHMARKS_DIR / "docker"


@dataclass(frozen=True)
class Credentials:
    openai_api_key: str
    openai_base_url: str


def load_credentials() -> Credentials:
    """Load API credentials from .env at project root."""
    load_dotenv(PROJECT_ROOT / ".env")
    api_key = os.environ.get("OPENAI_API_KEY", "")
    base_url = os.environ.get("OPENAI_BASE_URL", "https://openrouter.ai/api/v1")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY not set in .env or environment")
    return Credentials(openai_api_key=api_key, openai_base_url=base_url)


def load_benchmark(
    yaml_path: Path,
    cli_overrides: dict | None = None,
) -> tuple[BenchmarkConfig, dict[str, Scenario]]:
    """
    Parse the YAML benchmark file and apply CLI overrides.

    Returns (config, scenarios_dict) where scenarios_dict is keyed by scenario id.
    """
    raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    benchmark_file = BenchmarkFile.model_validate(raw)

    config = benchmark_file.config
    if cli_overrides:
        update = {}
        if "runs_per_scenario" in cli_overrides:
            update["runs_per_scenario"] = cli_overrides["runs_per_scenario"]
        if "max_parallel" in cli_overrides:
            update["max_parallel"] = cli_overrides["max_parallel"]
        if "timeout_seconds" in cli_overrides:
            update["timeout_seconds"] = cli_overrides["timeout_seconds"]
        if "agent_model" in cli_overrides:
            update["agent_model"] = cli_overrides["agent_model"]
        if "judge_model" in cli_overrides:
            update["judge_model"] = cli_overrides["judge_model"]
        if update:
            config = config.model_copy(update=update)

    scenarios = {s.id: s for s in benchmark_file.scenarios}
    return config, scenarios


def fetch_model_pricing(
    model_id: str,
    creds: Credentials,
) -> ModelPricing:
    """Fetch per-token pricing for a model from OpenRouter API.

    model_id can be in opencode format ("openrouter/qwen/qwen3.6-plus")
    or plain OpenRouter format ("qwen/qwen3.6-plus").
    """
    # Strip "openrouter/" prefix if present — OpenRouter API uses bare IDs
    api_id = model_id.removeprefix("openrouter/")

    try:
        resp = httpx.get(
            f"{creds.openai_base_url}/models",
            headers={"Authorization": f"Bearer {creds.openai_api_key}"},
            timeout=15.0,
        )
        resp.raise_for_status()
        for m in resp.json().get("data", []):
            if m.get("id") == api_id:
                p = m.get("pricing", {})
                return ModelPricing(
                    prompt=float(p.get("prompt", 0)),
                    completion=float(p.get("completion", 0)),
                )
    except Exception:
        pass
    return ModelPricing()
