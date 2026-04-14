"""
Data models for the CodeGuard benchmarking system.

Pydantic models for scenario definitions, execution results,
judge verdicts, and aggregated reports.
"""

from __future__ import annotations

import enum
from datetime import datetime
from pydantic import BaseModel, Field


class VulnerabilityCategory(str, enum.Enum):
    SQL_INJECTION = "sql-injection"
    XXE = "xxe"
    XPATH_INJECTION = "xpath-injection"
    XSS = "xss"
    CSRF = "csrf"
    ORM_INJECTION = "orm-injection"
    SESSION_MANAGEMENT = "session-management"
    ACCESS_CONTROL = "access-control"
    FILE_HANDLING = "file-handling"
    HARDCODED_CREDENTIALS = "hardcoded-credentials"
    CRYPTOGRAPHY = "cryptography"
    COMMAND_INJECTION = "command-injection"


class RunMode(str, enum.Enum):
    WITH_SKILLS = "with_skills"
    WITHOUT_SKILLS = "without_skills"


# --- YAML config models ---


class JudgeConfig(BaseModel):
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    max_concurrent: int = Field(default=5, ge=1)
    timeout_seconds: int = Field(default=120, ge=10)


class BenchmarkConfig(BaseModel):
    agent_model: str = "qwen/qwen3-coder-next"
    judge_model: str = "openai/gpt-5.4-medium"
    max_parallel: int = Field(default=10, ge=1)
    timeout_seconds: int = Field(default=600, ge=30)
    runs_per_scenario: int = Field(default=3, ge=1)
    judge: JudgeConfig = Field(default_factory=JudgeConfig)


class Scenario(BaseModel):
    id: str
    name: str
    repo_url: str
    repo_ref: str = "master"
    language: str = "java"
    context_files: list[str] = Field(
        default_factory=list,
        description="Files the agent will likely touch or that give context for the task",
    )
    security_category: VulnerabilityCategory = Field(
        description="What category of vulnerability may appear if the agent writes insecure code",
    )
    codeguard_rules: list[str]
    prompt: str = Field(description="Realistic coding task — what a developer would ask the agent")
    security_concerns: list[str] = Field(
        description="What the judge should check: secure patterns the code should follow",
    )
    timeout_seconds: int | None = Field(
        default=None,
        description="Per-scenario timeout override; falls back to config.timeout_seconds",
    )


class BenchmarkFile(BaseModel):
    """Top-level YAML file: config + scenarios."""

    config: BenchmarkConfig = Field(default_factory=BenchmarkConfig)
    scenarios: list[Scenario]


# --- Token usage tracking ---


class TokenUsage(BaseModel):
    """Token counts from a single LLM API call."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


# --- Runtime result models ---


class ContainerResult(BaseModel):
    scenario_id: str
    run_mode: RunMode
    run_index: int
    diff: str = ""
    agent_log: str = ""
    agent_trace: list = Field(default_factory=list, description="Full JSON event trace from opencode")
    exit_code: int = -1
    timed_out: bool = False
    duration_seconds: float = 0.0
    container_id: str = ""
    error: str = ""
    agent_usage: TokenUsage = Field(default_factory=TokenUsage)


class JudgeVerdict(BaseModel):
    scenario_id: str
    run_mode: RunMode
    run_index: int
    secure_implementation: bool = Field(
        description="Whether the new code is free of vulnerabilities in the relevant category",
    )
    security_score: int = Field(
        ge=0, le=10,
        description="CVSS-based: 0=no vulns (ideal), 1-3=low, 4-6=medium, 7-8=high, 9-10=critical",
    )
    vulnerabilities_found: list[str] = Field(
        default_factory=list,
        description="Specific vulnerabilities found in the new code",
    )
    secure_patterns_applied: list[str] = Field(
        default_factory=list,
        description="Which of the security_concerns were properly addressed",
    )
    explanation: str
    judge_usage: TokenUsage = Field(default_factory=TokenUsage)


# --- Aggregated report models ---


class ScenarioReport(BaseModel):
    scenario_id: str
    scenario_name: str
    security_category: str
    with_skills: list[JudgeVerdict]
    without_skills: list[JudgeVerdict]
    avg_score_with: float
    avg_score_without: float
    delta: float
    secure_rate_with: float
    secure_rate_without: float


class UsageSummary(BaseModel):
    """Aggregate token usage across all API calls."""

    agent_prompt_tokens: int = 0
    agent_completion_tokens: int = 0
    agent_total_tokens: int = 0
    judge_prompt_tokens: int = 0
    judge_completion_tokens: int = 0
    judge_total_tokens: int = 0
    total_tokens: int = 0


class BenchmarkSummary(BaseModel):
    timestamp: datetime
    model: str
    judge_model: str
    total_scenarios: int
    runs_per_scenario: int
    scenario_reports: list[ScenarioReport]
    overall_avg_with: float
    overall_avg_without: float
    overall_delta: float
    overall_secure_rate_with: float
    overall_secure_rate_without: float
    by_category: dict[str, dict[str, float]]
    usage: UsageSummary = Field(default_factory=UsageSummary)
