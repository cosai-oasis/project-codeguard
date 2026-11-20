"""Run selected skill experiments individually or as a resumable matrix."""

import argparse
import json
import math
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Literal

from inspect_ai import Task, eval_set, task
from inspect_ai.model import GenerateConfig, ModelCost
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError, field_validator
import yaml

from codeguard_evals.cyberseceval.cyberseceval import build_task as cyberseceval_task
from codeguard_evals.harness import TURN_LIMIT
from codeguard_evals.protocol import Condition
from codeguard_evals.safe_io import load_strict_json, read_bounded
from codeguard_evals.securityeval.securityeval import build_task as securityeval_task
from codeguard_evals.skill_catalog import load_skill_catalog, load_skill_variant

BENCHMARKS = ("securityeval", "cyberseceval")
AGENTS = ("codex-cli",)
MAX_MATRIX_BYTES = 256 * 1024


def _build(
    benchmark: str, condition: Condition, variant: str | None, languages: str | list[str], agent_turn_limit: int,
) -> Task:
    if benchmark == "cyberseceval":
        return cyberseceval_task(condition, languages=languages, agent_turn_limit=agent_turn_limit,
                                skill_variant=variant)
    if benchmark == "securityeval":
        if languages:
            raise ValueError("SecurityEval does not support a language filter")
        return securityeval_task(condition, agent_turn_limit=agent_turn_limit, skill_variant=variant)
    raise ValueError("Select securityeval or cyberseceval")


@task
def baseline(benchmark: str, languages: str | list[str] = "", agent_turn_limit: int = TURN_LIMIT) -> Task:
    """Run the same benchmark prompts without a skill."""
    return _build(benchmark, "baseline", None, languages, agent_turn_limit)


@task
def secure_prompt(benchmark: str, languages: str | list[str] = "", agent_turn_limit: int = TURN_LIMIT) -> Task:
    """Add the plain security reminder to the benchmark prompts, without a skill."""
    return _build(benchmark, "secure_prompt", None, languages, agent_turn_limit)


@task
def skill(benchmark: str, variant: str, languages: str | list[str] = "", agent_turn_limit: int = TURN_LIMIT) -> Task:
    """Make exactly one pinned skill variant available for natural discovery."""
    return _build(benchmark, "skill", variant, languages, agent_turn_limit)


class _Settings(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    models: list[str] = Field(min_length=1)
    agents: list[str] | Literal["all"] = Field(default_factory=lambda: ["codex-cli"])
    skills: list[str] | Literal["all"] = Field(default_factory=list)
    baseline: bool = False
    secure_prompt: bool = False
    epochs: int = Field(default=1, gt=0)
    reasoning_effort: str = "medium"
    agent_turn_limit: int = Field(default=TURN_LIMIT, gt=0)
    limit: int | None = Field(default=None, gt=0)
    languages: list[str] | None = None

    @field_validator("models", "agents", "skills", "languages")
    @classmethod
    def distinct_names(cls, values):
        if isinstance(values, list) and (
            any(not value or value != value.strip() for value in values)
            or len(set(values)) != len(values)
        ):
            raise ValueError("Use distinct, nonempty names without surrounding spaces")
        return values

    @field_validator("reasoning_effort")
    @classmethod
    def native_effort(cls, value):
        return GenerateConfig(reasoning_effort=value).reasoning_effort


# Validating all benchmarks at once names the benchmark in each error location.
_BENCHMARK_SETTINGS = TypeAdapter(dict[str, _Settings])


class _Execution(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    max_tasks: int = Field(default=1, gt=0)
    max_samples: int = Field(default=4, gt=0)
    max_sandboxes: int = Field(default=4, gt=0)
    max_connections: int = Field(default=4, gt=0)
    retry_attempts: int = Field(default=1, ge=0)
    max_retries: int = Field(default=2, ge=0)
    display: Literal["plain", "full", "none"] = "plain"
    model_cost_config: str | None = None


class _Matrix(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    defaults: dict = Field(default_factory=dict)
    benchmarks: dict[str, dict] | Literal["all"]
    execution: _Execution = Field(default_factory=_Execution)


def _read_json(path: Path):
    return load_strict_json(read_bounded(path, MAX_MATRIX_BYTES, label="Experiment matrix"))


def _resolve_execution(config: _Execution, matrix_path: Path) -> dict:
    execution = config.model_dump(exclude_none=True)
    if config.model_cost_config is not None:
        path = matrix_path.parent / config.model_cost_config
        raw = read_bounded(path, MAX_MATRIX_BYTES, label="Model prices")
        try:
            data = load_strict_json(raw) if path.suffix.lower() == ".json" else yaml.safe_load(raw)
        except yaml.YAMLError:
            raise ValueError("Model prices must be valid JSON or YAML") from None
        prices = TypeAdapter(dict[str, ModelCost]).validate_python(data, strict=True)
        rates = {name: cost.model_dump() for name, cost in prices.items()}
        if any(not math.isfinite(rate) or rate < 0 for cost in rates.values() for rate in cost.values()):
            raise ValueError("Model prices must be finite, nonnegative USD rates")
        execution["model_cost_config"] = rates
    return execution


def _select(requested, available, previous=None) -> list[str]:
    selected = requested
    if requested == "all":
        selected = previous if previous is not None else sorted(available)
    if (
        not isinstance(selected, list)
        or any(not isinstance(item, str) for item in selected)
        or len(set(selected)) != len(selected)
        or any(item not in available for item in selected)
    ):
        raise ValueError(f"Select distinct supported names from: {', '.join(sorted(available))}")
    return selected


def _validate_saved_selection(previous) -> None:
    invalid = ValueError("The saved matrix is invalid; use a new run directory")
    if (
        not isinstance(previous, dict) or set(previous) != {"benchmarks", "skills", "execution"}
        or not isinstance(previous["benchmarks"], dict) or not previous["benchmarks"]
        or any(name not in BENCHMARKS for name in previous["benchmarks"])
        or not isinstance(previous["skills"], dict) or not isinstance(previous["execution"], dict)
    ):
        raise invalid
    # Scan-only trusts these settings, so require exactly what _resolve_matrix saves.
    try:
        saved = _BENCHMARK_SETTINGS.validate_python(previous["benchmarks"])
    except ValidationError:
        raise invalid from None
    if any(
        settings.model_dump() != previous["benchmarks"][name] or "all" in (settings.agents, settings.skills)
        for name, settings in saved.items()
    ):
        raise invalid


def _resolve_matrix(config: _Matrix, previous: dict | None) -> dict:
    old = previous["benchmarks"] if previous is not None else {}
    requested = config.benchmarks
    if requested == "all":
        names = _select("all", BENCHMARKS, list(old) if previous is not None else None)
    else:
        names = _select(list(requested), BENCHMARKS)
    if not names:
        raise ValueError("Select at least one benchmark")
    effective = _BENCHMARK_SETTINGS.validate_python({
        name: config.defaults | ({} if requested == "all" else requested[name]) for name in names
    })
    catalog = load_skill_catalog()
    resolved = {"benchmarks": {}, "skills": {}}
    for name, parsed in effective.items():
        settings = parsed.model_dump()
        original = old.get(name, {})
        settings["agents"] = _select(settings["agents"], AGENTS, original.get("agents"))
        settings["skills"] = _select(settings["skills"], catalog, original.get("skills"))
        if not settings["agents"] or not (settings["skills"] or settings["baseline"] or settings["secure_prompt"]):
            raise ValueError("Select an agent and at least one skill, the baseline or the secure prompt")
        for variant in settings["skills"]:
            if variant not in resolved["skills"]:
                _, identity = load_skill_variant(variant)
                resolved["skills"][variant] = identity.model_dump()
        resolved["benchmarks"][name] = settings
    return resolved


def _matrix_tasks(resolved: dict) -> dict[str, list[Task]]:
    groups = {}
    for name, settings in resolved["benchmarks"].items():
        options = dict(languages=settings["languages"] if settings["languages"] is not None else "",
                       agent_turn_limit=settings["agent_turn_limit"])
        tasks = [baseline(name, **options)] if settings["baseline"] else []
        if settings["secure_prompt"]:
            tasks.append(secure_prompt(name, **options))
        for variant in settings["skills"]:
            selected = skill(name, variant, **options)
            if selected.metadata["skill"] != resolved["skills"][variant]:
                raise ValueError("A selected skill changed while preparing the experiment")
            tasks.append(selected)
        groups[name] = tasks
    return groups


def _variant(metadata: dict) -> str | None:
    """Name a run by its skill ID, or by its no-skill condition."""
    return (metadata.get("skill") or {}).get("id", metadata.get("condition"))


def _expected_runs(settings: dict) -> set[tuple[str, str]]:
    variants = [name for name in ("baseline", "secure_prompt") if settings[name]] + settings["skills"]
    return {(model, variant) for model in settings["models"] for variant in variants}


def _preview(resolved: dict, groups: dict[str, list[Task]]) -> None:
    evaluations = attempts = 0
    for name, tasks in groups.items():
        settings = resolved["benchmarks"][name]
        for model in settings["models"]:
            for selected in tasks:
                variant = _variant(selected.metadata)
                count = len(selected.dataset)
                if settings["limit"] is not None:
                    count = min(count, settings["limit"])
                count *= settings["epochs"]
                print(f"{name} | {model} | {selected.metadata['agent']} | {variant} | {count} samples")
                evaluations += 1
                attempts += count
    print(f"{evaluations} evaluations; {attempts} sample attempts before retries.")


def _require_run_directory(directory: Path) -> None:
    """Apply execution's rules to an existing run directory without creating one."""
    try:
        details = directory.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(details.st_mode):
        raise ValueError(f"--log-dir must be a directory, not a file or link: {directory}")
    if stat.S_IMODE(details.st_mode) != 0o700:
        raise ValueError(f"--log-dir must be private; run chmod 700 on it or use a new directory: {directory}")
    receipt = directory / "resolved.json"
    if not (receipt.exists() or receipt.is_symlink()) and any(directory.iterdir()):
        raise ValueError(f"--log-dir must be empty or resume a run containing resolved.json: {directory}")


def _save_selection(directory: Path, resolved: dict) -> None:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    _require_run_directory(directory)
    destination = directory / "resolved.json"
    if destination.exists() or destination.is_symlink():
        if _read_json(destination) != resolved:
            raise ValueError("The saved matrix changed; use a new run directory")
        return
    raw = (json.dumps(resolved, indent=2) + "\n").encode()
    if len(raw) > MAX_MATRIX_BYTES:
        raise ValueError("The resolved experiment matrix is too large")
    with tempfile.TemporaryDirectory(dir=directory, prefix=".matrix-") as temporary:
        staged = Path(temporary) / "resolved.json"
        with staged.open("wb") as output:
            staged.chmod(0o600)
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.link(staged, destination)


def _scan(benchmarks: dict[str, dict], directory: Path, *, dry_run: bool = False) -> int:
    # Reuse the scan CLI's log selection, validation and container lifecycle.
    from inspect_ai.log import read_eval_log
    from codeguard_evals.scan import latest_generation_logs, main as scan_main

    status = 0
    for name, settings in benchmarks.items():
        source = directory / "generation" / name
        destination = directory / "scored" / name
        # Report each benchmark, as the scan does, rather than stopping at the first gap.
        try:
            logs = latest_generation_logs(source)
        except (OSError, ValueError) as error:
            print(f"{name}: {error}", file=sys.stderr)
            status = 1
            continue
        # Inspect writes a log only once its task starts, so check the saved selection is complete.
        headers = (read_eval_log(str(log), header_only=True).eval for log in logs)
        found = {(header.model, _variant(header.metadata or {})) for header in headers}
        missing = sorted(_expected_runs(settings) - found)
        if missing:
            listed = ", ".join(f"{model} {variant}" for model, variant in missing)
            print(f"{name}: missing generation logs for {listed}; rerun generation to resume.", file=sys.stderr)
            status = 1
        elif dry_run:
            print(f"{name}: {len(logs)} saved logs -> {destination}")
        else:
            status |= scan_main([str(source), "--output-dir", str(destination)])
    return status


def _execute(resolved: dict, groups: dict[str, list[Task]], directory: Path, *, scan: bool = True) -> int:
    execution = dict(resolved["execution"])
    if "model_cost_config" in execution:
        execution["model_cost_config"] = {
            name: ModelCost.model_validate(rates, strict=True)
            for name, rates in execution["model_cost_config"].items()
        }
    completed = []
    status = 0
    for name, tasks in groups.items():
        settings = resolved["benchmarks"][name]
        success, _ = eval_set(
            tasks, model=settings["models"], log_dir=str(directory / "generation" / name),
            epochs=settings["epochs"], reasoning_effort=settings["reasoning_effort"],
            limit=settings["limit"],
            # Inspect warns when immediate retry is enabled with no retry attempts.
            retry_immediate=execution["retry_attempts"] > 0,
            **execution,
        )
        if success:
            completed.append(name)
        else:
            print(f"{name}: generation is incomplete; rerun the same matrix command to resume.", file=sys.stderr)
            status = 1
    if scan and completed:
        status |= _scan({name: resolved["benchmarks"][name] for name in completed}, directory)
    print("Experiment matrix finished." if status == 0 else "Experiment matrix has unfinished generation or scans.")
    return status


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", type=Path, help="JSON selections and settings for generation and all stages")
    parser.add_argument("--log-dir", type=Path, required=True, help="Dedicated directory for this matrix")
    parser.add_argument("--stage", choices=("generation", "scan", "all"), default="all",
                        help="Generate, scan saved outputs, or both (default: all)")
    parser.add_argument("--dry-run", action="store_true", help="Validate and preview without running or writing logs")
    parser.add_argument("--debug", action="store_true", help="Show tracebacks for unexpected execution failures")
    args = parser.parse_args(argv)
    if args.stage == "scan" and args.matrix is not None:
        parser.error("--stage scan reads resolved.json; omit --matrix")
    if args.stage != "scan" and args.matrix is None:
        parser.error("--matrix is required for generation and all stages")
    try:
        # Previews check the same directory rules, so a dry run predicts execution.
        _require_run_directory(args.log_dir)
        receipt = args.log_dir / "resolved.json"
        previous = None
        if receipt.exists() or receipt.is_symlink():
            previous = _read_json(receipt)
            _validate_saved_selection(previous)
        if args.stage == "scan":
            if previous is None:
                raise ValueError("--stage scan requires resolved.json; run generation first")
            return _scan(previous["benchmarks"], args.log_dir, dry_run=args.dry_run)
        config = _Matrix.model_validate(_read_json(args.matrix))
        resolved = _resolve_matrix(config, previous)
        resolved["execution"] = _resolve_execution(config.execution, args.matrix)
        if previous is not None and resolved != previous:
            raise ValueError("Matrix selections, settings or prices changed; use a new run directory")
        groups = _matrix_tasks(resolved)
        _preview(resolved, groups)
        if args.dry_run:
            return 0
        _save_selection(args.log_dir, resolved)
        return _execute(resolved, groups, args.log_dir, scan=args.stage == "all")
    except ValidationError as error:
        for item in error.errors(include_input=False, include_context=False, include_url=False):
            print(f"Invalid matrix {'.'.join(map(str, item['loc']))}: {item['msg']}", file=sys.stderr)
        return 1
    except (OSError, ValueError, RuntimeError) as error:
        print(f"Experiment matrix failed: {error}", file=sys.stderr)
        return 1
    except Exception as error:
        if args.debug:
            raise
        print(f"Experiment execution failed ({type(error).__name__}); rerun with --debug for details.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
