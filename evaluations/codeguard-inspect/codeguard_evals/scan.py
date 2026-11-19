"""Batch-scan completed generation logs; preserve originals and publish validated results."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import os
import tempfile
import sys
from pathlib import Path

from inspect_ai import Task, eval_async, score_async
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.log import (
    EvalError,
    EvalLog,
    EvalSample,
    EvalSampleSummary,
    list_eval_logs,
    read_eval_log,
    read_eval_log_async,
    read_eval_log_sample_async,
    read_eval_log_sample_summaries_async,
)
from inspect_ai.model import ModelName
from inspect_ai.scorer import Target
from inspect_ai.solver import Generate, TaskState, solver
from inspect_ai.viewer import ViewerConfig

from codeguard_evals.artifacts import require_directory
from codeguard_evals.graders.base import StaticGrader
from codeguard_evals.locking import exclusive_file_lock
from codeguard_evals.metrics import SKILL_SNAPSHOT_KEY, load_skill_snapshot
from codeguard_evals.output_artifact import SAVED_OUTPUT_KEY, load_saved_output
from codeguard_evals.protocol import EVALUATION_VERSION, condition_has_skill
from codeguard_evals.sandbox_client import BenchmarkInfrastructureError
from codeguard_evals.securityeval.scorers import semgrep_grader
from codeguard_evals.cyberseceval.scorers import cyberseceval_grader
from codeguard_evals.streaming_log import scoring_samples

# Trusted adapters only. A log cannot select a module or command to execute.
GRADERS = {
    "SecurityEval": semgrep_grader,
    "CyberSecEval": cyberseceval_grader,
}


class IncompleteBatchScanError(BenchmarkInfrastructureError):
    """Some sources could not be analyzed; the scored log records their errors."""


def _file_sha256(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def _state(log: EvalLog, sample: EvalSample) -> TaskState:
    # Scanning needs source and benchmark identity, not agent transcripts or
    # skill-read metrics. The score pass reads the complete original sample.
    return TaskState(
        model=ModelName(log.eval.model),
        sample_id=sample.id,
        epoch=sample.epoch,
        input=sample.input,
        messages=[],
        target=Target(sample.target),
        metadata=sample.metadata,
        store={SAVED_OUTPUT_KEY: sample.store.get(SAVED_OUTPUT_KEY)},
        sample_uuid=sample.uuid,
    )


def _validate_generation(log: EvalLog, summaries: list[EvalSampleSummary]) -> str:
    metadata = log.eval.metadata or {}
    if (
        log.status != "success"
        or log.invalidated
        or log.eval.task_version != EVALUATION_VERSION
        or metadata.get("phase") != "generation"
        or not summaries
        or log.eval.scorers
        or any(name != "mean" for name in (log.eval.config.epochs_reducer or []))
        or log.results is None
        or log.results.total_samples != len(summaries)
        or any(sample.error is not None for sample in summaries)
        or len({(str(sample.id), sample.epoch) for sample in summaries})
        != len(summaries)
    ):
        raise BenchmarkInfrastructureError(
            "Scan requires a complete, successful generation log from this harness. "
            "Resume generation with the original eval-set command first."
        )
    benchmark = metadata.get("benchmark")
    if not isinstance(benchmark, str) or benchmark not in GRADERS:
        raise BenchmarkInfrastructureError("Unrecognized benchmark in generation log")
    return benchmark


async def _scan_outputs(
    states: list[TaskState], grader: StaticGrader, output_dir: Path,
) -> dict[tuple[str | int, int], str]:
    """Collect one log in one sandbox; discard the attempt on a scanner failure."""
    if grader.prepare is not None:
        try:
            grader.prepare()
        except RuntimeError as error:
            raise BenchmarkInfrastructureError(
                f"Scanner preparation failed: {error}"
            ) from error
    failures: dict[tuple[str | int, int], str] = {}

    @solver
    def scan_saved_outputs():
        async def solve(batch: TaskState, generate: Generate) -> TaskState:
            nonlocal failures
            del generate
            failures = await grader.collect(states)
            for state in states:
                grader.validate(state)
            return batch

        return solve

    task = Task(
        name="codeguard_batch_scan",
        dataset=MemoryDataset([Sample(
            id="scan",
            input="Scan saved source as data.",
            metadata={"scanner_cpus": grader.identity["cpus"]},
        )]),
        solver=scan_saved_outputs(),
        sandbox=("docker", str(grader.sandbox_config)),
        checkpoint=False,
        viewer=ViewerConfig(trust_content=False),
    )
    # Inspect owns the sandbox lifecycle. The local model placeholder is never called.
    scanned = (await eval_async(
        task, model="mockllm/model", score=False,
        log_dir=str(output_dir / ".scan-control"), log_samples=False,
        log_realtime=False, ctl_server=False, sandbox_cleanup=True,
    ))[0]
    if scanned.status != "success":
        reason = scanned.error.message if scanned.error else scanned.status
        raise BenchmarkInfrastructureError(
            f"Batch scan stopped: {reason}. No new scored log was published. "
            "Resolve the scanner failure and rerun the same scan command."
        )
    return failures


def latest_generation_logs(directory: Path) -> list[Path]:
    """Select attempts as eval-set does: newest file per task ID, regardless of status."""
    require_directory(directory)
    latest: dict[str, Path] = {}
    for info in list_eval_logs(str(directory), formats=["eval"], recursive=False):
        header = read_eval_log(info.name, header_only=True)
        if not header.eval.task_id:
            raise ValueError(f"Generation log has no task ID: {info.name}")
        latest.setdefault(header.eval.task_id, Path.from_uri(info.name))
    if not latest:
        raise ValueError("No generation logs found; run generation first")
    return list(latest.values())


async def scan_log(source: Path, output_dir: Path) -> Path:
    """Own the output directory from validation through final publication."""
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    require_directory(output_dir, private=True)
    with exclusive_file_lock(
        output_dir / ".scan.lock", description="this scan output directory"
    ):
        return await _scan_log(source, output_dir)


async def _scan_log(source: Path, output_dir: Path) -> Path:
    """Scan a completed log while holding its output-directory lock."""
    source = source.resolve(strict=True)
    if not source.is_file():
        raise ValueError("Generation log must be a regular file")
    source_hash = _file_sha256(source)
    log = await read_eval_log_async(source, header_only=True)
    summaries = await read_eval_log_sample_summaries_async(source)
    benchmark = _validate_generation(log, summaries)
    # The harness always records the condition on the log; sample metadata is up to each benchmark.
    has_skill = condition_has_skill((log.eval.metadata or {}).get("condition"))
    grader = GRADERS[benchmark]()
    identity = grader.identity
    scan_metadata = {
        "schema_version": 2,
        "source_sha256": source_hash,
        "grader": identity,
    }

    destination = output_dir / (source.stem + ".eval")
    if destination.resolve() == source:
        raise ValueError(
            "Use a separate output directory; generation logs are immutable"
        )
    if destination.exists() or destination.is_symlink():
        if destination.is_symlink() or not destination.is_file():
            raise ValueError("Scored output must be a regular file, not a link")
        existing = await read_eval_log_async(destination, header_only=True)
        if (existing.eval.metadata or {}).get("batch_scan") != scan_metadata:
            raise ValueError(
                "Output belongs to another run or scanner; use a new output directory"
            )

    states: dict[tuple[str | int, int], TaskState] = {}
    for summary in summaries:
        sample = await read_eval_log_sample_async(
            source,
            summary.id,
            summary.epoch,
            resolve_attachments=True,
            exclude_fields={"messages", "events", "output"},
        )
        if sample.error is not None or sample.invalidation is not None:
            raise BenchmarkInfrastructureError(
                "Generation sample is errored or invalidated"
            )
        if (
            sample.limit is not None
            and sample.limit.type == "time"
            and sample.limit.limit == log.eval.config.time_limit
        ):
            raise BenchmarkInfrastructureError(
                "Generation hit the sample time backstop without a recorded error. "
                "Use the updated harness and a fresh generation log directory; "
                "eval-set will not retry this completed limit stop."
            )
        if has_skill:
            load_skill_snapshot(sample.store.get(SKILL_SNAPSHOT_KEY))
        state = _state(log, sample)
        saved = load_saved_output(state)
        if (
            saved.filename != grader.filename(state)
            or grader.evidence_key in sample.store
        ):
            raise BenchmarkInfrastructureError(
                "Generation artifact has an unexpected filename or scan evidence"
            )
        states[(sample.id, sample.epoch)] = state

    failures = await _scan_outputs(list(states.values()), grader, output_dir)

    async def attach_evidence(sample: EvalSample) -> None:
        sample_key = (sample.id, sample.epoch)
        sample.store[grader.evidence_key] = states[sample_key].store.get(grader.evidence_key)
        if sample_key in failures:
            sample.error = EvalError(
                message=failures[sample_key], traceback="", traceback_ansi=""
            )

    failure_summary = f"{len(failures)} source scans could not be completed"
    log.eval.metadata = {
        **(log.eval.metadata or {}),
        "phase": "scored",
        "batch_scan": scan_metadata,
    }
    # The SecurityEval results exporter still consumes this field.
    if benchmark == "SecurityEval":
        log.eval.metadata["semgrep"] = identity
    with tempfile.TemporaryDirectory(dir=output_dir, prefix=".scored-") as temporary:
        completed_path = Path(temporary) / "result.eval"
        async with scoring_samples(
            log,
            source,
            [(sample.id, sample.epoch) for sample in summaries],
            completed_path,
            attach_evidence,
        ) as samples:
            # Saved roles must not initialize provider clients during offline scoring.
            roles = log.eval.model_roles
            log.eval.model_roles = None
            log.eval.metrics = None
            try:
                log = await score_async(
                    log,
                    grader.scorer,
                    model="mockllm/model",
                    action="overwrite",
                    display="none",
                    copy=False,
                    samples=samples,
                )
            finally:
                log.eval.model_roles = roles
        if _file_sha256(source) != source_hash:
            raise BenchmarkInfrastructureError(
                "Generation log changed during scanning"
            )
        completed_path.chmod(0o600)
        with completed_path.open("rb") as completed:
            os.fsync(completed.fileno())
        os.replace(completed_path, destination)
    if failures:
        raise IncompleteBatchScanError(
            f"{failure_summary}; results are in {destination}. These samples have no scores."
        )
    return destination


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "logs", nargs="+", type=Path,
        help="Generation logs or directories (latest attempt per task in each directory)",
    )
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args(argv)

    current: Path | None = None
    sources: list[Path] = []

    async def run() -> int:
        nonlocal current
        status = 0
        for current in sources:
            try:
                output = await scan_log(current, args.output_dir)
            except IncompleteBatchScanError as error:
                print(f"{current}: {error}", file=sys.stderr)
                status = 1
            else:
                print(f"Scored saved generations: {output}")
        return status

    try:
        # Keep Inspect's synchronous log readers outside the async scan loop.
        for current in args.logs:
            sources.extend(latest_generation_logs(current) if current.is_dir() else [current])
        return asyncio.run(run())
    except (BenchmarkInfrastructureError, OSError, ValueError) as error:
        print(f"{current}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
