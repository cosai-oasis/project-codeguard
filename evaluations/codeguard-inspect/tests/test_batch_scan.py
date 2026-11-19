"""Whole-log scanning preserves generations and publishes only validated results."""

import asyncio
import importlib
import os
import shutil
import stat
from pathlib import Path

import codeguard_evals.graders.semgrep as semgrep
import pytest
from codeguard_evals.securityeval import scorers
from codeguard_evals.locking import exclusive_file_lock
from codeguard_evals.sandbox_client import BenchmarkInfrastructureError
from inspect_ai.log import (
    EvalSampleLimit,
    ProvenanceData,
    read_eval_log,
    write_eval_log,
    write_eval_log_async,
)
from inspect_ai.util import SandboxUnavailableError

from tests.conftest import generation_log

batch = importlib.import_module("codeguard_evals.scan")


def test_batch_uses_one_environment_and_rescans_the_whole_log(tmp_path, scanner):
    source = generation_log(tmp_path)
    original = source.read_bytes()
    output = asyncio.run(batch.scan_log(source, tmp_path / "scored"))
    calls, launches, preparations = scanner
    assert len(calls) == 3 and len(launches) == len(preparations) == 1
    log = read_eval_log(output)
    assert log.eval.metadata["phase"] == "scored"
    assert all(
        sample.scores["static_safety_scorer"].value["finding_count"] == 0 for sample in log.samples
    )
    asyncio.run(batch.scan_log(source, tmp_path / "scored"))
    assert len(calls) == 6 and len(launches) == len(preparations) == 2
    assert not (tmp_path / "scored/.scan-cache").exists()
    assert source.read_bytes() == original


@pytest.mark.parametrize("change", ["command", "environment", "timeout", "collector"])
def test_scanner_changes_require_a_new_output_directory(tmp_path, scanner, monkeypatch, change):
    from codeguard_evals.graders import semgrep_runner

    source = generation_log(tmp_path, count=1)
    directory = tmp_path / "scored"
    output = asyncio.run(batch.scan_log(source, directory))
    original = output.read_bytes()
    if change == "command":
        command = (*semgrep_runner.SCANNER_COMMAND, "--changed-worker-invocation")
        monkeypatch.setattr(semgrep_runner, "SCANNER_COMMAND", command)
    elif change == "environment":
        monkeypatch.setitem(semgrep_runner.scanner_client.ENVIRONMENT, "PYTHONUTF8", "0")
    elif change == "timeout":
        monkeypatch.setattr(semgrep_runner, "SEMGREP_TIMEOUT_SECONDS", 60)
    else:
        root = Path(semgrep_runner.__file__).parents[2]
        copy = tmp_path / "collector"
        for name in semgrep_runner.COLLECTOR_FILES:
            target = copy / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((root / name).read_bytes())
        path = copy / "codeguard_evals/graders/semgrep_runner.py"
        path.write_bytes(path.read_bytes() + b"\n# changed collector implementation\n")
        monkeypatch.setattr(semgrep_runner, "__file__", str(path))
    with pytest.raises(ValueError, match="another run or scanner"):
        asyncio.run(batch.scan_log(source, directory))
    assert output.read_bytes() == original and len(scanner[0]) == 1
    # Removing the previous scored output permits a deliberate rescan.
    output.unlink()
    asyncio.run(batch.scan_log(source, directory))
    assert len(scanner[0]) == 2


def test_direct_scans_lock_the_output_directory_until_publication(tmp_path, scanner, monkeypatch):
    first = generation_log(tmp_path / "first", count=1)
    second = generation_log(tmp_path / "second", count=2)
    second = second.rename(second.with_name(first.name))
    directory = tmp_path / "scored"
    native_pending = batch._scan_outputs

    async def run():
        entered, release = asyncio.Event(), asyncio.Event()

        async def hold_first(*args):
            if args[-1] == directory:
                entered.set()
                await release.wait()
            return await native_pending(*args)

        monkeypatch.setattr(batch, "_scan_outputs", hold_first)
        active = asyncio.create_task(batch.scan_log(first, directory))
        try:
            await asyncio.wait_for(entered.wait(), timeout=10)
            with pytest.raises(ValueError, match="already using this scan output directory"):
                await asyncio.wait_for(batch.scan_log(second, directory), timeout=2)
            # Independent output directories can still be used while this one is locked.
            await batch.scan_log(second, tmp_path / "other-scored")
        finally:
            release.set()
            output = await active
        original = output.read_bytes()
        with pytest.raises(ValueError, match="another run or scanner"):
            await batch.scan_log(second, directory)
        assert output.read_bytes() == original

    asyncio.run(run())
    assert len(scanner[0]) == 3


@pytest.mark.parametrize("error_type", [RuntimeError, asyncio.CancelledError])
def test_scan_lock_is_released_on_failure_or_cancellation(
    tmp_path, scanner, monkeypatch, error_type
):
    source = generation_log(tmp_path, count=1)
    directory = tmp_path / "scored"
    native_pending = batch._scan_outputs

    async def fail(*args):
        raise error_type("stopped")

    monkeypatch.setattr(batch, "_scan_outputs", fail)
    with pytest.raises(error_type):
        asyncio.run(batch.scan_log(source, directory))
    lock_inode = (directory / ".scan.lock").stat().st_ino
    monkeypatch.setattr(batch, "_scan_outputs", native_pending)
    output = asyncio.run(batch.scan_log(source, directory))
    assert read_eval_log(output).status == "success"
    assert (directory / ".scan.lock").stat().st_ino == lock_inode


def test_direct_scan_command_reports_a_busy_output_directory(tmp_path, scanner, capsys):
    source = generation_log(tmp_path, count=1)
    directory = tmp_path / "scored"
    directory.mkdir(mode=0o700)
    with exclusive_file_lock(directory / ".scan.lock", description="test"):
        assert batch.main([str(source), "--output-dir", str(directory)]) == 1
    assert not scanner[1]
    assert "already using this scan output directory" in capsys.readouterr().err


@pytest.mark.parametrize("failure", ["generation", "scanner", "selection"])
def test_scan_command_stops_on_the_first_fatal_error(tmp_path, scanner, monkeypatch, capsys, failure):
    bad = generation_log(tmp_path / "bad", count=1)
    good = generation_log(tmp_path / "good", count=1)
    if failure == "generation":
        log = read_eval_log(bad)
        log.status = "cancelled"
        write_eval_log(log, bad)
        message = "Resume generation"
    elif failure == "scanner":

        async def fail(sources):
            raise RuntimeError("fixture scanner failure")

        monkeypatch.setattr(semgrep, "scan_sources", fail)
        message = "fixture scanner failure"
    else:
        bad = tmp_path / "empty-logs"
        bad.mkdir()
        message = "No generation logs"
    directory = tmp_path / "scored"
    assert batch.main([str(bad), str(good), "--output-dir", str(directory)]) == 1
    output = capsys.readouterr()
    assert str(bad) in output.err and message in output.err
    assert "Traceback" not in output.err
    assert len(scanner[1]) == (1 if failure == "scanner" else 0)
    assert not list(directory.glob("*.eval"))


@pytest.mark.parametrize("damage", [None, "missing", "changed"])
def test_codeguard_snapshot_is_validated_before_scanning_and_preserved_for_scoring(
    tmp_path, scanner, damage
):
    from tests.conftest import codeguard_files
    from codeguard_evals.metrics import SKILL_SNAPSHOT_KEY, save_skill_snapshot
    from codeguard_evals.securityeval.protocol import securityeval_prompt

    from tests.conftest import task_state

    source = generation_log(tmp_path, count=1)
    log = read_eval_log(source)
    sample = log.samples[0]
    log.eval.metadata["condition"] = sample.metadata["condition"] = "codeguard"
    sample.id = sample.id.replace("/baseline/", "/codeguard/")
    sample.input = securityeval_prompt("codeguard")
    if damage != "missing":
        state = task_state()
        save_skill_snapshot(state, codeguard_files())
        snapshot = state.store.get(SKILL_SNAPSHOT_KEY)
        if damage == "changed":
            snapshot["document"] = "changed"
        sample.store[SKILL_SNAPSHOT_KEY] = snapshot
    write_eval_log(log, source)
    if damage is None:
        output = asyncio.run(batch.scan_log(source, tmp_path / "scored"))
        scored = read_eval_log(output).samples[0]
        assert scored.store[SKILL_SNAPSHOT_KEY] == snapshot
        assert scored.scores["static_safety_scorer"].value["skill_loaded"] == 0
        return
    with pytest.raises(BenchmarkInfrastructureError, match="Skill snapshot"):
        asyncio.run(batch.scan_log(source, tmp_path / "scored"))
    assert not scanner[0] and not scanner[1]


def test_log_condition_requires_a_skill_snapshot_when_samples_record_none(tmp_path, scanner):
    # Benchmarks need not copy the condition into samples; the log's condition decides.
    source = generation_log(tmp_path, count=1)
    log = read_eval_log(source)
    log.eval.metadata["condition"] = "skill"
    del log.samples[0].metadata["condition"]
    write_eval_log(log, source)
    with pytest.raises(BenchmarkInfrastructureError, match="Skill snapshot is missing"):
        asyncio.run(batch.scan_log(source, tmp_path / "scored"))
    assert not scanner[0] and not scanner[1]


@pytest.mark.parametrize(
    "benchmark,legacy_key",
    [
        ("SecurityEval", "semgrep"),
        ("CyberSecEval", None),
        ("ThirdStaticBenchmark", None),
    ],
)
def test_scanner_metadata_keeps_only_the_exporter_compatibility_alias(
    tmp_path, scanner, monkeypatch, benchmark, legacy_key
):
    # One fake grader isolates metadata routing from individual scanner behavior.
    source = generation_log(tmp_path, count=1)
    log = read_eval_log(source)
    log.eval.metadata["benchmark"] = benchmark
    if legacy_key is not None:
        log.eval.metadata[legacy_key] = {"old_configured_scanner": True}
    write_eval_log(log, source)
    monkeypatch.setitem(batch.GRADERS, benchmark, scorers.semgrep_grader)
    output = asyncio.run(batch.scan_log(source, tmp_path / "scored"))
    metadata = read_eval_log(output).eval.metadata
    identity = metadata["batch_scan"]["grader"]
    assert identity == scorers.semgrep_grader().identity
    for key in ("semgrep", "icd"):
        if key == legacy_key:
            assert metadata[key] == identity
        else:
            assert key not in metadata


def test_scored_results_are_private_even_with_a_permissive_umask(tmp_path, scanner):
    source = generation_log(tmp_path, count=1)
    previous_umask = os.umask(0)
    try:
        output = asyncio.run(batch.scan_log(source, tmp_path / "scored"))
    finally:
        os.umask(previous_umask)
    assert stat.S_IMODE(output.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(output.stat().st_mode) == 0o600


def test_nonprivate_output_directory_is_rejected_before_scanner_startup(tmp_path, scanner):
    source = generation_log(tmp_path)
    destination = tmp_path / "scored"
    destination.mkdir()
    destination.chmod(0o755)
    with pytest.raises(ValueError, match="0700"):
        asyncio.run(batch.scan_log(source, destination))
    assert not list(destination.iterdir()) and scanner[1] == []


def test_unrelated_scored_output_is_preserved(tmp_path, scanner):
    source = generation_log(tmp_path)
    output = asyncio.run(batch.scan_log(source, tmp_path / "scored"))
    existing = read_eval_log(output)
    existing.eval.metadata["batch_scan"]["source_sha256"] = "0" * 64
    write_eval_log(existing, output)
    original = output.read_bytes()
    with pytest.raises(ValueError, match="another run or scanner"):
        asyncio.run(batch.scan_log(source, tmp_path / "scored"))
    assert output.read_bytes() == original and len(scanner[1]) == 1


def test_scoring_never_initializes_provider_roles_and_preserves_provenance(
    tmp_path, scanner, monkeypatch
):
    source = generation_log(tmp_path)
    log = read_eval_log(source)
    log.eval = type(log.eval).model_validate(
        {
            **log.eval.model_dump(),
            "model": "openai/not-a-real-model",
            "model_roles": {"grader": {"model": "openai/not-a-real-model"}},
        }
    )
    roles = log.eval.model_roles
    log.eval.metadata["semgrep"] = {"configured_before_generation": True}
    write_eval_log(log, source)
    original = source.read_bytes()
    scoring = importlib.import_module("inspect_ai._eval.score")
    native_roles = scoring.model_roles_config_to_model_roles
    native_model = scoring.get_model

    def no_provider_roles(value):
        assert value is None
        return native_roles(value)

    def mock_model_only(model, *args, **kwargs):
        assert model == "mockllm/model"
        return native_model(model, *args, **kwargs)

    monkeypatch.setattr(scoring, "model_roles_config_to_model_roles", no_provider_roles)
    monkeypatch.setattr(scoring, "get_model", mock_model_only)
    output = asyncio.run(batch.scan_log(source, tmp_path / "scored"))
    scored = read_eval_log(output)
    assert scored.eval.model_roles == roles
    assert scored.eval.model == "openai/not-a-real-model"
    assert scored.eval.metadata["semgrep"] == scored.eval.metadata["batch_scan"]["grader"]
    assert source.read_bytes() == original


@pytest.mark.parametrize(
    "damage",
    [
        "status",
        "phase",
        "version",
        "duplicate",
        "reducer",
        "invalidated",
        "invalidated_sample",
        "backstop",
    ],
)
def test_unfinished_or_mismatched_logs_are_not_scored(tmp_path, scanner, damage):
    source = generation_log(tmp_path)
    log = read_eval_log(source)
    if damage == "status":
        log.status = "cancelled"
    elif damage == "phase":
        log.eval.metadata["phase"] = "scored"
    elif damage == "version":
        log.eval.task_version = "old"
    elif damage == "reducer":
        log.eval.config.epochs_reducer = ["untrusted/custom"]
    elif damage == "invalidated":
        log.invalidated = True
    elif damage == "invalidated_sample":
        log.samples[0].invalidation = ProvenanceData(author="unit-test", reason="withdrawn")
    elif damage == "backstop":
        log.eval.config.time_limit = 1200
        log.samples[0].limit = EvalSampleLimit(type="time", limit=1200, reason="backstop")
    else:
        log.samples[1].id = log.samples[0].id
    write_eval_log(log, source)
    expected_error = (
        "invalidated"
        if damage == "invalidated_sample"
        else "backstop"
        if damage == "backstop"
        else "complete, successful"
    )
    with pytest.raises(BenchmarkInfrastructureError, match=expected_error) as error:
        asyncio.run(batch.scan_log(source, tmp_path / "scored"))
    if damage == "backstop":
        assert "fresh generation log directory" in str(error.value)
        assert "eval-set will not retry" in str(error.value)
    assert scanner[1] == []


def test_scanning_cannot_overwrite_generation_log(tmp_path, scanner):
    source = generation_log(tmp_path)
    original = source.read_bytes()
    source.parent.chmod(0o700)
    with pytest.raises(ValueError, match="immutable"):
        asyncio.run(batch.scan_log(source, source.parent))
    assert source.read_bytes() == original and scanner[1] == []


@pytest.mark.parametrize("error_type", [ValueError, RuntimeError])
def test_failed_scanner_preflight_does_not_start_a_sandbox(
    tmp_path, scanner, monkeypatch, capsys, error_type
):
    source = generation_log(tmp_path)

    def reject():
        raise error_type("unverified scanner artifacts; run prefetch")

    monkeypatch.setattr(scorers, "load_default_locked_rules_directory", reject)
    directory = tmp_path / "scored"
    assert batch.main([str(source), "--output-dir", str(directory)]) == 1
    message = capsys.readouterr().err
    assert "unverified scanner artifacts; run prefetch" in message
    assert "Traceback" not in message
    assert not list(directory.glob("*.eval"))
    assert scanner[1] == []


def test_generation_log_changed_during_scanning_is_not_published(tmp_path, scanner, monkeypatch):
    source = generation_log(tmp_path, count=1)
    changed = read_eval_log(source)
    changed.eval.metadata["changed_during_scan"] = True

    async def scan_and_change_log(code):
        scanner[0].append(code)
        await write_eval_log_async(changed, source)
        return [() for _ in code]

    monkeypatch.setattr(semgrep, "scan_sources", scan_and_change_log)
    with pytest.raises(BenchmarkInfrastructureError, match="changed during scanning"):
        asyncio.run(batch.scan_log(source, tmp_path / "scored"))
    assert len(scanner[0]) == 1
    assert not (tmp_path / "scored" / source.name).exists()
    assert not list((tmp_path / "scored").glob(".scored-*"))


def test_complete_scored_log_replays_without_any_scanning(tmp_path, scanner, monkeypatch):
    from codeguard_evals.securityeval.scorers import static_safety_scorer
    from inspect_ai import score

    source = generation_log(tmp_path, count=1)
    output = asyncio.run(batch.scan_log(source, tmp_path / "scored"))
    monkeypatch.setattr(
        semgrep, "scan_sources", lambda *args: pytest.fail("scanner used for replay")
    )
    original = read_eval_log(output)
    replayed = score(
        original,
        static_safety_scorer(),
        model="mockllm/model",
        action="overwrite",
        display="none",
    )
    assert replayed.samples[0].scores["static_safety_scorer"].value == pytest.approx(
        original.samples[0].scores["static_safety_scorer"].value, nan_ok=True
    )


@pytest.mark.parametrize("latest_status", ["success", "started", "error"])
def test_scan_selects_latest_attempt_without_hiding_unfinished_generation(
    tmp_path, scanner, monkeypatch, latest_status
):
    native_selection = batch.latest_generation_logs

    def select(directory):
        with pytest.raises(RuntimeError, match="no running event loop"):
            asyncio.get_running_loop()
        return native_selection(directory)

    monkeypatch.setattr(batch, "latest_generation_logs", select)
    job = tmp_path / "job with spaces"
    source = generation_log(job, count=1)
    job.chmod(0o700)
    source.parent.chmod(0o700)
    log = read_eval_log(source)
    abandoned = source.with_name("abandoned.eval")
    log.status = "started" if latest_status == "success" else "success"
    write_eval_log(log, abandoned)
    log.status = latest_status
    write_eval_log(log, source)
    os.utime(abandoned, (1, 1))
    os.utime(source, (2, 2))
    # A completed log before a later failure must remain available.
    other = generation_log(tmp_path / "other", count=1)
    shutil.copy2(other, source.parent / other.name)
    os.utime(source.parent / other.name, (3, 3))
    original = {path: path.read_bytes() for path in source.parent.glob("*.eval")}

    status = batch.main([str(source.parent), "--output-dir", str(job / "scored")])
    assert status == (0 if latest_status == "success" else 1)
    scored = {path.name for path in (job / "scored").glob("*.eval")}
    assert scored == ({source.name, other.name} if status == 0 else {other.name})
    assert all(path.read_bytes() == raw for path, raw in original.items())


@pytest.mark.parametrize(
    "failure",
    [
        RuntimeError("invalid scanner rules"),
        SandboxUnavailableError("container lost"),
        TimeoutError("scanner timed out"),
        asyncio.CancelledError(),
    ],
)
def test_failed_batch_preserves_results_and_reruns_every_source(
    tmp_path, scanner, monkeypatch, failure
):
    source = generation_log(tmp_path)
    directory = tmp_path / "scored"
    output = asyncio.run(batch.scan_log(source, directory))
    original = source.read_bytes(), output.read_bytes()
    batches = []

    async def fail(sources):
        batches.append(sources)
        raise failure

    with monkeypatch.context() as patch:
        patch.setattr(semgrep, "scan_sources", fail)
        with pytest.raises((BenchmarkInfrastructureError, asyncio.CancelledError)):
            asyncio.run(batch.scan_log(source, directory))
    assert original == (source.read_bytes(), output.read_bytes())
    assert len(batches) == 1 and len(batches[0]) == 3
    assert not (directory / ".scan-cache").exists()
    asyncio.run(batch.scan_log(source, directory))
    assert len(scanner[0]) == 6 and len(scanner[1]) == 3


@pytest.mark.parametrize("outcomes", [[(), "parse_error", ()], ["resource_limit"] * 3])
def test_incomplete_files_remain_unscored_through_export_and_replay(
    tmp_path, scanner, monkeypatch, capsys, outcomes
):
    from codeguard_evals.export_results import read_run
    from inspect_ai import score

    source = generation_log(tmp_path)
    generation = read_eval_log(source)
    generation.eval.metadata["condition"] = "baseline"
    write_eval_log(generation, source)
    later = generation_log(tmp_path / "later", count=1)
    pending_results = iter((outcomes, [()]))

    async def scan(sources):
        result = next(pending_results)
        assert len(sources) == len(result)
        return result

    monkeypatch.setattr(semgrep, "scan_sources", scan)
    directory = tmp_path / "scored"
    assert batch.main([str(source), str(later), "--output-dir", str(directory)]) == 1
    output = capsys.readouterr()
    assert str(source) in output.err and "These samples have no scores" in output.err
    assert str(directory / later.name) in output.out
    later_result = read_eval_log(directory / later.name)
    assert later_result.status == "success" and later_result.results.completed_samples == 1
    assert all(sample.scores and sample.error is None for sample in later_result.samples)
    assert len(scanner[1]) == 2
    result = read_eval_log(directory / source.name)
    assert result.status == "success" and result.error is None
    assert result.results.completed_samples == outcomes.count(())
    _, _, rows = read_run("Fixture", directory / source.name)
    assert len(rows) == 3
    for sample, row, outcome in zip(result.samples, rows, outcomes, strict=True):
        if isinstance(outcome, str):
            assert outcome in sample.error.message and not sample.scores
            assert sample.store[semgrep.SEMGREP_EVIDENCE_KEY]["incomplete_reason"] == outcome
            assert row["error"] and row["findings"] == ""
        else:
            assert sample.error is None and sample.scores

    monkeypatch.setattr(
        semgrep, "scan_sources", lambda *args: pytest.fail("scanner used for replay")
    )
    replayed = score(
        result,
        scorers.static_safety_scorer(),
        model="mockllm/model",
        action="overwrite",
        display="none",
    )
    for before, after in zip(result.samples, replayed.samples, strict=True):
        assert before.error == after.error and before.store == after.store
        if before.error is not None:
            assert not after.scores
        else:
            assert after.scores["static_safety_scorer"].value == pytest.approx(
                before.scores["static_safety_scorer"].value, nan_ok=True
            )
