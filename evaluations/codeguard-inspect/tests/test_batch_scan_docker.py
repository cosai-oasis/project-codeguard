"""Whole-log scanning and container teardown using trusted fixtures only."""

import asyncio
import json
import subprocess

import pytest
from inspect_ai.log import read_eval_log
from inspect_ai.util import sandbox

import codeguard_evals.graders.semgrep_runner as runner
import codeguard_evals.scan as batch
import codeguard_evals.graders.semgrep as grader
from codeguard_evals.scan import scan_log
from codeguard_evals.sandbox_client import BenchmarkInfrastructureError
from tests.conftest import generation_log

pytestmark = pytest.mark.docker


def test_hard_timeout_tears_down_descendants_and_reruns_the_whole_log(tmp_path, monkeypatch):
    cpus = runner.scan_identity()["cpus"]
    source = generation_log(tmp_path)
    original = source.read_bytes()
    real_command = runner.SCANNER_COMMAND
    fixture = """
import subprocess, sys, time
from pathlib import Path
child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'],
    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
Path('/tmp/scanner-descendant.pid').write_text(str(child.pid))
time.sleep(120)
"""
    monkeypatch.setattr(runner, "SCANNER_COMMAND", ("python3", "-I", "-c", fixture))
    monkeypatch.setattr(runner, "SEMGREP_TIMEOUT_SECONDS", 10)
    native_scan = runner.scan_sources
    containers, descendants, sizes = [], [], []

    async def record(sources):
        environment = sandbox("semgrep")
        connection = await environment.connection()
        details = json.loads(subprocess.check_output(
            ["docker", "inspect", connection.container], text=True, timeout=30,
        ))[0]
        containers.append(details["Id"])
        assert details["HostConfig"]["NanoCpus"] == int(cpus * 1_000_000_000)
        sizes.append(len(sources))
        try:
            return await native_scan(sources)
        except RuntimeError as error:
            assert "TimeoutError" in str(error), str(error)
            child = await environment.exec(["/bin/cat", "/tmp/scanner-descendant.pid"], timeout=5)
            assert child.success, child.stderr
            descendants.append(int(child.stdout))
            raise

    def assert_stopped(container):
        states = subprocess.check_output(
            [
                "docker",
                "container",
                "ls",
                "--all",
                "--filter",
                f"id={container}",
                "--format",
                "{{.State}}",
            ],
            text=True,
            timeout=30,
        ).strip()
        assert states in ("", "exited", "dead")

    native_eval = batch.eval_async

    async def eval_with_changed_environment(*args, **kwargs):
        # Inspect metadata must preserve the selected quota during environment loading.
        with monkeypatch.context() as scoped:
            scoped.setenv("CODEGUARD_SCANNER_CPUS", "1.0")
            scoped.setenv("SAMPLE_METADATA_SCANNER_CPUS", "1.0")
            return await native_eval(*args, **kwargs)

    monkeypatch.setattr(batch, "eval_async", eval_with_changed_environment)
    monkeypatch.setattr(grader, "scan_sources", record)
    directory = tmp_path / "scored"
    with pytest.raises(BenchmarkInfrastructureError, match="rerun the same scan command"):
        asyncio.run(scan_log(source, directory))
    assert len(containers) == len(descendants) == 1 and descendants[0] > 0
    assert_stopped(containers[0])
    assert not (directory / source.name).exists()
    monkeypatch.setattr(runner, "SCANNER_COMMAND", real_command)
    monkeypatch.setattr(runner, "SEMGREP_TIMEOUT_SECONDS", 120)
    output = asyncio.run(scan_log(source, directory))
    assert sizes == [3, 3] and containers[0] != containers[1]
    assert_stopped(containers[1])
    result = read_eval_log(output)
    assert result.results.completed_samples == 3
    assert result.eval.metadata["batch_scan"]["grader"]["cpus"] == cpus
    assert all(sample.scores and not sample.error for sample in result.samples)
    assert source.read_bytes() == original
    assert not (directory / ".scan-cache").exists()
