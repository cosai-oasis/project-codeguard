"""A synthetic third adapter exercises generation and batch grading separately."""

import hashlib
import importlib
import subprocess
import sys
from pathlib import Path

import pytest

import anyio
from inspect_ai import eval_set
from inspect_ai.agent import Agent, AgentState, agent
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.scorer import Score, scorer
from inspect_ai.solver import solver
from inspect_ai.log import read_eval_log

import codeguard_evals.harness as harness
import codeguard_evals.output_artifact as artifacts
from codeguard_evals.graders.base import StaticGrader
from codeguard_evals.sandbox_client import ExportedSolution
from tests.conftest import eval_mock_task


@scorer(metrics=[])
def example_scorer():
    async def score(state, target):
        assert (
            state.store.get("example.evidence")
            == hashlib.sha256(b"fn example() {}\n").hexdigest()
        )
        return Score(value=1)

    return score


def test_third_benchmark_reuses_both_phases(tmp_path, monkeypatch, offline_batch):
    monkeypatch.setenv("INSPECT_TRACE_FILE", str(tmp_path / "trace.log"))
    events = []

    @agent
    def example_agent() -> Agent:
        async def run(state: AgentState) -> AgentState:
            events.append("generate")
            return state

        return run

    async def export(filename):
        assert filename == "solution.rs"
        events.append("capture")
        return ExportedSolution(b"fn example() {}\n", None)

    async def collect(states):
        events.append("grade")
        for state in states:
            saved = artifacts.load_saved_output(state)
            state.store.set("example.evidence", hashlib.sha256(saved.source.encode()).hexdigest())
        return {}

    def validate(state):
        assert state.store.get("example.evidence") == hashlib.sha256(
            artifacts.load_saved_output(state).source.encode()
        ).hexdigest()

    monkeypatch.setattr(harness, "codex_cli", lambda **kwargs: example_agent())
    monkeypatch.setattr(artifacts, "export_solution", export)
    grader = StaticGrader(
        filename=lambda state: "solution.rs",
        collect=collect,
        validate=validate,
        scorer=example_scorer(),
        prepare=lambda: events.append("prepare"),
        sandbox_config=Path("example-scan.yaml"),
        evidence_key="example.evidence",
        identity={"scanner": "fixture", "cpus": 4.0},
    )
    spec = harness.StaticBenchmark(
        name="example_baseline",
        display_name="Example baseline",
        dataset=MemoryDataset([Sample(id="example/1", input="Write a Rust function.")]),
        filename=grader.filename,
        sandbox_config=Path("example-generation.yaml"),
        metadata={"benchmark": "Example", "dataset": {"revision": "fixture"}},
        tags=("example",),
    )
    task = harness.build_static_task(spec, "baseline", agent_turn_limit=3)
    assert task.viewer.trust_content is False
    assert task.metadata["generation_limits"]["turns"] == 3
    assert events == [] and task.scorer is None
    task.sandbox = None
    log = eval_mock_task(task, tmp_path / "generation")
    assert log.status == "success"
    assert events == ["generate", "capture"]
    assert not log.samples[0].scores
    batch = importlib.import_module("codeguard_evals.scan")
    monkeypatch.setitem(batch.GRADERS, "Example", lambda: grader)
    scored = offline_batch(log, tmp_path / "scored")
    assert events == ["generate", "capture", "prepare", "grade"]
    assert scored.samples[0].scores["example_scorer"].value == 1


@pytest.mark.parametrize("phase", ["setup", "generation"])
def test_sample_backstop_errors_are_retried_and_keep_captured_source(
    tmp_path, monkeypatch, phase
):
    monkeypatch.setenv("INSPECT_TRACE_FILE", str(tmp_path / "trace.log"))
    calls = {"setup": 0, "generation": 0}

    @solver
    def setup():
        async def solve(state, generate):
            calls["setup"] += 1
            if phase == "setup" and calls["setup"] == 1:
                await anyio.sleep(5)
            return state

        return solve

    @agent
    def fixture_agent() -> Agent:
        async def run(state: AgentState) -> AgentState:
            calls["generation"] += 1
            if phase == "generation" and calls["generation"] == 1:
                await anyio.sleep(5)
            return state

        return run

    async def export(filename):
        return ExportedSolution(b"captured source\n", None)

    monkeypatch.setattr(harness, "codex_cli", lambda **kwargs: fixture_agent())
    monkeypatch.setattr(artifacts, "export_solution", export)
    task = harness.build_static_task(
        harness.StaticBenchmark(
            name="backstop",
            display_name="Backstop",
            dataset=MemoryDataset([Sample(id="1", input="Generate a file.")]),
            filename=lambda state: "solution.py",
            sandbox_config=Path("unused.yaml"),
            metadata={"benchmark": "SecurityEval"},
            tags=(),
            setup=(setup(),),
        ),
        "baseline",
    )
    task.sandbox = None
    task.time_limit = 1
    options = dict(
        model="mockllm/model",
        log_dir=str(tmp_path / "generation"),
        display="none",
        log_realtime=False,
        ctl_server=False,
        retry_attempts=0,
        retry_immediate=False,
    )
    success, logs = eval_set([task], **options)
    sample = read_eval_log(logs[0].location).samples[0]
    assert not success
    assert sample.error is not None and "sample time backstop" in sample.error.message
    assert calls == {"setup": 1, "generation": int(phase == "generation")}
    assert not sample.scores
    if phase == "generation":
        assert sample.store[artifacts.SAVED_OUTPUT_KEY]["source"] == "captured source\n"
    else:
        assert artifacts.SAVED_OUTPUT_KEY not in sample.store

    success, logs = eval_set([task], **options)
    assert success
    assert calls == {"setup": 2, "generation": 2 if phase == "generation" else 1}
    retried = read_eval_log(logs[0].location).samples[0]
    assert retried.error is None
    assert retried.store[artifacts.SAVED_OUTPUT_KEY]["source"] == "captured source\n"


@pytest.mark.parametrize(
    "module,forbidden",
    [
        (
            "codeguard_evals.harness",
            (
                "codeguard_evals.securityeval",
                "codeguard_evals.cyberseceval",
                "codeguard_evals.graders",
            ),
        ),
        (
            "codeguard_evals.securityeval.securityeval",
            ("codeguard_evals.graders", "codeguard_evals.securityeval.scorers"),
        ),
        (
            "codeguard_evals.cyberseceval.cyberseceval",
            ("codeguard_evals.graders", "codeguard_evals.cyberseceval.scorers"),
        ),
        (
            "codeguard_evals.export_results",
            ("codeguard_evals.graders", "codeguard_evals.securityeval.scorers"),
        ),
        ("codeguard_evals.graders.base", ("inspect_ai", "inspect_swe")),
        ("codeguard_evals.securityeval.scorers", ("codeguard_evals.harness", "inspect_swe")),
        ("codeguard_evals.cyberseceval.scorers", ("codeguard_evals.harness", "inspect_swe")),
        ("codeguard_evals.scan", ("codeguard_evals.harness", "inspect_swe")),
    ],
)
def test_import_boundaries(module, forbidden):
    script = f"import sys; import {module}; assert not any(name.startswith({forbidden!r}) for name in sys.modules)"
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).parents[1],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr


@pytest.fixture
def experiment_inputs(monkeypatch):
    from codeguard_evals.securityeval.dataset import SecurityEvalCase
    from codeguard_evals.cyberseceval.dataset import CyberSecEvalCase
    from tests.conftest import ORIGINAL_SOURCE

    security = importlib.import_module("codeguard_evals.securityeval.securityeval")
    cyber = importlib.import_module("codeguard_evals.cyberseceval.cyberseceval")
    monkeypatch.setattr(security, "load_securityeval_cases", lambda: [
        SecurityEvalCase("CWE-020_fixture_1.py", "CWE-20", ORIGINAL_SOURCE),
    ])
    monkeypatch.setattr(cyber, "load_cases", lambda: [
        CyberSecEvalCase(1, language, "CWE-20", "Write a function that returns one.")
        for language in ("c", "cpp")
    ])
    executions = []

    @agent
    def fixture_skill_agent() -> Agent:
        async def run(state: AgentState) -> AgentState:
            executions.append("generate")
            return state
        return run

    monkeypatch.setattr(harness, "codex_cli", lambda **kwargs: fixture_skill_agent())
    return executions


@pytest.mark.parametrize("benchmark", ["securityeval", "cyberseceval"])
def test_generic_skill_selection_uses_native_inspect_arguments(benchmark, catalog_skill, experiment_inputs):
    from inspect_ai._cli.util import parse_cli_config
    from inspect_ai._eval.loader import load_tasks
    from codeguard_evals.protocol import SECURITY_REMINDER
    catalog_skill("selected")
    catalog_skill("not-selected")
    options = [f"benchmark={benchmark}", "variant=selected", "agent_turn_limit=3"]
    if benchmark == "cyberseceval":
        options.append("languages=c,cpp")
    path = "codeguard_evals/experiments.py"
    tasks = load_tasks([f"{path}@skill"], task_args=parse_cli_config(options, None))
    assert len(tasks) == 1
    selected = tasks[0]
    assert selected.metadata["skill"]["id"] == "selected"
    assert selected.metadata["generation_limits"]["turns"] == 3
    options.remove("variant=selected")
    baseline, = load_tasks([f"{path}@baseline"], task_args=parse_cli_config(options, None))
    secure, = load_tasks([f"{path}@secure_prompt"], task_args=parse_cli_config(options, None))
    assert baseline.metadata.get("skill") is None and secure.metadata.get("skill") is None
    assert [sample.input for sample in selected.dataset] == [sample.input for sample in baseline.dataset]
    assert all(SECURITY_REMINDER in sample.input for sample in secure.dataset)
    assert not any(SECURITY_REMINDER in sample.input for sample in baseline.dataset)
    assert len(selected.setup) == len(baseline.setup) + 1 == len(secure.setup) + 1
    assert not experiment_inputs


@pytest.mark.parametrize("changed_file", ["SKILL.md", "references/REFERENCE.md"])
def test_selected_snapshot_controls_native_resume(tmp_path, monkeypatch, catalog_skill, experiment_inputs, changed_file):
    import json
    from types import SimpleNamespace
    from inspect_ai._util.error import PrerequisiteError
    from codeguard_evals import skill_catalog
    from codeguard_evals.skill_files import skill_content_sha256
    from codeguard_evals.experiments import skill
    from tests.conftest import SAFE_SOURCE

    path, snapshot = catalog_skill("selected", guidance=True)

    class Installer:
        async def exec(self, *args, **kwargs):
            return SimpleNamespace(success=True)

    monkeypatch.setattr(harness, "sandbox", lambda _: Installer())
    security = importlib.import_module("codeguard_evals.securityeval.securityeval")
    monkeypatch.setattr(security, "sandbox", lambda _: Installer())

    async def export(filename):
        return ExportedSolution(SAFE_SOURCE.encode(), None)

    monkeypatch.setattr(artifacts, "export_solution", export)

    def task():
        selected = skill("securityeval", "selected")
        selected.sandbox = None
        return selected

    options = dict(model="mockllm/model", log_dir=str(tmp_path / "generation"),
                   display="none", log_realtime=False, ctl_server=False,
                   retry_attempts=0, retry_immediate=False)
    assert eval_set([task()], **options)[0]
    catalog_skill("unrelated")
    assert eval_set([task()], **options)[0]
    assert len(experiment_inputs) == 1
    snapshot[changed_file] += b"Changed guidance.\n"
    (path / changed_file).write_bytes(snapshot[changed_file])
    with pytest.raises(ValueError, match="pinned fingerprint"):
        task()
    entries = json.loads(skill_catalog.CATALOG_PATH.read_text())
    entries["selected"]["content_sha256"] = skill_content_sha256(snapshot)
    skill_catalog.CATALOG_PATH.write_text(json.dumps(entries))
    with pytest.raises(PrerequisiteError, match="not associated with a task"):
        eval_set([task()], **options)
    assert len(experiment_inputs) == 1


@pytest.fixture
def matrix_definition(tmp_path, catalog_skill):
    import json

    catalog_skill("first")
    catalog_skill("second", guidance=True)
    definition = {
        "defaults": {
            "models": ["mockllm/model-a", "mockllm/model-b"],
            "skills": "all", "baseline": True,
        },
        "benchmarks": "all",
        "execution": {"retry_attempts": 0, "display": "none"},
    }
    path = tmp_path / "matrix.json"

    def save():
        path.write_text(json.dumps(definition))
        return path

    return definition, save


def test_matrix_preview_applies_benchmark_overrides_without_running(
    tmp_path, monkeypatch, capsys, matrix_definition, experiment_inputs,
):
    from codeguard_evals import experiments

    definition, save = matrix_definition
    definition["benchmarks"] = {
        "securityeval": {"secure_prompt": True},
        "cyberseceval": {
            "models": ["mockllm/model-b"], "skills": [], "languages": ["cpp"],
            "epochs": 2, "limit": 1,
        },
    }
    monkeypatch.setattr(experiments, "eval_set", lambda *a, **k: pytest.fail("generation started"))
    monkeypatch.setattr("inspect_ai.model.get_model", lambda *a, **k: pytest.fail("model initialized"))
    directory = tmp_path / "not-created"
    assert experiments.main(["--matrix", str(save()), "--log-dir", str(directory), "--dry-run"]) == 0
    output = capsys.readouterr().out
    assert "9 evaluations; 10 sample attempts before retries" in output
    assert "securityeval | mockllm/model-a | codex-cli | secure_prompt | 1 samples" in output
    assert "cyberseceval | mockllm/model-a" not in output
    assert not directory.exists() and not experiment_inputs


@pytest.mark.parametrize("change", [
    {"defaults": {"models": []}},
    {"defaults": {"models": ["mockllm/model-a", "mockllm/model-a"]}},
    {"defaults": {"models": ["mockllm/model-a"], "skills": []}},
    {"defaults": {"models": ["mockllm/model-a"], "skills": ["unknown"]}},
    {"defaults": {"models": ["mockllm/model-a"], "agents": ["claude-code"]}},
    {"defaults": {"models": ["mockllm/model-a"], "epochs": True}},
    {"benchmarks": {}},
    {"benchmarks": {"unknown": {}}},
    {"benchmarks": {"securityeval": {"languages": ["cpp"]}}},
    {"execution": {"sandbox": "unsafe", "api_key": "PRIVATE_CONFIG_VALUE"}},
])
def test_invalid_matrix_launches_nothing(
    tmp_path, monkeypatch, capsys, matrix_definition, experiment_inputs, change,
):
    from codeguard_evals import experiments

    definition, save = matrix_definition
    definition.update(change)
    monkeypatch.setattr(experiments, "eval_set", lambda *a, **k: pytest.fail("generation started"))
    directory = tmp_path / "not-created"
    assert experiments.main(["--matrix", str(save()), "--log-dir", str(directory)]) == 1
    assert not directory.exists() and not experiment_inputs
    assert "PRIVATE_CONFIG_VALUE" not in capsys.readouterr().err


def test_matrix_settings_errors_name_the_benchmark(tmp_path, capsys, matrix_definition, experiment_inputs):
    from codeguard_evals import experiments

    definition, save = matrix_definition
    definition["benchmarks"] = {"securityeval": {}, "cyberseceval": {"epochs": 0}}
    directory = tmp_path / "not-created"
    assert experiments.main(["--matrix", str(save()), "--log-dir", str(directory), "--dry-run"]) == 1
    errors = capsys.readouterr().err.splitlines()
    assert len(errors) == 1 and errors[0].startswith("Invalid matrix cyberseceval.epochs:")


@pytest.mark.parametrize("problem", ["shared", "occupied", "file"])
def test_matrix_preview_applies_execution_directory_rules(
    tmp_path, monkeypatch, capsys, matrix_definition, experiment_inputs, problem,
):
    from codeguard_evals import experiments

    directory = tmp_path / "run"
    if problem == "file":
        directory.write_text("not a directory")
    else:
        directory.mkdir(mode=0o755 if problem == "shared" else 0o700)
        directory.chmod(0o755 if problem == "shared" else 0o700)
        if problem == "occupied":
            (directory / "notes.txt").write_text("unrelated")
    before = sorted(directory.iterdir()) if directory.is_dir() else None
    monkeypatch.setattr(experiments, "eval_set", lambda *a, **k: pytest.fail("generation started"))
    _, save = matrix_definition
    for dry_run in (["--dry-run"], []):
        args = ["--matrix", str(save()), "--log-dir", str(directory), *dry_run]
        assert experiments.main(args) == 1
        expected = {"shared": "chmod 700", "occupied": "resolved.json", "file": "not a file"}[problem]
        assert expected in capsys.readouterr().err
    assert (sorted(directory.iterdir()) if directory.is_dir() else None) == before
    assert not experiment_inputs


@pytest.mark.parametrize("generation_first", [False, True])
def test_matrix_runs_both_models_and_benchmarks_and_resumes_frozen_selection(
    tmp_path, monkeypatch, capsys, matrix_definition, catalog_skill, experiment_inputs, scanner, generation_first,
):
    import json
    from types import SimpleNamespace
    from codeguard_evals import experiments
    from codeguard_evals.graders import icd
    from tests.conftest import SAFE_SOURCE

    class Installer:
        async def exec(self, *args, **kwargs):
            return SimpleNamespace(success=True)

    monkeypatch.setattr(harness, "sandbox", lambda _: Installer())
    security = importlib.import_module("codeguard_evals.securityeval.securityeval")
    monkeypatch.setattr(security, "sandbox", lambda _: Installer())

    async def export(filename):
        source = SAFE_SOURCE if filename.endswith(".py") else "int f(void) { return 1; }\n"
        return ExportedSolution(source.encode(), None)

    async def scan(sources, **kwargs):
        return [icd.IcdScan(
            language=language, source_sha256=hashlib.sha256(source.encode()).hexdigest(),
            complete=True, reason=None, analyzers=list(icd.expected_analyzers(language)), findings=[],
        ) for source, language in sources]

    monkeypatch.setattr(artifacts, "export_solution", export)
    monkeypatch.setattr(icd, "load_detector", lambda: None)
    monkeypatch.setattr(icd, "scan_sources", scan)
    native_eval_set = experiments.eval_set

    def run(tasks, **kwargs):
        for selected in tasks:
            selected.sandbox = None
        return native_eval_set(tasks, log_realtime=False, ctl_server=False, **kwargs)

    monkeypatch.setattr(experiments, "eval_set", run)
    definition, save = matrix_definition
    directory = tmp_path / "run"
    args = ["--matrix", str(save()), "--log-dir", str(directory)]
    assert experiments.main([*args, *(["--stage", "generation"] if generation_first else [])]) == 0
    assert len(experiment_inputs) == 18
    original = (directory / "resolved.json").read_bytes()
    if generation_first:
        assert not (directory / "scored").exists()
        assert all(not calls for calls in scanner)
        # Scanning needs only the run directory: remove the matrix and catalog it was built from.
        with monkeypatch.context() as scan_only:
            from codeguard_evals import skill_catalog
            save().unlink()
            scan_only.setattr(skill_catalog, "CATALOG_PATH", tmp_path / "missing-catalog.json")
            scan_only.setattr(experiments, "eval_set", lambda *a, **k: pytest.fail("generation started"))
            scan_args = ["--stage", "scan", "--log-dir", str(directory)]
            # Inspect writes a log only once its task starts, so a run that never began blocks the scan.
            held = sorted((directory / "generation" / "securityeval").glob("*.eval"))[0]
            aside = tmp_path / held.name
            held.rename(aside)
            capsys.readouterr()
            assert experiments.main([*scan_args, "--dry-run"]) == 1
            assert "securityeval: missing generation logs for mockllm/model-" in capsys.readouterr().err
            aside.rename(held)
            assert experiments.main([*scan_args, "--dry-run"]) == 0
            assert not (directory / "scored").exists()
            assert all(not calls for calls in scanner)
            # A matrix file would look applied, so scan-only rejects it before reading anything.
            with pytest.raises(SystemExit) as rejected:
                experiments.main([*scan_args, "--matrix", str(tmp_path / "unavailable.json")])
            assert rejected.value.code == 2
            assert experiments.main(scan_args) == 0
        save()
        assert (directory / "resolved.json").read_bytes() == original
        assert len(experiment_inputs) == 18
    for benchmark in ("securityeval", "cyberseceval"):
        logs = list((directory / "generation" / benchmark).glob("*.eval"))
        scored = list((directory / "scored" / benchmark).glob("*.eval"))
        assert len(logs) == len(scored) == 6
        assert {read_eval_log(p, header_only=True).eval.model for p in logs} == {
            "mockllm/model-a", "mockllm/model-b",
        }
        assert all(read_eval_log(p).samples[0].scores for p in scored)
    catalog_skill("new-entry")
    assert experiments.main(args) == 0
    assert len(experiment_inputs) == 18
    assert (directory / "resolved.json").read_bytes() == original
    assert json.loads(original)["benchmarks"]["securityeval"]["skills"] == ["first", "second"]
    definition["defaults"]["epochs"] = 2
    save()
    assert experiments.main(args) == 1
    assert len(experiment_inputs) == 18
    definition["defaults"]["epochs"] = 1
    definition["execution"]["max_samples"] = 2
    save()
    assert experiments.main(args) == 1
    assert len(experiment_inputs) == 18


def test_matrix_scans_only_completed_benchmarks_and_reports_scan_failure(
    tmp_path, monkeypatch, matrix_definition, experiment_inputs,
):
    from types import SimpleNamespace
    import inspect_ai.log
    from codeguard_evals import experiments
    batch = importlib.import_module("codeguard_evals.scan")
    generation, scans = [], []

    def run(tasks, **options):
        generation.append(options)
        return tasks[0].metadata["benchmark"] != "SecurityEval", []

    def scan(argv):
        scans.append(argv)
        return 1

    monkeypatch.setattr(experiments, "eval_set", run)
    monkeypatch.setattr(batch, "main", scan)
    # The fake generation writes no files, so present the completed benchmark's six logs.
    logged = [SimpleNamespace(eval=SimpleNamespace(model=model, metadata=metadata))
              for model in ("mockllm/model-a", "mockllm/model-b")
              for metadata in ({"condition": "baseline"}, {"skill": {"id": "first"}}, {"skill": {"id": "second"}})]
    monkeypatch.setattr(batch, "latest_generation_logs",
                        lambda source: [source / f"{index}.eval" for index in range(len(logged))])
    monkeypatch.setattr(inspect_ai.log, "read_eval_log", lambda path, **k: logged[int(Path(path).stem)])
    _, save = matrix_definition
    assert experiments.main(["--matrix", str(save()), "--log-dir", str(tmp_path / "run")]) == 1
    assert len(generation) == 2 and len(scans) == 1
    assert scans[0][0].endswith("/cyberseceval")
    assert all(item["model"] == ["mockllm/model-a", "mockllm/model-b"] for item in generation)
    assert not experiment_inputs


def test_matrix_cancellation_preserves_selection_and_starts_no_scan(
    tmp_path, monkeypatch, matrix_definition, experiment_inputs,
):
    from codeguard_evals import experiments
    batch = importlib.import_module("codeguard_evals.scan")

    def stop(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(experiments, "eval_set", stop)
    monkeypatch.setattr(batch, "main", lambda *a: pytest.fail("scan started after cancellation"))
    _, save = matrix_definition
    directory = tmp_path / "run"
    assert experiments.main(["--matrix", str(save()), "--log-dir", str(directory)]) == 130
    assert (directory / "resolved.json").is_file() and not experiment_inputs


@pytest.mark.parametrize("stage", ["all", "scan"])
@pytest.mark.parametrize("saved", [
    None, [], {"benchmarks": {"securityeval": None}, "skills": {}},
    {"benchmarks": {"../outside": {}}, "skills": {}, "execution": {}},
    {"benchmarks": {}, "skills": {}, "execution": {}},
    # Scan-only plans from saved settings, so partial or mistyped ones are refused.
    {"benchmarks": {"securityeval": {"models": ["mockllm/model"], "baseline": True}}, "skills": {}, "execution": {}},
    {"benchmarks": {"securityeval": {"models": "mockllm/model"}}, "skills": {}, "execution": {}},
])
def test_matrix_rejects_invalid_saved_selections(
    tmp_path, monkeypatch, matrix_definition, experiment_inputs, saved, stage,
):
    import json
    from codeguard_evals import experiments

    directory = tmp_path / "run"
    directory.mkdir(mode=0o700)
    (directory / "resolved.json").write_text(json.dumps(saved))
    monkeypatch.setattr(experiments, "eval_set", lambda *a, **k: pytest.fail("generation started"))
    _, save = matrix_definition
    matrix = ["--matrix", str(save())] if stage == "all" else []
    assert experiments.main([*matrix, "--log-dir", str(directory), "--stage", stage, "--dry-run"]) == 1
    assert not experiment_inputs


def test_matrix_scan_preview_reports_every_benchmark(
    tmp_path, monkeypatch, capsys, matrix_definition, experiment_inputs,
):
    from codeguard_evals import experiments, scan

    # Generation saved its selection but was interrupted before writing any logs.
    monkeypatch.setattr(experiments, "eval_set", lambda *a, **k: (False, []))
    _, save = matrix_definition
    directory = tmp_path / "run"
    assert experiments.main(["--matrix", str(save()), "--log-dir", str(directory), "--stage", "generation"]) == 1
    monkeypatch.setattr(scan, "main", lambda *a, **k: pytest.fail("scan started"))
    capsys.readouterr()
    assert experiments.main(["--stage", "scan", "--log-dir", str(directory), "--dry-run"]) == 1
    errors = capsys.readouterr().err
    assert "securityeval:" in errors and "cyberseceval:" in errors


def test_matrix_scan_requires_saved_selection_without_creating_a_run(tmp_path, monkeypatch, capsys):
    from codeguard_evals import experiments

    monkeypatch.setattr(experiments, "eval_set", lambda *a, **k: pytest.fail("generation started"))
    directory = tmp_path / "not-created"
    assert experiments.main(["--stage", "scan", "--log-dir", str(directory)]) == 1
    assert "run generation first" in capsys.readouterr().err
    assert not directory.exists()


@pytest.mark.parametrize("extension", ["json", "yaml"])
def test_matrix_freezes_prices_before_resuming_incomplete_generation(
    tmp_path, monkeypatch, matrix_definition, experiment_inputs, extension,
):
    import json
    import yaml
    from codeguard_evals import experiments
    from inspect_ai.model import ModelCost

    definition, save = matrix_definition
    definition["benchmarks"] = {"securityeval": {}}
    definition["execution"]["model_cost_config"] = f"prices.{extension}"
    prices = tmp_path / f"prices.{extension}"
    rates = {name: dict(input=1, output=2, input_cache_read=0.1, input_cache_write=1)
             for name in definition["defaults"]["models"]}
    prices.write_text(json.dumps(rates) if extension == "json" else yaml.safe_dump(rates))
    calls = []

    def incomplete(tasks, **options):
        calls.append(options["model_cost_config"])
        return False, []

    monkeypatch.setattr(experiments, "eval_set", incomplete)
    directory = tmp_path / "run"
    args = ["--matrix", str(save()), "--log-dir", str(directory)]
    assert experiments.main(args) == 1
    assert len(calls) == 1
    assert all(isinstance(cost, ModelCost) for cost in calls[0].values())
    receipt = (directory / "resolved.json").read_bytes()
    assert json.loads(receipt)["execution"]["model_cost_config"]["mockllm/model-a"]["output"] == 2
    # Native execution receives frozen data even if the source file disappears.
    prices.unlink()
    assert calls[0]["mockllm/model-a"].output == 2
    prices.write_text(json.dumps(rates) if extension == "json" else yaml.safe_dump(rates))
    assert experiments.main(args) == 1
    assert len(calls) == 2
    rates["mockllm/model-a"]["output"] = 200
    prices.write_text(json.dumps(rates) if extension == "json" else yaml.safe_dump(rates))
    assert experiments.main(args) == 1
    assert len(calls) == 2
    assert (directory / "resolved.json").read_bytes() == receipt
    assert not experiment_inputs


@pytest.mark.parametrize("rate", [-1, float("nan")])
def test_matrix_rejects_invalid_prices_before_generation(
    tmp_path, monkeypatch, matrix_definition, experiment_inputs, rate,
):
    import yaml
    from codeguard_evals import experiments

    definition, save = matrix_definition
    definition["execution"]["model_cost_config"] = "prices.yaml"
    (tmp_path / "prices.yaml").write_text(yaml.safe_dump({
        "mockllm/model-a": dict(input=rate, output=2, input_cache_read=0, input_cache_write=0),
    }))
    monkeypatch.setattr(experiments, "eval_set", lambda *a, **k: pytest.fail("generation started"))
    directory = tmp_path / "not-created"
    assert experiments.main(["--matrix", str(save()), "--log-dir", str(directory), "--dry-run"]) == 1
    assert not directory.exists() and not experiment_inputs


@pytest.mark.parametrize("debug", [False, True])
def test_matrix_startup_failure_offers_opt_in_diagnostics(
    tmp_path, monkeypatch, capsys, matrix_definition, experiment_inputs, debug,
):
    from inspect_ai._util.error import PrerequisiteError
    from codeguard_evals import experiments

    def fail(*args, **kwargs):
        raise PrerequisiteError("FIXTURE_API_KEY missing; PRIVATE_PROVIDER_DETAIL")

    monkeypatch.setattr(experiments, "eval_set", fail)
    _, save = matrix_definition
    args = ["--matrix", str(save()), "--log-dir", str(tmp_path / "run")]
    if debug:
        with pytest.raises(PrerequisiteError, match="FIXTURE_API_KEY"):
            experiments.main([*args, "--debug"])
    else:
        assert experiments.main(args) == 1
        message = capsys.readouterr().err
        assert "PrerequisiteError" in message and "--debug" in message
        assert "PRIVATE_PROVIDER_DETAIL" not in message
    assert not experiment_inputs
