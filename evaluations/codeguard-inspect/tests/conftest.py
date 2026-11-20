"""Shared test data and fixtures.

Nearly every test in this suite is built on one pair: a SecurityEval scaffold
with an unfilled function body, and a solution that fills it. Keeping them here
means a change to the shape of a scaffold does not have to be mirrored across
three modules.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

import pytest

from inspect_ai.model import ChatMessage, ModelName, ModelOutput, ModelUsage
from inspect_ai.scorer import Target
from inspect_ai.solver import TaskState

from codeguard_evals.sandbox_protocol import (
    CODEX_HOME_DIR,
    CODEX_SKILLS_DIR,
    SANDBOX_WORKDIR,
)
from codeguard_evals.securityeval.protocol import TASK_PROMPT
from codeguard_evals.skill_files import CODEGUARD_SKILL_NAME, load_skill_files

if TYPE_CHECKING:
    from codeguard_evals.graders.semgrep_artifacts import SemgrepLock


def semgrep_lock_for_files(files: dict[str, bytes]) -> SemgrepLock:
    """Build a valid Semgrep lock for harmless, explicitly supplied test files."""
    from codeguard_evals.graders.semgrep_artifacts import SEMGREP_LOCK, SemgrepLock

    digest = hashlib.sha256()
    pins = {}
    for name, raw in sorted(files.items()):
        encoded = name.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
        pins[name] = {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    value = SEMGREP_LOCK.model_dump(mode="json")
    value["rules"].update(tree_sha256=digest.hexdigest(), files=pins)
    return SemgrepLock.model_validate(value)


@pytest.fixture(autouse=True)
def no_docker_or_tokenizer_for_unit_tests(request, monkeypatch, tmp_path):
    """Keep unit tests independent of Docker and tokenizer initialization."""
    if request.node.get_closest_marker("docker") is None:
        monkeypatch.setenv("DOCKER_HOST", f"unix://{tmp_path / 'docker-disabled.sock'}")
        # DOCKER_CONTEXT overrides DOCKER_HOST. An empty value also prevents
        # ordinary dotenv loading from reintroducing a context from .env.
        monkeypatch.setenv("DOCKER_CONTEXT", "")
        monkeypatch.delenv("CODEGUARD_SCANNER_CPUS", raising=False)

        def reject_tokenizer(*_args, **_kwargs):
            pytest.fail("Unit tests must supply explicit mock token usage.", pytrace=False)

        monkeypatch.setattr("tiktoken.get_encoding", reject_tokenizer)


# A scaffold as the dataset supplies it: signature present, body unfilled.
ORIGINAL_SOURCE = "def generated(command):\n    pass\n"
# The same scaffold with a real implementation.
SAFE_SOURCE = "def generated(command):\n    return str(command)\n"
# A parse-valid no-op body used to verify that validation does not infer intent.
STUB_SOURCE = "def generated(command):\n    return None\n"

# The pinned CodeGuard snapshot that the benchmark packages' CodeGuard tasks install.
CODEGUARD_SNAPSHOT_DIR: Final = Path(__file__).parents[1] / "skill_snapshots/codeguard-1.5.0/codeguard"
CODEGUARD_SKILL_DIR: Final = f"{CODEX_SKILLS_DIR}/{CODEGUARD_SKILL_NAME}"


def codeguard_files() -> dict[str, bytes]:
    return load_skill_files(CODEGUARD_SNAPSHOT_DIR)


CASE_ID = "CWE-078_author_1.py"
SAMPLE_CWE = "CWE-78"
SAMPLE_ID = f"static_safety/baseline/{CASE_ID}"

TMPFS_REQUIRED_OPTIONS: Final[Mapping[str, frozenset[str]]] = MappingProxyType(
    {
        SANDBOX_WORKDIR: frozenset(
            {
                "rw",
                "nosuid",
                "nodev",
                "noexec",
                "size=32m",
                "uid=65532",
                "gid=0",
                "mode=0730",
            }
        ),
        CODEX_HOME_DIR: frozenset(
            {
                "rw",
                "nosuid",
                "nodev",
                "noexec",
                "size=32m",
                "uid=65532",
                "gid=0",
                "mode=0730",
            }
        ),
        CODEX_SKILLS_DIR: frozenset(
            {
                "rw",
                "nosuid",
                "nodev",
                "noexec",
                "size=2m",
                "uid=0",
                "gid=0",
                "mode=0755",
            }
        ),
        "/tmp": frozenset(
            {
                "rw",
                "nosuid",
                "nodev",
                "noexec",
                "size=16m",
                "uid=0",
                "gid=0",
                "mode=1777",
            }
        ),
        "/var/tmp": frozenset(
            {
                "rw",
                "nosuid",
                "nodev",
                "exec",
                "size=768m",
                "uid=0",
                "gid=0",
                "mode=1777",
            }
        ),
    }
)


def task_state(
    *,
    sample_id: str = SAMPLE_ID,
    target: str = ORIGINAL_SOURCE,
    input_text: str | list[ChatMessage] = TASK_PROMPT,
    output: ModelOutput | None = None,
    messages: list[ChatMessage] | None = None,
    metadata: dict[str, object] | None = None,
) -> TaskState:
    """Build the common SecurityEval state used by solver and scorer tests."""
    return TaskState(
        model=ModelName("mockllm/model"),
        sample_id=sample_id,
        epoch=1,
        input=input_text,
        target=Target(target),
        messages=[] if messages is None else messages,
        output=(
            ModelOutput.from_content("mockllm/model", "done")
            if output is None
            else output
        ),
        metadata=(
            {
                "case_id": CASE_ID,
                "cwe": SAMPLE_CWE,
                "condition": "baseline",
            }
            if metadata is None
            else metadata
        ),
    )


def assert_tmpfs_policy(
    tmpfs: Mapping[str, str],
    expected: Mapping[str, frozenset[str]] = TMPFS_REQUIRED_OPTIONS,
) -> None:
    """Assert the writable mounts shared by static and live container tests."""
    assert set(tmpfs) == set(expected)
    for path, expected_options in expected.items():
        observed = set(tmpfs[path].split(","))
        assert observed == expected_options, path


class FakeSandbox:
    """Minimal queued sandbox used by solver and exporter tests."""

    def __init__(self, *results: object) -> None:
        self._results = iter(results)
        self.calls: list[tuple[list[str], dict[str, object]]] = []

    async def exec(self, command: list[str], **arguments: object) -> object:
        self.calls.append((command, arguments))
        result = next(self._results)
        if isinstance(result, BaseException):
            raise result
        return result


def compose_config(path):
    """Read our scalar-only extends overrides; reject unsupported Compose merges."""
    import yaml

    config = yaml.safe_load(path.read_text())
    services = {}
    for name, raw in config["services"].items():
        service = dict(raw)
        extends = service.pop("extends", None)
        if extends:
            base = compose_config(path.parent / extends["file"])["services"][
                extends["service"]
            ]
            if any(
                isinstance(base[key], (dict, list)) or isinstance(service[key], (dict, list))
                for key in base.keys() & service.keys()
            ):
                raise ValueError(
                    "Nested Compose overrides require validation with Docker Compose"
                )
            service = {**base, **service}
        services[name] = service
    return {"services": services}


@pytest.fixture
def offline_batch(monkeypatch):
    """Exercise the real batch workflow with test scanners and no Docker."""
    import asyncio
    import importlib
    from pathlib import Path

    from inspect_ai.log import read_eval_log

    from codeguard_evals.securityeval import scorers
    import codeguard_evals.graders.icd as icd

    batch = importlib.import_module("codeguard_evals.scan")
    native_eval = batch.eval_async

    async def launch(task, **kwargs):
        task.sandbox = None
        return await native_eval(task, **kwargs)

    monkeypatch.setattr(batch, "eval_async", launch)
    monkeypatch.setattr(icd, "load_detector", lambda: None)
    monkeypatch.setattr(scorers, "load_default_locked_rules_directory", lambda: None)

    def scan(log, output_dir):
        output = asyncio.run(batch.scan_log(Path(log.location), output_dir))
        return read_eval_log(output)

    return scan

def eval_mock_task(task, log_dir, **options):
    """Run one fixture task with Inspect's mock model and no viewer or control server."""
    from inspect_ai import eval as inspect_eval

    def response(*_) -> ModelOutput:
        content = "Default output from mockllm/model"
        output = ModelOutput.from_content("mockllm/model", content)
        output.usage = ModelUsage(
            input_tokens=1, output_tokens=len(content), total_tokens=1 + len(content)
        )
        return output

    # Explicit fixture usage keeps budget tests independent of tokenizer downloads.
    options["model_args"] = {"custom_outputs": response, **(options.get("model_args") or {})}
    return inspect_eval(
        task,
        model="mockllm/model",
        display="none",
        log_dir=str(log_dir),
        log_realtime=False,
        ctl_server=False,
        **options,
    )[0]


def generation_log(tmp_path, count=3):
    """Write a real Inspect generation log with deterministic saved Python source."""
    from pathlib import Path
    from inspect_ai import Task
    from inspect_ai.dataset import MemoryDataset, Sample
    from inspect_ai.solver import solver
    from codeguard_evals.output_artifact import SAVED_OUTPUT_KEY, SavedOutput
    from codeguard_evals.protocol import EVALUATION_VERSION

    @solver
    def record():
        async def solve(state, generate):
            state.store.set(
                SAVED_OUTPUT_KEY,
                SavedOutput(
                    evaluation_version=EVALUATION_VERSION,
                    source=f"def generated(command):\n    return {state.metadata['number']}\n",
                    capture_error=None,
                ).model_dump(mode="json"),
            )
            # The real sample metadata must remain the benchmark's strict schema.
            del state.metadata["number"]
            return state

        return solve

    samples = [
        Sample(
            id=f"static_safety/baseline/CWE-078_fixture_{n}.py",
            input=TASK_PROMPT,
            target=ORIGINAL_SOURCE,
            metadata={
                "case_id": f"CWE-078_fixture_{n}.py",
                "condition": "baseline",
                "cwe": "CWE-78",
                "number": n,
            },
        )
        for n in range(1, count + 1)
    ]
    log = eval_mock_task(
        Task(
            name="fixture_generation",
            dataset=MemoryDataset(samples),
            solver=record(),
            version=EVALUATION_VERSION,
            metadata={"benchmark": "SecurityEval", "phase": "generation", "condition": "baseline"},
        ),
        tmp_path / "generation",
    )
    assert log.status == "success"
    return Path(log.location)


@pytest.fixture
def scanner(monkeypatch, tmp_path):
    """Record real batch scheduling while substituting an in-process Semgrep scan."""
    import importlib
    import codeguard_evals.graders.semgrep as semgrep
    from codeguard_evals.securityeval import scorers

    batch = importlib.import_module("codeguard_evals.scan")
    monkeypatch.setenv("INSPECT_TRACE_FILE", str(tmp_path / "trace.log"))
    calls, launches, preparations = [], [], []
    native_eval = batch.eval_async

    async def launch(task, **kwargs):
        launches.append(task)
        task.sandbox = None
        return await native_eval(task, **kwargs)

    async def scan(sources):
        calls.extend(sources)
        return [() for _ in sources]

    monkeypatch.setattr(batch, "eval_async", launch)
    monkeypatch.setattr(semgrep, "scan_sources", scan)
    monkeypatch.setattr(
        scorers,
        "load_default_locked_rules_directory",
        lambda: preparations.append(True),
    )
    return calls, launches, preparations


@pytest.fixture
def catalog_skill(tmp_path, monkeypatch):
    """Write small reviewed-snapshot inputs under a temporary repository root."""
    import json
    from codeguard_evals import skill_catalog
    from codeguard_evals.skill_files import skill_content_sha256

    root = tmp_path / "repository"
    root.mkdir()
    catalog = root / "catalog.json"
    entries = {}
    monkeypatch.setattr(skill_catalog, "PROJECT_ROOT", root)
    monkeypatch.setattr(skill_catalog, "CATALOG_PATH", catalog)

    def add(variant, *, name="example-security", guidance=False, body="Prioritize security.\n"):
        directory = root / "skills" / variant / name
        directory.mkdir(parents=True, exist_ok=True)
        snapshot = {"SKILL.md": (
            f"---\nname: {name}\ndescription: Secure coding guidance.\n---\n\n{body}"
        ).encode()}
        if guidance:
            snapshot["references/REFERENCE.md"] = b"Review the trust boundary.\n"
        for path, content in snapshot.items():
            destination = directory / path
            destination.parent.mkdir(exist_ok=True)
            destination.write_bytes(content)
        entries[variant] = {
            "label": "Example security", "path": directory.relative_to(root).as_posix(),
            "content_sha256": skill_content_sha256(snapshot),
        }
        catalog.write_text(json.dumps(entries))
        return directory, snapshot

    return add
