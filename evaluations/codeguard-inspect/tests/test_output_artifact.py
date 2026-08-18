from __future__ import annotations

import asyncio
import copy
import math
import os
import subprocess
import sys
from pathlib import Path
from typing import cast

import pytest
from inspect_ai import Task, eval as inspect_eval
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.log import read_eval_log
from inspect_ai.model import (
    ChatMessageAssistant,
    Logprob,
    Logprobs,
    ModelFallback,
    ModelOutput,
    ModelUsage,
    StopDetails,
)
from inspect_ai.scorer import Target
from inspect_ai.solver import Generate, Solver, TaskState, solver

import codeguard_evals.output_artifact as artifact_module
from codeguard_evals.output_artifact import (
    GENERATION_LIMIT_KEY,
    SAVED_OUTPUT_KEY,
    SavedOutput,
    capture_generated_output,
    load_saved_output,
)
from codeguard_evals.sandbox_client import (
    BenchmarkInfrastructureError,
    ExportedSolution,
)
from codeguard_evals.sandbox_protocol import MAX_PYTHON_SOURCE_BYTES
from codeguard_evals.scorers import static_safety_scorer
from codeguard_evals.securityeval.protocol import (
    EVALUATION_VERSION,
    TASK_PROMPT,
    securityeval_task_name,
)
from tests.conftest import (
    CASE_ID,
    ORIGINAL_SOURCE,
    SAFE_SOURCE,
    SAMPLE_CWE,
    SAMPLE_ID,
    STUB_SOURCE,
    task_state,
)


def _state(sample_id: str = SAMPLE_ID) -> TaskState:
    output = ModelOutput.from_content(
        "mockllm/model",
        "agent narration",
        stop_reason="max_tokens",
        stop_details=StopDetails(
            type="length",
            explanation="The provider reached its output limit.",
        ),
    )
    output.choices[0].logprobs = Logprobs(
        content=[Logprob(token="agent", logprob=-0.25)]
    )
    output.usage = ModelUsage(input_tokens=11, output_tokens=7, total_tokens=18)
    output.fallback = ModelFallback(
        model="mockllm/model",
        fallback_model="mockllm/fallback",
        count=2,
    )
    output.time = 1.25
    output.metadata = {
        "provider.request_id": "request-1",
        "provider.tags": ["benchmark"],
    }
    return task_state(
        sample_id=sample_id,
        messages=[
            ChatMessageAssistant(
                content="agent narration",
                model="mockllm/model",
            )
        ],
        output=output,
        metadata={
            "case_id": CASE_ID,
            "condition": "baseline",
            "cwe": SAMPLE_CWE,
        },
    )


def _export(
    source: bytes | None = SAFE_SOURCE.encode(),
    *,
    reason: str | None = None,
) -> ExportedSolution:
    if source is None:
        return ExportedSolution(None, reason or "missing output")
    return ExportedSolution(source, reason)


def _capture(
    monkeypatch: pytest.MonkeyPatch,
    exported: ExportedSolution,
    *,
    state: TaskState | None = None,
) -> TaskState:
    async def capture() -> ExportedSolution:
        return exported

    monkeypatch.setattr(artifact_module, "export_solution", capture)
    return asyncio.run(
        capture_generated_output()(
            _state() if state is None else state,
            cast(Generate, None),
        )
    )


def _stored_payload(state: TaskState) -> dict[str, object]:
    value = state.store.get(SAVED_OUTPUT_KEY)
    assert isinstance(value, dict)
    return value


def test_capture_preserves_model_output_and_stores_validated_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _state()
    original_output = state.output.model_copy(deep=True)
    original_messages = copy.deepcopy(state.messages)

    result = _capture(monkeypatch, _export(), state=state)

    assert result.output == original_output
    assert result.messages == original_messages
    assert result.output.metadata == {
        "provider.request_id": "request-1",
        "provider.tags": ["benchmark"],
    }
    assert load_saved_output(result) == SavedOutput(
        evaluation_version=EVALUATION_VERSION,
        source=SAFE_SOURCE,
        capture_error=None,
    )

    with pytest.raises(BenchmarkInfrastructureError, match="already exists"):
        asyncio.run(
            capture_generated_output()(
                result,
                cast(Generate, None),
            )
        )


@pytest.mark.parametrize(
    ("source", "reason", "expected_source", "expected_answer", "explanation"),
    [
        (None, "missing output", None, None, "missing output"),
        (b"", None, "", "", "empty solution"),
    ],
)
def test_missing_and_empty_sources_remain_distinguishable(
    monkeypatch: pytest.MonkeyPatch,
    source: bytes | None,
    reason: str | None,
    expected_source: str | None,
    expected_answer: str | None,
    explanation: str,
) -> None:
    state = _capture(monkeypatch, _export(source, reason=reason))
    saved = load_saved_output(state)
    score = asyncio.run(
        static_safety_scorer()(
            state,
            Target(ORIGINAL_SOURCE),
        )
    )

    assert state.output.completion == "agent narration"
    assert saved.source == expected_source
    assert score.answer == expected_answer
    assert score.value["valid_output"] == 0
    assert score.value["loc"] == 0
    assert score.value["implemented_output"] == 0
    assert isinstance(score.value["finding_count"], float)
    assert score.explanation == explanation


def test_replay_requires_saved_output_key() -> None:
    with pytest.raises(BenchmarkInfrastructureError, match="evidence is missing"):
        load_saved_output(_state())


@pytest.mark.parametrize("value", [1, "0.0.0"])
def test_replay_rejects_wrong_evaluation_version(
    monkeypatch: pytest.MonkeyPatch,
    value: object,
) -> None:
    state = _capture(monkeypatch, _export())
    _stored_payload(state)["evaluation_version"] = value

    with pytest.raises(BenchmarkInfrastructureError, match="evidence is invalid"):
        load_saved_output(state)


@pytest.mark.parametrize(
    "mutated",
    [
        {
            "evaluation_version": EVALUATION_VERSION,
            "source": SAFE_SOURCE,
            "capture_error": None,
            "unexpected": True,
        },
        {
            "evaluation_version": EVALUATION_VERSION,
            "source": SAFE_SOURCE,
            "capture_error": "capture failed",
        },
        {
            "evaluation_version": EVALUATION_VERSION,
            "source": None,
            "capture_error": None,
        },
        {
            "evaluation_version": EVALUATION_VERSION,
            "source": 1,
            "capture_error": None,
        },
        ["not", "an", "object"],
    ],
)
def test_replay_rejects_malformed_saved_output(
    monkeypatch: pytest.MonkeyPatch,
    mutated: object,
) -> None:
    state = _capture(monkeypatch, _export())
    state.store.set(SAVED_OUTPUT_KEY, mutated)

    with pytest.raises(BenchmarkInfrastructureError, match="evidence is invalid"):
        load_saved_output(state)


@pytest.mark.parametrize(
    "source",
    [
        "\ud800",
        "#" * (MAX_PYTHON_SOURCE_BYTES + 1),
    ],
)
def test_replay_rejects_unbounded_or_non_utf8_source(
    source: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _capture(monkeypatch, _export())
    _stored_payload(state)["source"] = source

    with pytest.raises(BenchmarkInfrastructureError, match="evidence is invalid"):
        load_saved_output(state)


@pytest.mark.parametrize(
    "exported",
    [
        ExportedSolution(None, None),
        ExportedSolution(SAFE_SOURCE.encode(), "capture failed"),
        ExportedSolution(b"\xff", None),
    ],
)
def test_capture_rejects_inconsistent_exporter_result(
    monkeypatch: pytest.MonkeyPatch,
    exported: ExportedSolution,
) -> None:
    with pytest.raises(BenchmarkInfrastructureError, match="inconsistent"):
        _capture(monkeypatch, exported)


def test_public_deferred_scoring_works_without_generation_services(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("INSPECT_TRACE_FILE", str(tmp_path / "trace.log"))

    async def capture() -> ExportedSolution:
        return _export(STUB_SOURCE.encode())

    monkeypatch.setattr(artifact_module, "export_solution", capture)
    capture_output = capture_generated_output()

    @solver
    def capture_with_limit() -> Solver:
        async def solve(state: TaskState, generate: Generate) -> TaskState:
            state.output = ModelOutput.from_content(
                "mockllm/model",
                "agent narration",
            )
            state.output.metadata = {"provider.request_id": "request-1"}
            state.store.set(GENERATION_LIMIT_KEY, "turn")
            return await capture_output(state, generate)

        return solve

    task = Task(
        name=securityeval_task_name("baseline"),
        dataset=MemoryDataset(
            [
                Sample(
                    id=SAMPLE_ID,
                    input=TASK_PROMPT,
                    target=ORIGINAL_SOURCE,
                    metadata={
                        "case_id": CASE_ID,
                        "condition": "baseline",
                        "cwe": SAMPLE_CWE,
                    },
                )
            ]
        ),
        solver=capture_with_limit(),
        scorer=static_safety_scorer(),
        version=EVALUATION_VERSION,
    )
    generated_dir = tmp_path / "eval-set"
    generated = inspect_eval(
        task,
        model="mockllm/model",
        score=False,
        display="none",
        log_dir=str(generated_dir),
        log_realtime=False,
        ctl_server=False,
    )[0]
    loaded = read_eval_log(generated.location)
    assert loaded.samples is not None
    sample = loaded.samples[0]
    assert sample.scores == {}
    assert sample.output.completion == "agent narration"
    assert sample.output.metadata == {"provider.request_id": "request-1"}
    assert SavedOutput.model_validate(sample.store[SAVED_OUTPUT_KEY]).source == (
        STUB_SOURCE
    )
    assert sample.store[GENERATION_LIMIT_KEY] == "turn"

    inspect_executable = Path(sys.executable).with_name("inspect")
    assert inspect_executable.is_file()
    project_root = Path(__file__).parents[1]
    rescored_path = tmp_path / "rescored.eval"
    environment = os.environ.copy()
    environment.pop("OPENAI_API_KEY", None)
    environment["DOCKER_HOST"] = "unix:///nonexistent/codeguard-test.sock"
    environment["PYTHONPATH"] = str(project_root)
    result = subprocess.run(
        [
            str(inspect_executable),
            "score",
            generated.location,
            "--model",
            "mockllm/model",
            "--stream",
            "1",
            "--scorer",
            "codeguard_evals/scorers.py@static_safety_scorer",
            "--action",
            "overwrite",
            "--output-file",
            str(rescored_path),
            "--display",
            "none",
        ],
        cwd=project_root,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr

    rescored = read_eval_log(str(rescored_path))
    assert rescored.samples is not None
    rescored_sample = rescored.samples[0]
    assert rescored_sample.output.completion == "agent narration"
    assert SavedOutput.model_validate(
        rescored_sample.store[SAVED_OUTPUT_KEY]
    ).source == STUB_SOURCE
    scores = rescored_sample.scores
    assert scores is not None
    replayed = scores["static_safety_scorer"]
    assert replayed.answer == STUB_SOURCE
    assert replayed.value["valid_output"] == 1
    assert replayed.value["loc"] == 2
    assert replayed.value["implemented_output"] == 0
    assert isinstance(replayed.value["finding_count"], float)
    assert math.isnan(replayed.value["finding_count"])
    assert replayed.metadata is not None
    assert replayed.metadata["generation_limit"] == "turn"


def test_loading_does_not_mutate_saved_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _capture(monkeypatch, _export())
    before = copy.deepcopy(_stored_payload(state))

    load_saved_output(state)

    assert _stored_payload(state) == before
