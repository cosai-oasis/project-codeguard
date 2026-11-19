"""Qualify Inspect's incremental writer without Docker or provider calls."""

import asyncio
import copy
from zipfile import ZipFile
from dataclasses import replace
from functools import wraps

import pytest
from inspect_ai.log import read_eval_log, write_eval_log
from inspect_ai.event import ModelEvent
from inspect_ai.model import ChatMessageTool, ChatMessageUser, GenerateConfig, ModelOutput

import codeguard_evals.graders.semgrep as semgrep
from codeguard_evals.securityeval import scorers
import codeguard_evals.scan as batch
import codeguard_evals.streaming_log as streaming
from codeguard_evals.metrics import SKILL_SNAPSHOT_KEY, save_skill_snapshot
from codeguard_evals.securityeval.protocol import securityeval_prompt
from tests.conftest import CODEGUARD_SKILL_DIR, codeguard_files, generation_log


def test_streaming_bounds_readers_and_writer_without_loading_the_whole_log(
    tmp_path, scanner, monkeypatch
):
    source = generation_log(tmp_path, count=11)
    native_read = batch.read_eval_log_async
    native_sample_read = batch.read_eval_log_sample_async
    native_writer = streaming.create_recorder_for_location
    native_grader = scorers.semgrep_grader
    active_scores = peak_scores = 0
    buffered = peak_buffered = 0

    async def headers_only(path, **kwargs):
        assert kwargs.get("header_only") is True
        return await native_read(path, **kwargs)

    async def scan_inputs_only(*args, **kwargs):
        assert {"messages", "events", "output"} <= kwargs.get("exclude_fields", set())
        return await native_sample_read(*args, **kwargs)

    def bounded_writer(*args):
        writer = native_writer(*args)
        log_sample, flush, finish = writer.log_sample, writer.flush, writer.log_finish

        async def record(*args):
            nonlocal buffered, peak_buffered
            buffered += 1
            peak_buffered = max(peak_buffered, buffered)
            return await log_sample(*args)

        async def release(*args):
            nonlocal buffered
            await flush(*args)
            buffered = 0

        async def finish_header(*args, **kwargs):
            assert kwargs["header_only"] is True
            return await finish(*args, **kwargs)

        writer.log_sample, writer.flush, writer.log_finish = (
            record,
            release,
            finish_header,
        )
        return writer

    def measured_grader():
        grader = native_grader()

        @wraps(grader.scorer)
        async def score(state, target):
            nonlocal active_scores, peak_scores
            active_scores += 1
            peak_scores = max(peak_scores, active_scores)
            try:
                await asyncio.sleep(0.005)
                return await grader.scorer(state, target)
            finally:
                active_scores -= 1

        return replace(grader, scorer=score)

    monkeypatch.setattr(batch, "read_eval_log_async", headers_only)
    monkeypatch.setattr(batch, "read_eval_log_sample_async", scan_inputs_only)
    monkeypatch.setattr(streaming, "create_recorder_for_location", bounded_writer)
    monkeypatch.setitem(batch.GRADERS, "SecurityEval", measured_grader)
    output = asyncio.run(batch.scan_log(source, tmp_path / "scored"))
    assert read_eval_log(output).results.completed_samples == 11
    assert peak_scores == 1
    assert peak_buffered <= streaming.WRITE_BUFFER_SAMPLES


def test_streamed_scores_match_full_log_with_epochs_transcripts_and_skill_reads(
    tmp_path, scanner
):
    source = generation_log(tmp_path)
    original = read_eval_log(source, resolve_attachments=True)
    sample = original.samples[0]
    sample.id = sample.id.replace("baseline", "codeguard")
    sample.metadata["condition"] = "codeguard"
    sample.input = securityeval_prompt("codeguard")
    snapshot = codeguard_files()
    state = batch._state(original, sample)
    save_skill_snapshot(state, snapshot)
    sample.store[SKILL_SNAPSHOT_KEY] = state.store.get(SKILL_SNAPSHOT_KEY)
    sample.messages.extend(
        [
            ModelOutput.for_tool_call(
                "mockllm/model",
                "exec_command",
                {"cmd": f"cat {CODEGUARD_SKILL_DIR}/SKILL.md"},
                tool_call_id="skill-read",
            ).message,
            ChatMessageTool(
                tool_call_id="skill-read", content=snapshot["SKILL.md"].decode()
            ),
        ]
    )
    for sample in list(original.samples):
        repeated = copy.deepcopy(sample)
        repeated.epoch = 2
        repeated.uuid = None
        original.samples.append(repeated)
    original.eval.config.epochs = 2
    original.eval.config.epochs_reducer = []
    original.eval.dataset.sample_ids = [sample.id for sample in original.samples[:3]]
    original.results.total_samples = original.results.completed_samples = 6
    write_eval_log(original, source)
    original_bytes = source.read_bytes()
    output = asyncio.run(batch.scan_log(source, tmp_path / "scored"))
    scored = read_eval_log(output, resolve_attachments=True)
    expected = read_eval_log(source, resolve_attachments=True)
    for before, after in zip(expected.samples, scored.samples, strict=True):
        assert before.messages == after.messages
        assert before.input == after.input and before.target == after.target
        # Inspect replaces the old scorer span, retaining generation events.
        scoring_start = next(
            (
                i
                for i, event in enumerate(before.events)
                if getattr(event, "type", None) == "scorers"
            ),
            len(before.events),
        )
        assert after.events[:scoring_start] == before.events[:scoring_start]
        before.store[semgrep.SEMGREP_EVIDENCE_KEY] = after.store[
            semgrep.SEMGREP_EVIDENCE_KEY
        ]
        assert before.store == after.store
    expected = asyncio.run(
        batch.score_async(
            expected,
            scorers.semgrep_grader().scorer,
            model="mockllm/model",
            action="overwrite",
            display="none",
            copy=False,
        )
    )
    for before, after in zip(expected.samples, scored.samples, strict=True):
        assert before.scores["static_safety_scorer"].value == pytest.approx(
            after.scores["static_safety_scorer"].value,
            nan_ok=True,
        )
        if after.metadata["condition"] == "codeguard":
            assert after.scores["static_safety_scorer"].value["skill_loaded"] == 1
    assert expected.results.model_dump_json() == scored.results.model_dump_json()
    assert source.read_bytes() == original_bytes


def test_streamed_logs_keep_repeated_model_content_deduplicated(tmp_path, scanner):
    source = generation_log(tmp_path, count=1)
    original = read_eval_log(source)
    content = "Repeated model context. " * 2048
    for _ in range(6):
        original.samples[0].events.append(ModelEvent(
            model="mockllm/model", input=[ChatMessageUser(content=content)],
            tools=[], tool_choice="auto", config=GenerateConfig(),
            output=ModelOutput.from_content("mockllm/model", "done"),
        ))
    write_eval_log(original, source)
    output = asyncio.run(batch.scan_log(source, tmp_path / "scored"))
    for path in (source, output):
        with ZipFile(path) as archive:
            sample_name = next(name for name in archive.namelist() if name.startswith("samples/"))
            assert archive.read(sample_name).count(content.encode()) == 1
    replayed = read_eval_log(output, resolve_attachments=True)
    events = [event for event in replayed.samples[0].events if isinstance(event, ModelEvent)]
    assert len(events) == 6 and all(event.input[0].content == content for event in events)


def test_cancelled_scoring_preserves_existing_output(
    tmp_path, scanner, monkeypatch
):
    source = generation_log(tmp_path)
    output = asyncio.run(batch.scan_log(source, tmp_path / "scored"))
    original = output.read_bytes()

    async def cancel(log, scorer, *, samples, **kwargs):
        async with samples(0):
            pass
        raise asyncio.CancelledError()

    with monkeypatch.context() as cancellation:
        cancellation.setattr(batch, "score_async", cancel)
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(batch.scan_log(source, tmp_path / "scored"))
    assert output.read_bytes() == original
    assert not list((tmp_path / "scored").glob(".scored-*"))
    asyncio.run(batch.scan_log(source, tmp_path / "scored"))
    assert len(scanner[0]) == 9
