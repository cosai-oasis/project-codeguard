"""Skill-read evidence stays tied to the original installation during replay."""

import copy
import hashlib
import json

import pytest
from inspect_ai.model import ChatMessageTool, ModelOutput

import codeguard_evals.skill_files as skill_files
from codeguard_evals.skill_files import MAX_SKILL_FILE_BYTES
from codeguard_evals.metrics import (
    SKILL_SNAPSHOT_KEY,
    skill_was_read,
    save_skill_snapshot,
)
from codeguard_evals.sandbox_client import BenchmarkInfrastructureError
from tests.conftest import CODEGUARD_SKILL_DIR, codeguard_files, task_state


@pytest.fixture
def saved_skill_state():
    state = task_state()
    snapshot = codeguard_files()
    # Represent a prior skill revision, distinct from the current checkout.
    snapshot["SKILL.md"] = snapshot["SKILL.md"].replace(
        b"CodeGuard", b"CodeGuard (original run)", 1
    )
    save_skill_snapshot(state, snapshot)
    state.messages = [
        ModelOutput.for_tool_call(
            "mockllm/model",
            "exec_command",
            {"cmd": f"cat {CODEGUARD_SKILL_DIR}/SKILL.md"},
            tool_call_id="skill-read",
        ).message,
        ChatMessageTool(
            tool_call_id="skill-read",
            function="exec_command",
            content="Output:\n" + snapshot["SKILL.md"].decode(),
        ),
    ]
    return state


@pytest.mark.parametrize("json_output", [False, True], ids=["plain", "json"])
def test_replay_uses_original_document_without_reading_current_skill(
    saved_skill_state, monkeypatch, json_output
):
    state = saved_skill_state
    persisted = json.loads(json.dumps(state.store.get(SKILL_SNAPSHOT_KEY)))
    state.store.set(SKILL_SNAPSHOT_KEY, persisted)
    if json_output:
        state.messages[-1].content = json.dumps({"output": state.messages[-1].text})
    monkeypatch.setattr(
        skill_files,
        "load_skill_files",
        lambda *_: pytest.fail("current skill read during replay"),
    )
    assert skill_was_read(state) == 1
    state.messages = []
    assert skill_was_read(state) == 0


def test_skill_read_requires_the_original_saved_document(
    saved_skill_state,
):
    legacy = task_state(messages=saved_skill_state.messages)
    with pytest.raises(BenchmarkInfrastructureError, match="snapshot is missing"):
        skill_was_read(legacy)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", 3),
        ("skill_name", "../escape"),
        ("document_sha256", "f" * 64),
        ("document", "different instructions"),
        ("document", ""),
        ("content_sha256", "missing"),
        ("unexpected", True),
    ],
)
def test_malformed_or_changed_snapshot_is_rejected(saved_skill_state, field, value):
    state = saved_skill_state
    record = copy.deepcopy(state.store.get(SKILL_SNAPSHOT_KEY))
    record[field] = value
    state.store.set(SKILL_SNAPSHOT_KEY, record)
    with pytest.raises(BenchmarkInfrastructureError, match="snapshot is invalid"):
        skill_was_read(state)


def test_original_snapshot_cannot_be_overwritten(saved_skill_state):
    with pytest.raises(BenchmarkInfrastructureError, match="already exists"):
        save_skill_snapshot(saved_skill_state, codeguard_files())


@pytest.mark.parametrize("extra_characters", [0, 1], ids=["at-byte-limit", "over-byte-limit"])
def test_replayed_skill_document_is_bounded_in_utf8_bytes(
    saved_skill_state, extra_characters
):
    record = saved_skill_state.store.get(SKILL_SNAPSHOT_KEY)
    record["document"] = "é" * (MAX_SKILL_FILE_BYTES // 2 + extra_characters)
    record["document_sha256"] = hashlib.sha256(record["document"].encode()).hexdigest()
    saved_skill_state.store.set(SKILL_SNAPSHOT_KEY, record)
    if extra_characters:
        with pytest.raises(BenchmarkInfrastructureError, match="snapshot is invalid"):
            skill_was_read(saved_skill_state)
    else:
        assert skill_was_read(saved_skill_state) == 0


def test_legacy_snapshot_still_uses_the_original_codeguard_path(saved_skill_state):
    record = dict(saved_skill_state.store.get(SKILL_SNAPSHOT_KEY))
    record["schema_version"] = 1
    del record["skill_name"]
    saved_skill_state.store.set(SKILL_SNAPSHOT_KEY, record)
    assert skill_was_read(saved_skill_state) == 1


def test_skill_read_uses_the_recorded_installation_name(catalog_skill):
    from codeguard_evals.skill_catalog import load_skill_variant
    from codeguard_evals.sandbox_protocol import CODEX_SKILLS_DIR
    catalog_skill("selected", name="security-reminder")
    snapshot, _ = load_skill_variant("selected")
    state = task_state()
    save_skill_snapshot(state, snapshot)
    state.messages = [
        ModelOutput.for_tool_call(
            "mockllm/model", "exec_command",
            {"cmd": f"cat {CODEX_SKILLS_DIR}/security-reminder/SKILL.md"}, tool_call_id="read",
        ).message,
        ChatMessageTool(tool_call_id="read", content=snapshot["SKILL.md"].decode()),
    ]
    assert skill_was_read(state) == 1
    state.messages[0].tool_calls[0].arguments["cmd"] = f"cat {CODEGUARD_SKILL_DIR}/SKILL.md"
    assert skill_was_read(state) == 0
