"""Tests for password-storage task and prompt wiring."""

from __future__ import annotations

import pytest

from codeguard_harness.prompts import (
    BASELINE_VARIANT,
    BOTH_VARIANT,
    CODEGUARD_VARIANT,
    build_prompt,
    selected_prompt_variants,
)
from codeguard_harness.tasks.password_storage import (
    BASE_PROMPT,
    CODEGUARD_GUIDANCE,
    password_storage,
    password_storage_samples,
)


def test_both_variant_expands_to_baseline_and_codeguard() -> None:
    assert selected_prompt_variants(BOTH_VARIANT) == (BASELINE_VARIANT, CODEGUARD_VARIANT)


@pytest.mark.parametrize(
    "call",
    [
        pytest.param(lambda: build_prompt(BASE_PROMPT, CODEGUARD_GUIDANCE, "unknown"), id="prompt"),
        pytest.param(lambda: password_storage_samples("unknown"), id="task"),
    ],
)
def test_invalid_variant_fails_fast(call) -> None:
    with pytest.raises(ValueError):
        call()


def test_codeguard_prompt_adds_guidance_to_same_task() -> None:
    baseline_prompt = build_prompt(BASE_PROMPT, CODEGUARD_GUIDANCE, BASELINE_VARIANT)
    codeguard_prompt = build_prompt(BASE_PROMPT, CODEGUARD_GUIDANCE, CODEGUARD_VARIANT)

    assert baseline_prompt == BASE_PROMPT
    assert BASE_PROMPT in codeguard_prompt
    assert CODEGUARD_GUIDANCE in codeguard_prompt
    assert CODEGUARD_GUIDANCE not in baseline_prompt


def test_password_storage_samples_include_expected_variants() -> None:
    samples = password_storage_samples(BOTH_VARIANT)

    assert [s.metadata["variant"] for s in samples] == ["baseline", "codeguard"]
    assert [s.metadata["guidance"] for s in samples] == ["none", "codeguard"]
    assert {s.metadata["scenario"] for s in samples} == {"password_storage"}


def test_password_storage_task_uses_named_memory_dataset_and_metadata() -> None:
    task = password_storage()

    assert task.dataset.name == "password_storage"
    assert len(task.dataset) == 2
    assert task.metadata["execution"] == "none"
    assert task.metadata["guidance_delivery"] == "prompt_block"
