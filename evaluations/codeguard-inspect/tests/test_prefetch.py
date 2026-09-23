from __future__ import annotations

from pathlib import Path

import pytest

import codeguard_evals.prefetch as prefetch


def test_main_validates_operator_rules_before_other_preparation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rules = tmp_path / "python"
    dataset = tmp_path / "dataset.jsonl"
    order: list[str] = []

    def validate() -> Path:
        order.append("rules")
        return rules

    def prepare_dataset() -> Path:
        order.append("dataset")
        return dataset

    monkeypatch.setattr(prefetch, "load_locked_rules_directory", validate)
    monkeypatch.setattr(prefetch, "prefetch_securityeval", prepare_dataset)

    assert prefetch.main() == 0
    assert order == ["rules", "dataset"]
    output = capsys.readouterr().out
    assert str(rules) in output
    assert str(dataset) in output


def test_main_stops_when_the_operator_checkout_is_invalid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared_dataset = False

    def reject() -> Path:
        raise FileNotFoundError("operator checkout is missing")

    def prepare_dataset() -> Path:
        nonlocal prepared_dataset
        prepared_dataset = True
        return Path("dataset.jsonl")

    monkeypatch.setattr(prefetch, "load_locked_rules_directory", reject)
    monkeypatch.setattr(prefetch, "prefetch_securityeval", prepare_dataset)

    with pytest.raises(FileNotFoundError, match="operator checkout"):
        prefetch.main()
    assert prepared_dataset is False
