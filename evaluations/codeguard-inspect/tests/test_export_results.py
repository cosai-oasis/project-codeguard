"""Offline exporter tests on synthetic Inspect logs: no provider, network, or Docker."""

from __future__ import annotations

import math
from pathlib import Path

import pytest
from inspect_ai.log import EvalError, EvalSampleLimit

import codeguard_evals.export_results as exporter
from codeguard_evals.export_results import SCORER, ExportError, export_results
from codeguard_evals import results_report as report
from codeguard_evals.results_report import CHARTS
from tests.synthetic_logs import CANARY, log_for, sample, values, save, offline, rows, repeated_log

FILES = {"index.md", "results.csv", "samples.csv"} | {f"{name}.png" for name in CHARTS}


def test_round_trip_keeps_results_and_excludes_private_content(
    tmp_path, save, offline
):
    log = log_for([sample(1), sample(2, values(findings=2))])
    log.samples[0].scores[SCORER].value[CANARY] = CANARY
    log.eval.metadata["dataset"]["revision"] = CANARY
    log.eval.metadata["python_version"] = CANARY
    source = save(log)
    before = source.read_bytes()
    output = tmp_path / "export"

    exporter.main(["--run", "Model A", str(source), "-o", str(output)])

    result = rows(output / "results.csv")[0]
    assert result["run"] == "model-a-codeguard-1.5.0"
    assert result["model"] == "Model A"
    assert result["codeguard_version"] == "1.5.0"
    assert set(result) == {
        "run", "epoch", "model", "condition", "codeguard_version", "cases", "shared_cases",
        "findings", "likely_vulnerabilities", "tokens_per_case", "unfinished",
        "recorded_cost_usd", "estimated_cost_usd", "cost_per_case_usd", "cost_change_pct",
        "confidence_high", "confidence_medium", "confidence_low",
        "agent_turn_limit", "agent_seconds", "sample_seconds_limit", "agent_output_tokens",
    }
    assert (result["shared_cases"], result["findings"]) == ("2", "2")
    assert (result["agent_turn_limit"], result["agent_seconds"], result["sample_seconds_limit"], result["agent_output_tokens"]) == (
        "16", "600", "1200", "32768"
    )
    assert (result["confidence_high"], result["confidence_medium"], result["confidence_low"]) == (
        "0", "0", "2"
    )
    assert source.read_bytes() == before
    assert {path.name for path in output.iterdir()} == FILES
    cases = rows(output / "samples.csv")
    assert [case["findings"] for case in cases] == ["0", "2"]
    assert all(set(case) == {
        "run", "case_id", "epoch", "outcome", "changed_output", "valid_output", "findings",
        "likely_vulnerabilities",
    } for case in cases)
    for path in output.iterdir():
        content = path.read_bytes()
        for private in (CANARY, str(tmp_path), "/Users/"):
            assert private.encode() not in content, path.name


def test_limits_errors_and_missing_values_are_kept_not_zeroed(tmp_path, save):
    timeout = sample(
        1, values(changed=0), limit=EvalSampleLimit(type="time", limit=600)
    )
    invalid = sample(2, values(valid=0))
    invalid.scores[SCORER].value["finding_count"] = math.nan
    failure = sample(3)
    failure.scores = None
    failure.error = EvalError(message=CANARY, traceback=CANARY, traceback_ansi=CANARY)
    turn_stop = sample(4, limit=EvalSampleLimit(type="turn", limit=16))
    token_stop = sample(5, limit=EvalSampleLimit(type="token", limit=32768))
    source = save(log_for([timeout, invalid, failure, turn_stop, token_stop]))
    export_results([("model", source)], tmp_path / "export")

    cases = rows(tmp_path / "export" / "samples.csv")
    assert [case["outcome"] for case in cases] == [
        "Time limit", "Completed", "Error", "Turn limit", "Other limit"
    ]
    assert cases[0]["changed_output"] == "0"
    assert cases[1]["findings"] == ""
    failed = cases[2]
    assert (failed["outcome"], failed["findings"]) == ("Error", "")
    result = rows(tmp_path / "export" / "results.csv")[0]
    assert result["unfinished"] == "4"
    for path in (tmp_path / "export").iterdir():
        content = path.read_bytes()
        for private in (CANARY, str(tmp_path), "/Users/"):
            assert private.encode() not in content, path.name


def test_resumed_log_counts_recorded_run_tokens_once(tmp_path, save):
    reused = sample(1)
    reused.started_at = "2026-01-01T10:00:00+00:00"
    log = log_for([reused, sample(2)])
    log.stats.model_usage[CANARY].total_tokens = 999
    _, run, samples = exporter.read_run("Model A", save(log))
    assert exporter.public_results([run], samples)[0]["tokens_per_case"] == 999 / 2


def test_one_log_per_run_and_per_task(tmp_path, save):
    first = save(log_for([sample(1)]), "first.eval")
    retry = save(log_for([sample(1)]), "retry.eval")
    for left, right in (("model", "model"), ("Model A", "model-a")):
        with pytest.raises(ExportError, match="case and most punctuation"):
            export_results([(left, first), (right, retry)], tmp_path / "export")
    with pytest.raises(ExportError, match="retry logs"):
        export_results([("model", first), ("other model", retry)], tmp_path / "export")
    assert not (tmp_path / "export").exists()


def test_unexpected_scorer_is_rejected_before_reading_samples(
    tmp_path, save, monkeypatch
):
    log = log_for([sample(1)])
    qualified = "codeguard_evals/static_safety_scorer"
    log.samples[0].scores = {qualified: log.samples[0].scores[SCORER]}
    for score in log.results.scores:
        score.scorer = qualified
    source = save(log)
    read_samples = []
    monkeypatch.setattr(exporter, "read_eval_log_sample_summaries", read_samples.append)

    with pytest.raises(ExportError, match="Unsupported scorer"):
        export_results([("model", source)], tmp_path / "export")
    assert read_samples == []


@pytest.mark.parametrize("keep_expected", [False, True])
def test_unexpected_sample_scorer_is_rejected(tmp_path, save, keep_expected):
    log = log_for([sample(1)])
    score = log.samples[0].scores[SCORER]
    log.samples[0].scores = {"codeguard_evals/static_safety_scorer": score}
    if keep_expected:
        log.samples[0].scores[SCORER] = score
    with pytest.raises(ExportError, match="Unsupported sample scorer"):
        export_results([("model", save(log))], tmp_path / "export")


def test_unknown_run_usage_stays_missing(tmp_path, save):
    log = log_for([sample(1)])
    log.stats.model_usage = {}
    source = save(log)
    _, run, samples = exporter.read_run("model", source)
    assert exporter.public_results([run], samples)[0]["tokens_per_case"] == ""
    with pytest.raises(ExportError, match="complete costs"):
        export_results([("model", source)], tmp_path / "export")
    assert not (tmp_path / "export").exists()


@pytest.mark.parametrize("sample_state", ["missing", "nan"])
def test_unavailable_metric_stays_missing(tmp_path, save, sample_state):
    item = sample(1)
    item.scores[SCORER].value["subcategory_vuln"] = math.nan
    if sample_state == "missing":
        item.scores[SCORER].value.pop("subcategory_vuln")
    export_results([("model", save(log_for([item])))], tmp_path / "export")
    assert rows(tmp_path / "export" / "samples.csv")[0]["likely_vulnerabilities"] == ""


@pytest.mark.parametrize(
    "change",
    ["cancelled", "invalidated", "missing_epoch", "missing_sample", "duplicate_case"],
)
def test_incomplete_or_ambiguous_logs_are_rejected(tmp_path, save, change):
    cases = [sample(1), sample(1)] if change == "duplicate_case" else [sample(1)]
    log = log_for(cases)
    if change == "cancelled":
        log.status = "cancelled"
    elif change == "invalidated":
        log.invalidated = True
    elif change == "missing_epoch":
        log.eval.config.epochs = 2
    elif change == "missing_sample":
        log.results.total_samples = 2
    with pytest.raises(ExportError):
        export_results([("model", save(log))], tmp_path / "export")
    assert not (tmp_path / "export").exists()


def test_remote_inputs_are_rejected_before_inspect_reads_them(monkeypatch):
    reads = []
    monkeypatch.setattr(exporter, "read_eval_log", reads.append)
    with pytest.raises(ExportError, match="local .eval"):
        exporter.read_run("model", Path("s3://private/log.eval"))
    assert reads == []


@pytest.mark.parametrize(
    "label", ["=1+1", "+1", "@formula", "\tprivate", "path/name", "a|b", ""]
)
def test_formula_like_or_unsafe_labels_are_rejected(tmp_path, save, label):
    with pytest.raises(ExportError):
        export_results([(label, save())], tmp_path / "export")


@pytest.mark.parametrize(
    "title", ["=HYPERLINK(1)", "[link](https://example.invalid)", "a|b"]
)
def test_unsafe_titles_are_rejected(tmp_path, save, title):
    source = save()
    with pytest.raises(ExportError):
        export_results([("model", source)], tmp_path / "export", title=title)


def test_formula_in_a_case_id_is_rejected(tmp_path, save):
    log = log_for([sample(1)])
    log.samples[0].id = '=HYPERLINK("https://example.invalid")'
    with pytest.raises(ExportError, match="case ID"):
        export_results([("model", save(log))], tmp_path / "export")


def test_text_in_a_numeric_score_is_rejected(tmp_path, save):
    log = log_for([sample(1)])
    log.samples[0].scores[SCORER].value["finding_count"] = CANARY
    with pytest.raises(ExportError, match="numeric"):
        export_results([("model", save(log))], tmp_path / "export")


def test_existing_output_is_rejected_before_reading_logs(tmp_path, monkeypatch):
    output = tmp_path / "export"
    output.mkdir()
    (output / "keep.txt").write_text("keep")

    def unexpected_read(*args, **kwargs):
        pytest.fail("an existing output must be rejected before logs are read")

    monkeypatch.setattr(exporter, "read_run", unexpected_read)
    with pytest.raises(ExportError, match="already exists"):
        export_results([("model", tmp_path / "unused.eval")], output)
    assert [path.name for path in output.iterdir()] == ["keep.txt"]


def test_dangling_output_symlink_is_rejected(tmp_path):
    output = tmp_path / "export"
    output.symlink_to(tmp_path / "missing")
    with pytest.raises(ExportError, match="already exists"):
        export_results([], output)
    assert output.is_symlink()


def test_output_created_during_render_is_never_replaced(tmp_path, save, monkeypatch):
    output = tmp_path / "export"

    def render(*args, **kwargs):
        output.mkdir()
        (output / "keep.txt").write_text("keep")
        return {}

    monkeypatch.setattr(report, "render_charts", render)
    with pytest.raises(FileExistsError):
        export_results([("model", save())], output)
    assert [path.name for path in output.iterdir()] == ["keep.txt"]


def test_exports_are_byte_for_byte_reproducible(tmp_path, save):
    log = log_for([sample(2), sample(1, values(findings=1))])
    log.samples[0].id = log.samples[0].id.replace("CWE-020", "CWE-1204")
    source = save(log)
    export_results([("model", source)], tmp_path / "first")
    export_results([("model", source)], tmp_path / "second")
    for path in (tmp_path / "first").iterdir():
        second = tmp_path / "second" / path.name
        assert path.read_bytes() == second.read_bytes(), path.name


def test_a_skill_that_records_no_version_is_refused(tmp_path, save):
    source = save(log_for([sample(1)], version="unspecified"))
    with pytest.raises(ExportError, match="aaaaaaaaaaaa records no version"):
        export_results([("model", source)], tmp_path / "export")


@pytest.mark.parametrize(
    "skill", [{"version": "1.5.0"}, {"version": "1.5.0", "content_sha256": CANARY}]
)
def test_codeguard_runs_need_a_valid_skill_hash(tmp_path, save, skill):
    log = log_for([sample(1)])
    log.eval.metadata["codeguard"] = skill
    with pytest.raises(ExportError):
        export_results([("model", save(log))], tmp_path / "export")


@pytest.mark.parametrize("condition", ["baseline", "secure_prompt"])
def test_other_conditions_have_no_skill_identity(tmp_path, save, condition):
    source = save(log_for([sample(1, condition=condition)], condition=condition))
    export_results([("model", source)], tmp_path / "export")
    result = rows(tmp_path / "export" / "results.csv")[0]
    assert result["run"] == f"model-{condition.replace('_', '-')}"
    assert result["codeguard_version"] == ""


def test_page_groups_models_and_keeps_supplied_run_order(tmp_path, save):
    def logged(name, cases, **options):
        return save(log_for(cases, task_id=name, **options), f"{name}.eval")

    runs = [
        ("Model A", logged("new", [sample(1, values(findings=2))], version="1.10.0")),
        ("Model A", logged("base", [sample(1, condition="baseline")], condition="baseline")),
        ("Model A", logged("old", [sample(1)], version="1.9.0")),
        ("Model A", logged("candidate", [sample(1)], version="1.10.0-rc.1")),
        ("Model B", logged("other", [sample(3)])),
    ]
    export_results(
        runs,
        tmp_path / "export",
        title="CodeGuard version comparison",
    )

    page = (tmp_path / "export" / "index.md").read_text()
    assert page.startswith("# CodeGuard version comparison\n")
    assert "[Evaluation Results](../index.md)" in page
    sol = page.split("### Model A (1 shared case)")[1].split("### Model B")[0]
    summary = [line for line in sol.splitlines() if line.startswith(("| Baseline |", "| CodeGuard "))]
    assert [line.split("|")[1].strip() for line in summary] == [
        "CodeGuard 1.10.0",
        "Baseline",
        "CodeGuard 1.9.0",
        "CodeGuard 1.10.0-rc.1",
    ]
    assert summary[0].startswith("| CodeGuard 1.10.0 | 2 | 0 | 0 |")
    assert "### Model B (1 shared case)" in page
    assert "| CodeGuard 1.5.0 | 0 | 0 | 0 |" in page
    for name in CHARTS:
        assert f"]({name}.png)" in page
    assert "[results.csv](results.csv)" in page
    assert "[samples.csv](samples.csv)" in page
    assert CANARY not in page and str(tmp_path) not in page


@pytest.mark.parametrize("stage, error", [
    ("read_run", ValueError), ("render_charts", RuntimeError),
    ("read_run", KeyError), ("render_charts", IndexError),
    ("render_charts", ZeroDivisionError), ("read_run", AttributeError),
])
def test_cli_hides_private_errors_and_writes_nothing(tmp_path, save, monkeypatch, capsys, stage, error):
    source = save()

    def fail(*args, **kwargs):
        raise error(CANARY)

    monkeypatch.setattr(exporter if stage == "read_run" else report, stage, fail)
    with pytest.raises(SystemExit) as raised:
        exporter.main(["--run", "model", str(source), "-o", str(tmp_path / "export")])
    assert raised.value.code == 2
    assert CANARY not in capsys.readouterr().err
    assert not (tmp_path / "export").exists()


@pytest.mark.parametrize("signal", [KeyboardInterrupt, SystemExit])
def test_cli_does_not_hide_cancellation(tmp_path, save, monkeypatch, signal):
    def cancel(*args, **kwargs):
        raise signal()

    monkeypatch.setattr(exporter, "read_run", cancel)
    with pytest.raises(signal):
        exporter.main(["--run", "model", str(save()), "-o", str(tmp_path / "export")])
    assert not (tmp_path / "export").exists()


def test_multiple_epochs_repeat_tables_and_charts_without_averaging(tmp_path, save):
    source = save(repeated_log())
    output = tmp_path / "export"
    export_results([("Model A", source)], output)
    summary = rows(output / "results.csv")
    assert [r["epoch"] for r in summary] == ["1", "2"]
    assert [r["cases"] for r in summary] == ["2", "2"]
    assert [r["findings"] for r in summary] == ["2", "4"]
    assert [float(r["tokens_per_case"]) for r in summary] == [100, 200]
    assert [float(r["recorded_cost_usd"]) for r in summary] == [0.5, 1.0]
    assert [r["estimated_cost_usd"] for r in summary] == ["", ""]
    assert [float(r["cost_per_case_usd"]) for r in summary] == [0.25, 0.5]
    samples = rows(output / "samples.csv")
    assert len({(r["case_id"], r["epoch"]) for r in samples}) == 4
    page = (output / "index.md").read_text()
    assert page.count("## Epoch ") == 2
    for epoch in (1, 2):
        for chart in CHARTS:
            name = f"{chart}-epoch-{epoch}.png"
            assert (output / name).is_file()
            assert f"]({name})" in page
    assert "Earlier retries may be missing" in page


def test_shared_cases_are_selected_separately_in_each_epoch(tmp_path, save):
    baseline = repeated_log("baseline")
    guarded = repeated_log()
    guarded.samples[-1].scores[SCORER].value["changed_output"] = 0
    runs = [
        ("Model A", save(baseline, "base.eval")),
        ("Model A", save(guarded, "guard.eval")),
    ]
    output = tmp_path / "export"
    export_results(runs, output)
    summary = rows(output / "results.csv")
    assert [r["shared_cases"] for r in summary] == ["2", "2", "1", "1"]
    assert [r["findings"] for r in summary] == ["2", "2", "2", "2"]


def test_different_epoch_counts_for_one_model_are_rejected(tmp_path, save):
    runs = [
        ("Model A", save(repeated_log("baseline", 1), "base.eval")),
        ("Model A", save(repeated_log(), "guard.eval")),
    ]
    with pytest.raises(ExportError, match="matching epoch counts"):
        export_results(runs, tmp_path / "export")
    assert not (tmp_path / "export").exists()


@pytest.mark.parametrize("case_ids", [[1], [1, 3]])
def test_different_case_inventories_for_one_model_are_rejected(tmp_path, save, case_ids):
    runs = [
        ("Model A", save(log_for([sample(n, condition="baseline") for n in (1, 2)],
                                condition="baseline", task_id="base"), "base.eval")),
        ("Model A", save(log_for([sample(n) for n in case_ids]), "guard.eval")),
    ]
    with pytest.raises(ExportError, match="same cases"):
        export_results(runs, tmp_path / "export")
    assert not (tmp_path / "export").exists()


def test_models_can_have_different_epoch_counts_without_repeating_run_totals(tmp_path, save):
    runs = [
        ("Model A", save(repeated_log("baseline", 1), "base.eval")),
        ("Model B", save(repeated_log(), "guard.eval")),
    ]
    raw, samples = exporter.read_runs(runs)
    summary = exporter.public_results(raw, samples)
    assert [(r["model"], r["epoch"]) for r in summary] == [
        ("Model A", 1), ("Model B", 1), ("Model B", 2)
    ]
    assert [float(r["tokens_per_case"]) for r in summary] == [9999 / 2, 100, 200]


def test_selected_epoch_preserves_number_and_excludes_other_data(tmp_path, save):
    source = save(repeated_log())
    exporter.main(["--run", "Model A", str(source), "--epoch", "2", "-o", str(tmp_path / "export")])
    result = rows(tmp_path / "export/results.csv")
    assert len(result) == 1
    assert (result[0]["epoch"], result[0]["findings"], result[0]["cases"]) == ("2", "4", "2")
    assert float(result[0]["tokens_per_case"]) == 200
    assert float(result[0]["recorded_cost_usd"]) == 1.0
    assert {row["epoch"] for row in rows(tmp_path / "export/samples.csv")} == {"2"}
    assert {p.name for p in (tmp_path / "export").iterdir()} == {
        "index.md", "results.csv", "samples.csv", *[f"{name}-epoch-2.png" for name in CHARTS]
    }
    page = (tmp_path / "export/index.md").read_text()
    assert "## Epoch 2" in page and "## Epoch 1" not in page
    assert "Earlier retries may be missing" in page


@pytest.mark.parametrize("epoch", [0, -1, 3, True, 1.5])
def test_invalid_epoch_writes_nothing(tmp_path, save, epoch):
    with pytest.raises(ExportError, match="selected epoch"):
        export_results([("Model A", save(repeated_log()))], tmp_path / "export", epoch=epoch)
    assert not (tmp_path / "export").exists()


def test_selected_epoch_must_exist_in_every_model(tmp_path, save):
    runs = [("Model A", save(repeated_log(), "a.eval")),
            ("Model B", save(repeated_log("baseline", 1), "b.eval"))]
    with pytest.raises(ExportError, match="selected epoch"):
        export_results(runs, tmp_path / "export", epoch=2)
    assert not (tmp_path / "export").exists()


@pytest.mark.parametrize("version", ["=1+1", "1.4.0|private", "1.4.0/path"])
def test_unsafe_skill_versions_are_refused_before_writing(tmp_path, save, version):
    source = save(log_for([sample(1)], version=version))
    with pytest.raises(ExportError, match="unsupported format"):
        export_results([("Model A", source)], tmp_path / "export")
    assert not (tmp_path / "export").exists()
