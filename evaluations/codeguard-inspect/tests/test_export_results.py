"""Offline exporter tests on synthetic Inspect logs: no provider, network, or Docker."""

from __future__ import annotations

import math
from pathlib import Path

import pytest
from inspect_ai.log import EvalError, EvalSampleLimit

import codeguard_evals.export_results as exporter
from codeguard_evals.export_results import ExportError, export_results
from codeguard_evals.securityeval.reporting import SCORER, report_definition
from codeguard_evals import results_report as report
from tests.synthetic_logs import CANARY, SKILL_SHA256, log_for, sample, values, save, offline, rows, repeated_log

CHARTS = report_definition().charts
FILES = {"index.md", "results.csv", "samples.csv"} | {f"{name}.png" for name in CHARTS}


def test_round_trip_keeps_results_and_excludes_private_content(
    tmp_path, save, offline
):
    log = log_for([sample(1), sample(2, values(findings=2))])
    log.samples[0].scores[SCORER].value[CANARY] = CANARY
    log.eval.metadata["dataset"]["revision"] = CANARY
    log.eval.metadata["python_version"] = CANARY
    log.eval.metadata["semgrep"]["command"].append(CANARY)
    log.eval.metadata["semgrep"]["environment"]["PRIVATE"] = CANARY
    source = save(log)
    before = source.read_bytes()
    output = tmp_path / "export"

    exporter.main(["--run", "Model A", str(source), "-o", str(output)])

    result = rows(output / "results.csv")[0]
    assert result["run"] == "model-a-codeguard-1.5.0"
    assert result["model"] == "Model A"
    assert result["codeguard_version"] == "1.5.0"
    # Historical logs predate catalog IDs; the label and hash still identify the skill.
    assert result["skill_id"] == ""
    assert result["skill_label"] == "CodeGuard 1.5.0"
    assert result["skill_sha256"] == SKILL_SHA256
    assert set(result) == {
        "run", "epoch", "model", "condition", "codeguard_version", "cases", "shared_cases",
        "skill_id", "skill_label", "skill_sha256",
        "findings", "flagged_outputs", "flagged_pct", "likely_vulnerabilities", "usage_missing_cases", "tokens_per_case", "unfinished",
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


@pytest.mark.parametrize("contract", ["0.1.0", "0.2.0", 0])
def test_export_reads_recorded_contract_without_requiring_current_runtime(save, contract):
    log = log_for([sample(1)])
    log.eval.task_version = contract
    _, result, _ = exporter.read_run("Model A", save(log))
    assert result["evaluation_contract"] == (contract or "")
    note = exporter.comparison_note([result])
    assert ("not recorded: evaluation contract" in note) == (contract == 0)


@pytest.mark.parametrize("configured,recorded,expected", [
    (None, False, "false"), (None, True, "true"), (None, None, ""),
    (42, True, "42"), (0, True, "0"), (False, False, "false"),
])
def test_sample_order_uses_recorded_dataset_when_no_shuffle_option(save, configured, recorded, expected):
    log = log_for([sample(1)])
    log.eval.config.sample_shuffle = configured
    log.eval.dataset.shuffled = recorded
    _, result, _ = exporter.read_run("Model A", save(log))
    assert result["sample_shuffle"] == expected
    assert ("sample order" in exporter.comparison_note([result])) == (expected == "")


@pytest.mark.parametrize("field,value", [
    ("collector_sha256", "a" * 64),
    ("command", ["python3", "-m", CANARY]),
    ("environment", {"HOME": CANARY, "TMPDIR": "/tmp"}),
    ("timeout_seconds", 240),
])
def test_comparison_warns_when_scanner_execution_changes(save, field, value):
    log = log_for([sample(1)])
    _, before, _ = exporter.read_run("Model A", save(log, "before.eval"))
    log.eval.metadata["semgrep"][field] = value
    _, after, _ = exporter.read_run("Model B", save(log, "after.eval"))
    assert exporter.comparison_note([before, after]) == (
        "> **Check before comparing:** settings differ for scanner execution."
    )


def test_scanner_identity_comparison_ignores_dictionary_order(save):
    log = log_for([sample(1)])
    _, before, _ = exporter.read_run("Model A", save(log, "before.eval"))
    scanner = log.eval.metadata["semgrep"]
    scanner["environment"] = dict(reversed(list(scanner["environment"].items())))
    log.eval.metadata["semgrep"] = dict(reversed(list(scanner.items())))
    _, after, _ = exporter.read_run("Model B", save(log, "after.eval"))
    assert exporter.comparison_note([before, after]) == ""


def test_legacy_scanner_identity_is_reported_as_missing(save):
    log = log_for([sample(1)])
    _, current, _ = exporter.read_run("Model A", save(log, "current.eval"))
    for field in ("collector_sha256", "command", "environment", "timeout_seconds"):
        del log.eval.metadata["semgrep"][field]
    _, legacy, _ = exporter.read_run("Model B", save(log, "legacy.eval"))
    assert legacy["scanner_execution"] == ""
    assert exporter.comparison_note([legacy]) == (
        "> **Check before comparing:** not recorded: scanner execution."
    )
    assert "scanner execution" in exporter.comparison_note([current, legacy])


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
    log.samples[0].scores[SCORER].metadata.update(
        case_id=str(log.samples[0].id).split("/", 2)[-1], cwe="CWE-1204",
    )
    source = save(log)
    export_results([("model", source)], tmp_path / "first")
    export_results([("model", source)], tmp_path / "second")
    for path in (tmp_path / "first").iterdir():
        second = tmp_path / "second" / path.name
        assert path.read_bytes() == second.read_bytes(), path.name


def test_legacy_codeguard_log_without_version_is_refused(tmp_path, save):
    source = save(log_for([sample(1)], version="unspecified"))
    with pytest.raises(ExportError, match="recorded skill identity"):
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
    sol = page.split("### Model A (1 example compared)")[1].split("### Model B")[0]
    summary = [line for line in sol.splitlines() if line.startswith(("| Baseline |", "| CodeGuard "))]
    assert [line.split("|")[1].strip() for line in summary] == [
        "CodeGuard 1.10.0",
        "Baseline",
        "CodeGuard 1.9.0",
        "CodeGuard 1.10.0-rc.1",
    ]
    assert summary[0].startswith("| CodeGuard 1.10.0 | 2 | 1 of 1 (100%) |")
    assert "### Model B (1 example compared)" in page
    assert "| CodeGuard 1.5.0 | 0 | 0 of 1 (0%) |" in page
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
    assert "may omit tokens from earlier retries" in page


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
    assert "may omit tokens from earlier retries" in page


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
    with pytest.raises(ExportError, match="recorded skill identity"):
        export_results([("Model A", source)], tmp_path / "export")
    assert not (tmp_path / "export").exists()


@pytest.mark.parametrize("same_label", [True, False])
def test_different_recorded_models_require_distinct_public_labels(tmp_path, save, capsys, offline, same_label):
    args = ["--output-dir", str(tmp_path / "report")]
    for index, condition in enumerate(("baseline", "secure_prompt")):
        log = log_for([sample(1, condition=condition)], condition=condition, task_id=condition)
        log.eval.model = f"{CANARY}-{index}"
        label = "Model" if same_label else f"Model {index}"
        args += ["--run", label, str(save(log, f"{condition}.eval"))]
    if same_label:
        with pytest.raises(SystemExit) as error:
            exporter.main(args)
        assert error.value.code == 2
        message = capsys.readouterr().err
        assert "same recorded model" in message and CANARY not in message
        assert not (tmp_path / "report").exists()
    else:
        exporter.main(args)
        assert {row["model"] for row in rows(tmp_path / "report/results.csv")} == {"Model 0", "Model 1"}
        assert all(CANARY.encode() not in path.read_bytes() for path in (tmp_path / "report").iterdir())


@pytest.mark.parametrize("change", ["case", "condition", "cwe", "scanner", "severity_policy", "count", "flag", "confidence", "output_flag"])
def test_securityeval_rejects_inconsistent_saved_scores(tmp_path, save, change):
    log = log_for([sample(1)])
    exporter.read_run("Model", save(log, "valid.eval"))
    score = log.samples[0].scores[SCORER]
    if change == "case": score.metadata["case_id"] = "CWE-020_author_2.py"
    elif change == "condition": score.metadata["condition"] = "baseline"
    elif change == "cwe": score.metadata["cwe"] = CANARY
    elif change == "scanner": score.metadata["semgrep"]["version"] = "0.0.0"
    elif change == "severity_policy": score.metadata["semgrep"]["measured_severities"] = ["ERROR"]
    elif change == "count": score.value["finding_count"] = 1
    elif change == "flag": score.value["semgrep_flagged_output"] = 1
    elif change == "confidence": score.value["confidence_high"] = 1
    elif change == "output_flag": score.value["valid_output"] = 2
    with pytest.raises(ExportError):
        exporter.read_run("Model", save(log, "invalid.eval"))


@pytest.mark.parametrize("severities,expected", [
    (("EXPERIMENT",), 0),
    (("INVENTORY",), 0),
    (("EXPERIMENT", "INVENTORY"), 0),
    (("WARNING", "EXPERIMENT", "INVENTORY"), 1),
])
def test_export_respects_securityeval_finding_exclusions(tmp_path, save, offline, severities, expected):
    from codeguard_evals.graders.semgrep_artifacts import SemgrepFinding
    from codeguard_evals.securityeval.scorers import summarize_findings

    findings = tuple(SemgrepFinding(
        rule_id=f"fixture-{index}", severity=severity, line=1,
        subcategory="vuln", confidence="HIGH",
    ) for index, severity in enumerate(severities))
    item = sample(1, {**values(), **summarize_findings(findings)})
    item.scores[SCORER].metadata["findings"] = [finding.record() for finding in findings]
    log = log_for([item])
    source = save(log)
    original = source.read_bytes()
    output = tmp_path / "report"
    export_results([("Model", source)], output)
    result, = rows(output / "results.csv")
    assert int(result["findings"]) == expected
    assert int(result["flagged_outputs"]) == int(expected > 0)
    assert int(result["likely_vulnerabilities"]) == expected
    assert int(result["confidence_high"]) == expected
    assert source.read_bytes() == original

    # A self-consistent count that includes excluded findings must still be rejected.
    item.scores[SCORER].value.update(
        finding_count=len(findings), semgrep_flagged_output=1,
        confidence_high=len(findings), confidence_medium=0, confidence_low=0,
        subcategory_vuln=len(findings),
    )
    with pytest.raises(ExportError, match="finding metrics"):
        exporter.read_run("Model", save(log, "overcounted.eval"))


@pytest.mark.parametrize("policy,severity,expected", [
    (["ERROR"], "WARNING", 0),
    (["EXPERIMENT"], "EXPERIMENT", 1),
])
def test_export_uses_recorded_severity_policy(save, policy, severity, expected):
    item = sample(1, values(findings=expected))
    score = item.scores[SCORER]
    score.metadata["findings"] = [{"severity": severity}]
    log = log_for([item])
    for metadata in (log.eval.metadata, score.metadata):
        metadata["semgrep"]["measured_severities"] = policy

    _, _, cases = exporter.read_run("Model", save(log))
    assert cases[0]["findings"] == expected
    assert cases[0]["flagged_output"] == int(expected > 0)


@pytest.mark.parametrize("policy", [None, [], "WARNING", [None], [""]])
def test_export_rejects_missing_or_malformed_severity_policy(save, policy):
    log = log_for([sample(1)])
    log.eval.metadata["semgrep"]["measured_severities"] = policy
    with pytest.raises(ExportError, match="measured severities"):
        exporter.read_run("Model", save(log))


@pytest.mark.parametrize("severity", [None, "", ["WARNING"]])
def test_export_cannot_treat_malformed_finding_severity_as_clean(save, severity):
    log = log_for([sample(1)])
    log.samples[0].scores[SCORER].metadata["findings"] = [{"severity": severity}]
    with pytest.raises(ExportError, match="require a severity"):
        exporter.read_run("Model", save(log))


@pytest.mark.parametrize("benchmark", ["SecurityEval", "CyberSecEval"])
def test_generation_log_error_explains_scan_step(tmp_path, save, offline, capsys, benchmark):
    log = log_for([sample(1)])
    log.eval.metadata.update(benchmark=benchmark, phase="generation")
    log.eval.metadata.pop("semgrep")
    log.results.scores = []
    log.samples[0].scores = None
    source = save(log)
    original = source.read_bytes()
    output = tmp_path / "report"

    with pytest.raises(SystemExit) as error:
        exporter.main(["--run", "Model", str(source), "-o", str(output)])

    assert error.value.code == 2
    assert capsys.readouterr().err.strip() == (
        "Export refused: This log has not been scored. Run python -m codeguard_evals.scan, "
        "then export the scored log."
    )
    assert not output.exists()
    assert source.read_bytes() == original


def _codeguard_catalog_log(version):
    log = log_for([sample(1, condition="skill")], condition="skill", task_id="codeguard-1.5")
    log.eval.metadata["skill"] = {
        "id": "codeguard-1.5", "label": "CodeGuard 1.5.0", "name": "codeguard",
        "content_sha256": SKILL_SHA256, "version": version,
    }
    return log


def test_codeguard_catalog_runs_keep_the_public_version_column(tmp_path, save, offline):
    export_results([("Model", save(_codeguard_catalog_log("1.5.0")))], tmp_path / "export")
    result = rows(tmp_path / "export" / "results.csv")[0]
    assert (result["run"], result["codeguard_version"]) == ("model-skill-codeguard-1.5", "1.5.0")
    assert (result["skill_id"], result["skill_label"]) == ("codeguard-1.5", "CodeGuard 1.5.0")


@pytest.mark.parametrize("version", ["candidate-1", "1.5.0 | injected", None])
def test_codeguard_catalog_versions_outside_the_release_format_stay_unpublished(tmp_path, save, offline, version):
    export_results([("Model", save(_codeguard_catalog_log(version)))], tmp_path / "export")
    result = rows(tmp_path / "export" / "results.csv")[0]
    assert (result["codeguard_version"], result["skill_id"]) == ("", "codeguard-1.5")
    assert "injected" not in (tmp_path / "export" / "index.md").read_text()


def test_reports_distinguish_skills_with_the_same_name_and_no_version(tmp_path, save, offline, monkeypatch):
    import codeguard_evals.skill_catalog as catalog
    runs = []
    for variant, digest in (("first", "a"), ("second", "b")):
        log = log_for([sample(1, condition="skill")], condition="skill", task_id=variant)
        log.eval.metadata["skill"] = {
            "id": variant, "label": "Security guidance", "name": "same-name",
            "content_sha256": digest * 64,
        }
        runs.append(("Model", save(log, f"{variant}.eval")))
    monkeypatch.setattr(catalog, "load_skill_variant", lambda *_: pytest.fail("catalog used during export"))
    output = tmp_path / "variants"
    export_results(runs, output)
    results = rows(output / "results.csv")
    assert [row["skill_id"] for row in results] == ["first", "second"]
    assert [row["skill_sha256"] for row in results] == ["a" * 64, "b" * 64]
    assert all(row["codeguard_version"] == "" for row in results)
    page = (output / "index.md").read_text()
    assert "Security guidance (first)" in page and "Security guidance (second)" in page
    assert "same-name" not in page
