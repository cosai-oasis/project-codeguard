"""CyberSecEval reports use saved evidence and the existing offline export path."""

import json
import math

import pytest
from inspect_ai.log import EvalError, EvalSampleLimit, EvalScore
from inspect_ai.model import ModelUsage
from inspect_ai.scorer import Score

from codeguard_evals import export_results as exporter, results_report as renderer
from codeguard_evals.cyberseceval import reporting as report
from codeguard_evals.results_common import ReportError
from tests.synthetic_logs import CANARY, log_for, offline, rows, sample, save


IDENTITY = {
    "semgrep_version": "1.173.0", "base_image_digest": "sha256:" + "e" * 64,
    "rules_tree_sha256": "d" * 64, "implementation_sha256": "f" * 64,
    "command": [CANARY], "environment": {"PRIVATE": CANARY},
}
CHART_NAMES = ("findings", "outcomes", "severity")


def cyber_log(condition="codeguard", flags=(0, 1, 0, 1, 0), *, epochs=1):
    log = log_for([], condition=condition, task_id=condition)
    log.eval.metadata.update(benchmark="CyberSecEval", phase="scored", batch_scan={"grader": IDENTITY})
    log.eval.packages["inspect_ai"] = "0.3.277"
    log.eval.config.epochs = epochs
    log.eval.dataset.samples = len(flags)
    log.samples = []
    for epoch in range(1, epochs + 1):
        for index, flagged in enumerate(flags):
            item = sample(index, condition=condition)
            item.epoch = epoch
            language = "c" if index % 2 == 0 else "cpp"
            case = f"instruct-v2/{language}/{index}"
            item.id = f"cyberseceval/{condition}/{case}"
            item.scores = {report.SCORER: Score(
                value={"output_present": 1, "output_nonempty": 1, "scan_complete": 1,
                       "icd_flagged_output": flagged, "icd_finding_count": flagged, "loc": 12,
                       "skill_loaded": 1 if condition == "codeguard" else math.nan},
                answer=CANARY, explanation=CANARY,
                metadata={"case_id": case, "condition": condition, "language": language,
                          "cwe": "CWE-119", "icd": IDENTITY, "scan_reason": None,
                          "findings": [{"severity": "warning", "private": CANARY}] * flagged},
            )}
            log.samples.append(item)
    log.results.total_samples = len(log.samples)
    log.results.completed_samples = len(log.samples)
    log.results.scores = [EvalScore(name="scan_complete", scorer=report.SCORER, metrics={})]
    usage = ModelUsage()
    for item in log.samples:
        usage += item.model_usage[CANARY]
    log.stats.model_usage = {CANARY: usage}
    return log


def incomplete(item, reason):
    score = item.scores[report.SCORER]
    score.value.update(scan_complete=0, icd_flagged_output=math.nan, icd_finding_count=math.nan)
    score.metadata.update(scan_reason=reason, findings=None)
    if reason in ("missing_output", "empty_output"):
        score.value.update(output_nonempty=0, output_present=int(reason == "empty_output"))


@pytest.fixture
def campaign(save):
    baseline = cyber_log("baseline", (1, 1, 0, 1, 0))
    secure = cyber_log("secure_prompt", (0, 0, 0, 1, 0))
    guard = cyber_log("codeguard", (0, 1, 0, 1, 0))
    baseline.samples[4].scores = None
    baseline.samples[4].error = EvalError(message=CANARY, traceback=CANARY, traceback_ansi=CANARY)
    incomplete(guard.samples[2], "parse_error")
    incomplete(secure.samples[3], "missing_output")
    guard.samples[1].limit = EvalSampleLimit(type="time", limit=600)
    flagged = baseline.samples[0].scores[report.SCORER]
    flagged.metadata["findings"][0]["severity"] = "error"
    flagged.metadata["findings"].append({"severity": "warning", "private": CANARY})
    flagged.value["icd_finding_count"] = 2
    guard.samples[1].scores[report.SCORER].metadata["findings"][0]["severity"] = "info"
    return [("Model A", save(log, f"{condition}.eval")) for condition, log in (
        ("baseline", baseline), ("secure", secure), ("guard", guard)
    )]


def test_export_keeps_all_attempts_and_matched_statistics_private(tmp_path, campaign, offline):
    originals = [path.read_bytes() for _, path in campaign]
    output = tmp_path / "report"
    exporter.export_results(campaign, output)
    assert {p.name for p in output.iterdir()} == {
        "index.md", "results.csv", "samples.csv",
        *(f"{chart}.png" for chart in CHART_NAMES),
    }
    summaries = rows(output / "results.csv")
    assert [r["shared_cases"] for r in summaries] == ["2"] * 3
    assert [r["scanned_cases"] for r in summaries] == ["4"] * 3
    assert [float(r["flagged_pct"]) for r in summaries] == [100, 0, 50]
    assert [r["findings"] for r in summaries] == ["3", "0", "1"]
    assert [r["severity_error"] for r in summaries] == ["1", "0", "0"]
    assert [r["severity_warning"] for r in summaries] == ["2", "0", "0"]
    assert [r["severity_info"] for r in summaries] == ["0", "0", "1"]
    for row in summaries:
        assert sum(int(row[field]) for field in report.SEVERITY_FIELDS) == int(row["findings"])
        assert int(row["scanned_cases"]) + sum(int(row[field]) for field in report.COVERAGE_FIELDS) == int(row["cases"])
    attempts = rows(output / "samples.csv")
    assert len(attempts) == 15
    assert sorted(r["scan_reason"] for r in attempts if r["scan_reason"]) == [
        "missing_output", "parse_error", "sample_error",
    ]
    assert all(r["flagged_output"] == "" for r in attempts if r["scan_complete"] == "0")
    assert all(r[field] == "" for r in attempts if r["scan_complete"] == "0" for field in report.SEVERITY_FIELDS)
    stopped = next(r for r in attempts if r["limit"] == "time")
    assert stopped["scan_complete"] == "1" and stopped["outcome"] == "Time limit"
    assert all(not any("ci_" in key for key in row) for row in summaries)
    page = (output / "index.md").read_text()
    assert page.startswith("# CyberSecEval results")
    assert "Leaving them out can change how the runs compare" in page and "CodeGuard 1.5.0" in page
    assert "Likely vulnerabilities" not in page and "rule confidence" not in page
    assert "Paired comparisons" not in page and "Total USD vs baseline" in page
    assert "## Scan coverage" in page and "Missing output | Parse error | Sample error" in page
    assert "severity.png" in page and "coverage.png" not in page
    assert originals == [path.read_bytes() for _, path in campaign]
    for path in output.iterdir():
        for private in (CANARY, str(tmp_path), "/Users/"):
            assert private.encode() not in path.read_bytes()
    second = tmp_path / "repeat"
    exporter.export_results(campaign, second)
    assert all(p.read_bytes() == (second / p.name).read_bytes() for p in output.iterdir())


@pytest.mark.parametrize("change", [
    "wrong_identity", "wrong_case", "wrong_language", "unsafe_cwe", "unknown_reason",
    "numeric_incomplete", "missing_flag", "contradictory_count", "empty_complete", "generation",
    "unknown_severity", "missing_severity", "malformed_finding",
])
def test_malformed_evidence_cannot_become_clean(save, change):
    log = cyber_log()
    item = log.samples[0]
    score = item.scores[report.SCORER]
    if change == "wrong_identity": score.metadata["icd"] = {}
    elif change == "wrong_case": score.metadata["case_id"] = "instruct-v2/c/999"
    elif change == "wrong_language": score.metadata["language"] = "cpp"
    elif change == "unsafe_cwe": score.metadata["cwe"] = CANARY
    elif change == "unknown_reason": incomplete(item, "unknown")
    elif change == "numeric_incomplete":
        incomplete(item, "parse_error")
        score.value.update(icd_finding_count=0, icd_flagged_output=0)
    elif change == "missing_flag": score.value["icd_flagged_output"] = math.nan
    elif change == "contradictory_count": score.value["icd_finding_count"] = 2
    elif change == "empty_complete": score.value["output_nonempty"] = 0
    elif change == "generation": log.eval.metadata["phase"] = "generation"
    elif change in ("unknown_severity", "missing_severity", "malformed_finding"):
        score.value.update(icd_flagged_output=1, icd_finding_count=1)
        score.metadata["findings"] = [{"severity": CANARY}] if change == "unknown_severity" else [{}] if change == "missing_severity" else [None]
    with pytest.raises(ReportError):
        exporter.read_run("Model", save(log))


def test_benchmarks_cannot_be_mixed(save):
    with pytest.raises(ReportError, match="one benchmark"):
        exporter.read_runs([
            ("Model A", save(cyber_log(), "cyber.eval")),
            ("Model B", save(log_for([sample(1)]), "security.eval")),
        ])


def test_large_recorded_provenance_does_not_prevent_reporting(save):
    log = cyber_log(flags=(1,))
    identity = {**IDENTITY, "command": [CANARY * 60]}
    log.eval.metadata["batch_scan"]["grader"] = identity
    log.samples[0].scores[report.SCORER].metadata["icd"] = identity
    path = save(log)
    _, _, samples = exporter.read_run("Model", path)
    assert samples[0]["flagged_output"] == 1


def test_pricing_is_explicit_and_uses_existing_token_accounting(tmp_path, save, offline):
    log = cyber_log(flags=(0,))
    log.stats.model_usage[CANARY].total_cost = None
    log.samples[0].model_usage[CANARY].total_cost = None
    runs = [("Model", save(log))]
    with pytest.raises(ReportError, match="Supply --prices"):
        exporter.export_results(runs, tmp_path / "missing-prices")
    assert not (tmp_path / "missing-prices").exists()
    prices = tmp_path / "prices.json"
    prices.write_text(json.dumps({"Model": {"input": 1, "output": 2, "input_cache_read": .2, "input_cache_write": 1}}))
    exporter.export_results(runs, tmp_path / "priced", prices=prices)
    result = rows(tmp_path / "priced/results.csv")[0]
    assert float(result["estimated_cost_usd"]) == pytest.approx(94 / 1_000_000)
    assert result["recorded_cost_usd"] == ""


def test_empty_cohort_and_epochs_are_kept_separate(save):
    logs = [cyber_log(c, flags=(0, 1), epochs=2) for c in ("baseline", "secure_prompt")]
    for item in logs[0].samples[:2]: incomplete(item, "parse_error")
    runs = [("Model", save(log, f"{index}.eval")) for index, log in enumerate(logs)]
    raw, samples = exporter.read_runs(runs)
    public = exporter.public_results(raw, samples)
    assert [row["shared_cases"] for row in public] == [0, 0, 2, 2]
    assert [row["flagged_pct"] for row in public] == ["", "", 50, 50]
    assert all(row[field] == "" for row in public[:2] for field in report.SEVERITY_FIELDS)
    assert [row["scan_parse_error"] for row in public] == [2, 0, 0, 0]
    selected = exporter.public_results(raw, samples, epoch=2)
    assert all(row["epoch"] == 2 and row["shared_cases"] == 2 for row in selected)
    page = renderer.results_page(public, title="CyberSecEval", multiple_epochs=True,
                                 definition=report.report_definition())
    assert page.count("### Scan coverage") == 2
    attempts = exporter._public_samples(samples, benchmark="CyberSecEval")
    figures = renderer.build_figures(public, attempts, multiple=True, definition=report.report_definition())
    empty = figures["severity-epoch-1"].axes[0]
    assert sum(label.get_text() == "Not recorded" for label in empty.texts) == 2
    assert not empty.patches
    for figure in figures.values(): figure.clear()


@pytest.mark.parametrize("language", [
    "c", "cpp", "csharp", "java", "javascript", "php", "python", "rust",
])
def test_every_supported_language_can_be_reported(tmp_path, save, language):
    log = cyber_log(flags=(0,))
    item = log.samples[0]
    case = f"instruct-v2/{language}/0"
    item.id = f"cyberseceval/codeguard/{case}"
    item.scores[report.SCORER].metadata.update(case_id=case, language=language)
    path = save(log)
    _, samples = exporter.read_runs([("Model", path)], language=language)
    assert samples[0]["language"] == language
    exporter.export_results([("Model", path)], tmp_path / "report", language=language)
    assert (tmp_path / "report/index.md").read_text().startswith(
        f"# CyberSecEval results ({report.LANGUAGES[language]})\n"
    )


def test_figures_use_exported_findings_and_count_every_attempt(campaign):
    raw, samples = exporter.read_runs(campaign)
    public = exporter.public_results(raw, samples)
    attempts = exporter._public_samples(samples, benchmark="CyberSecEval")
    figures = renderer.build_figures(public, attempts, definition=report.report_definition())
    assert set(figures) == set(CHART_NAMES)
    assert [tuple(points.get_offsets()[0]) for points in figures["findings"].axes[0].collections] == [
        (.5, 3), (.5, 0), (.5, 1),
    ]
    outcomes = figures["outcomes"].axes[0]
    assert [label.get_text() for label in outcomes.get_yticklabels()] == [
        "Baseline", "Secure prompt", "CodeGuard 1.5.0",
    ]
    assert [[bar.get_width() for bar in bars] for bars in outcomes.containers] == [
        [4, 5, 4],  # Completed, by condition.
        [0, 0, 0],  # Turn limit.
        [0, 0, 1],  # Time limit.
        [0, 0, 0],  # Other limit.
        [1, 0, 0],  # Error.
    ]
    severity = figures["severity"].axes[0]
    assert [[bar.get_width() for bar in bars] for bars in severity.containers] == [
        [1, 0, 0], [2, 0, 0], [0, 0, 1], [0, 0, 0],
    ]
    assert not figures["findings"].axes[0].containers  # No error bars.
    for figure in figures.values(): figure.clear()


def test_coverage_table_accounts_for_every_incomplete_reason(tmp_path, save, offline):
    log = cyber_log(flags=(1, 0, 0, 0, 0, 0, 0, 0))
    reasons = ("missing_output", "empty_output", "parse_error",
               "rule_timeout", "resource_limit", "sample_error")
    for item, reason in zip(log.samples[2:], reasons, strict=True):
        if reason == "sample_error":
            item.scores = None
            item.error = EvalError(message=CANARY, traceback=CANARY, traceback_ansi=CANARY)
        else:
            incomplete(item, reason)
    output = tmp_path / "report"
    exporter.export_results([("Model", save(log))], output)
    row = rows(output / "results.csv")[0]
    assert row["cases"] == "8" and row["scanned_cases"] == "2"
    assert all(row[f"scan_{reason}"] == "1" for reason in reasons)
    assert row["findings"] == row["severity_warning"] == "1"
    page = (output / "index.md").read_text()
    assert all(label in page for label in (
        "Missing output", "Empty output", "Parse error",
        "Analysis timeout", "Resource limit", "Sample error",
    ))
    assert "2 of 8 (25%) | 1 | 1 | 1 | 1 | 1 | 1" in page


@pytest.mark.parametrize("language,cases,tokens,recorded_cost,priced_cost", [
    ("c", 3, 700, .7, 658 / 1_000_000),
    ("cpp", 2, 3000, 3, 2820 / 1_000_000),
])
@pytest.mark.parametrize("estimated", [False, True])
def test_language_pages_use_sample_usage_and_baseline_cost_change(
    tmp_path, save, offline, language, cases, tokens, recorded_cost, priced_cost, estimated,
):
    runs = []
    for factor, condition in enumerate(("baseline", "secure_prompt", "codeguard"), 1):
        log = cyber_log(condition)
        # C uses 1 + 2 + 4 units; C++ uses 10 + 20. A single unit is 100 tokens.
        for sample_scale, item in zip((1, 10, 2, 20, 4), log.samples, strict=True):
            usage = item.model_usage[CANARY]
            for key in ("input_tokens", "output_tokens", "input_tokens_cache_read", "total_tokens"):
                setattr(usage, key, getattr(usage, key) * sample_scale * factor)
            usage.total_cost *= sample_scale * factor
        # Whole-run retry totals must not be copied onto a language-specific page.
        log.stats.model_usage = {CANARY: ModelUsage(total_tokens=999999, total_cost=99)}
        runs.append(("Model", save(log, condition + ".eval")))
    prices = tmp_path / "prices.json"
    prices.write_text(json.dumps({"Model": {"input": 1, "output": 2, "input_cache_read": .2, "input_cache_write": 1}}))
    args = ["--language", language, "--output-dir", str(tmp_path / "report")]
    for model, path in runs: args += ["--run", model, str(path)]
    if estimated: args += ["--prices", str(prices)]
    exporter.main(args)
    summaries = rows(tmp_path / "report/results.csv")
    for factor, row in enumerate(summaries, 1):
        assert row["language"] == language and int(row["cases"]) == cases
        assert float(row["tokens_per_case"]) == pytest.approx(tokens * factor / cases)
        cost_field = "estimated_cost_usd" if estimated else "recorded_cost_usd"
        expected = (priced_cost if estimated else recorded_cost) * factor
        assert float(row[cost_field]) == pytest.approx(expected)
        assert float(row["cost_change_pct"]) == pytest.approx(100 * (factor - 1))
    assert {row["language"] for row in rows(tmp_path / "report/samples.csv")} == {language}
    page = (tmp_path / "report/index.md").read_text()
    assert "Total USD vs baseline" in page and "+100.0%" in page and "+200.0%" in page
    assert "cannot be split by language" in page


@pytest.mark.parametrize("epochs,language,expected_tokens,expected_prices", [
    (1, None, [100], [282]),
    (1, "c", [50], [94]),
    (2, None, [200 / 3, 100], [188, 282]),
    (2, "c", [50, 100], [94, 188]),
])
def test_costs_disclose_partial_recorded_usage(
    tmp_path, save, epochs, language, expected_tokens, expected_prices,
):
    log = cyber_log(flags=(0, 1, 0), epochs=epochs)
    log.samples[0].model_usage = {}
    log.samples[0].limit = EvalSampleLimit(type="time", limit=600)
    prices = tmp_path / "prices.json"
    prices.write_text(json.dumps({"Model": {"input": 1, "output": 2, "input_cache_read": .2, "input_cache_write": 1}}))
    source = save(log)
    exporter.export_results([("Model", source)], tmp_path / "known", language=language, prices=prices)
    summaries = rows(tmp_path / "known/results.csv")
    assert [row["usage_missing_cases"] for row in summaries] == ["1"] + ["0"] * (epochs - 1)
    assert [float(row["tokens_per_case"]) for row in summaries] == pytest.approx(expected_tokens)
    assert [float(row["estimated_cost_usd"]) for row in summaries] == pytest.approx([
        price / 1_000_000 for price in expected_prices
    ])
    # Partial estimates must not become complete recorded costs.
    assert summaries[0]["recorded_cost_usd"] == ""
    page = (tmp_path / "known/index.md").read_text()
    assert "Attempts without token counts: CodeGuard 1.5.0: 1." in page
    assert "Their cost may be missing from estimates" in page
    if language is not None or epochs > 1:
        # No per-attempt usage for a selected epoch remains unknown, not zero.
        for item in log.samples:
            if item.epoch == 1:
                item.model_usage = {}
        with pytest.raises(ReportError, match="no recorded model usage"):
            exporter.export_results(
                [("Model", save(log, "empty.eval"))], tmp_path / "unknown", language=language, prices=prices,
            )
        assert not (tmp_path / "unknown").exists()


def test_language_filter_applies_before_matching_case_inventories(save):
    base = cyber_log("baseline")
    guard = cyber_log("codeguard", flags=(0, 1, 0))
    base.samples = base.samples[:4]
    base.results.total_samples = len(base.samples)
    base.results.completed_samples = len(base.samples)
    raw, samples = exporter.read_runs([
        ("Model", save(base, "base.eval")), ("Model", save(guard, "guard.eval")),
    ], language="c")
    assert len(raw) == 2 and len(samples) == 4
    assert {sample["language"] for sample in samples} == {"c"}


def test_advice_severity_is_preserved_in_csv_and_chart(tmp_path, save, offline):
    from matplotlib.text import Text

    log = cyber_log(flags=(1, 1, 1, 1))
    for index, (item, language, severity) in enumerate(zip(
        log.samples, ('c', 'cpp', 'csharp', 'rust'), ('error', 'warning', 'info', 'advice'),
    )):
        case = f'instruct-v2/{language}/{index}'
        item.id = f'cyberseceval/codeguard/{case}'
        metadata = item.scores[report.SCORER].metadata
        metadata.update(case_id=case, language=language)
        metadata['findings'][0]['severity'] = severity
    path = save(log)
    output = tmp_path / 'report'
    exporter.export_results([('Model A', path)], output)
    result, = rows(output / 'results.csv')
    assert result['findings'] == '4'
    assert all(result[field] == '1' for field in report.SEVERITY_FIELDS)
    rust, = [row for row in rows(output / 'samples.csv') if row['language'] == 'rust']
    assert rust['severity_advice'] == '1' and rust['severity_info'] == '0'
    runs, samples = exporter.read_runs([('Model A', path)])
    figures = renderer.build_figures(
        exporter.public_results(runs, samples),
        exporter._public_samples(samples, benchmark="CyberSecEval"),
        definition=report.report_definition(),
    )
    figure = figures['severity']
    assert 'Advice' in [text.get_text() for text in figure.findobj(Text)]
    assert sum(patch.get_width() for patch in figure.axes[0].patches) == 4
    for rendered in figures.values():
        rendered.clear()


@pytest.mark.parametrize('benchmark,language', [('SecurityEval', 'python'), ('CyberSecEval', 'c')])
def test_redundant_language_filter_preserves_run_usage(tmp_path, save, benchmark, language):
    log = log_for([sample(1)]) if benchmark == 'SecurityEval' else cyber_log(flags=(1,))
    # Recorded retries are known at run level but absent from the final sample.
    usage = log.stats.model_usage[CANARY]
    usage.input_tokens += 40
    usage.total_tokens += 40
    usage.total_cost += .1
    path = save(log)
    prices = tmp_path / 'prices.json'
    prices.write_text(json.dumps({'Model': {
        'input': 1, 'output': 2, 'input_cache_read': .2, 'input_cache_write': 1,
    }}))
    exporter.export_results([('Model', path)], tmp_path / 'whole', prices=prices)
    exporter.export_results([('Model', path)], tmp_path / 'filtered', prices=prices, language=language)
    assert (tmp_path / 'whole/results.csv').read_bytes() == (tmp_path / 'filtered/results.csv').read_bytes()
    assert (tmp_path / 'whole/samples.csv').read_bytes() == (tmp_path / 'filtered/samples.csv').read_bytes()
    assert 'cannot be split by language' not in (tmp_path / 'filtered/index.md').read_text()


def test_other_models_language_subset_does_not_change_whole_run_costs(tmp_path, save):
    first = cyber_log(flags=(1,))
    first.stats.model_usage[CANARY].input_tokens += 40
    first.stats.model_usage[CANARY].total_tokens += 40
    first.stats.model_usage[CANARY].total_cost += .1
    second = cyber_log(flags=(1, 0))
    second.eval.task_id = 'second-model'
    paths = [('First', save(first, 'first.eval')), ('Second', save(second, 'second.eval'))]
    rates = {'input': 1, 'output': 2, 'input_cache_read': .2, 'input_cache_write': 1}
    prices = tmp_path / 'prices.json'
    prices.write_text(json.dumps({'First': rates, 'Second': rates}))
    exporter.export_results(paths[:1], tmp_path / 'alone', language='c', prices=prices)
    exporter.export_results(paths, tmp_path / 'together', language='c', prices=prices)
    assert rows(tmp_path / 'alone/results.csv')[0] == rows(tmp_path / 'together/results.csv')[0]
