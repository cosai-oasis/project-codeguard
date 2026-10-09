"""Recorded costs and conservative estimates from usage summaries."""
import json
import math

import pytest
from inspect_ai.log import EvalError
from inspect_ai.model import ModelUsage

from codeguard_evals import export_results as exporter
from codeguard_evals.export_results import ExportError, export_results
from tests.synthetic_logs import CANARY, log_for, sample, save, offline, rows, repeated_log


def cost_config(tmp_path, label="Model A"):
    path = tmp_path / "prices.json"
    path.write_text(json.dumps({
        label: {"input": 1.0, "output": 4.0, "input_cache_read": 0.1, "input_cache_write": 1.25}
    }))
    return path


def token_usage(multiplier=1, **changes):
    fields = dict(input_tokens=50 * multiplier, input_tokens_cache_read=20 * multiplier,
                  input_tokens_cache_write=20 * multiplier, output_tokens=10 * multiplier,
                  total_tokens=100 * multiplier)
    fields.update(changes)
    return ModelUsage(**fields)


def unpriced_log_with_retry():
    item = sample(1)
    item.model_usage = {CANARY: token_usage()}
    log = log_for([item])
    log.eval.packages["inspect_ai"] = "0.3.260"
    log.stats.model_usage = {CANARY: token_usage(2)}  # Includes unsaved retry usage.
    return log


@pytest.mark.parametrize(
    "costs, expected",
    [([None], ""), ([0.0], "0.0"), ([0.25, 0.75], "1.0"), ([0.25, None], "")],
)
def test_recorded_cost_requires_complete_totals(tmp_path, save, costs, expected):
    log = log_for([sample(1)])
    log.stats.model_usage = {
        f"{CANARY}-{index}": ModelUsage(total_cost=cost)
        for index, cost in enumerate(costs)
    }
    log.samples[0].model_usage = log.stats.model_usage
    source = save(log)
    if expected == "":
        with pytest.raises(ExportError, match="complete costs"):
            export_results([("model", source)], tmp_path / "export")
        assert not (tmp_path / "export").exists()
    else:
        export_results([("model", source)], tmp_path / "export")
        assert rows(tmp_path / "export" / "results.csv")[0]["recorded_cost_usd"] == expected


def test_multi_epoch_missing_cost_does_not_become_a_partial_total(tmp_path, save):
    log = repeated_log()
    log.samples[0].model_usage[CANARY].total_cost = None
    source = save(log)
    _, run, samples = exporter.read_run("Model A", source)
    summary = exporter.public_results([run], samples)
    assert summary[0]["recorded_cost_usd"] == ""
    assert summary[1]["recorded_cost_usd"] == 1.0
    with pytest.raises(ExportError, match="complete costs"):
        export_results([("Model A", source)], tmp_path / "export")
    assert not (tmp_path / "export").exists()


def test_cost_per_case_and_baseline_changes_use_the_same_model_and_epoch(tmp_path, save):
    # Two cases per epoch; deliberately different baselines expose cross-group comparisons.
    specs = [
        ("Model A", "baseline", (1.0, 2.0)),
        ("Model A", "codeguard", (2.0, 1.0)),
        ("Model B", "baseline", (4.0, 0.0)),
        ("Model B", "codeguard", (1.0, 3.0)),
    ]
    runs = []
    for index, (model, condition, totals) in enumerate(specs):
        log = repeated_log(condition)
        log.eval.task_id = f"task-{index}"
        for item in log.samples:
            item.model_usage[CANARY].total_cost = totals[item.epoch - 1] / 2
        runs.append((model, save(log, f"run-{index}.eval")))
    export_results(runs, tmp_path / "export")
    results = rows(tmp_path / "export/results.csv")
    assert [(row["model"], row["condition"], row["epoch"]) for row in results] == [
        (model, condition, str(epoch)) for epoch in (1, 2) for model, condition, _ in specs
    ]
    assert [float(row["recorded_cost_usd"]) for row in results] == [1, 2, 4, 1, 2, 1, 0, 3]
    assert [float(row["cost_per_case_usd"]) for row in results] == [0.5, 1, 2, 0.5, 1, 0.5, 0, 1.5]
    assert [float(row["cost_change_pct"]) if row["cost_change_pct"] else "" for row in results] == [
        0, 100, 0, -75, 0, -50, "", "",
    ]


def test_mixed_priced_and_unpriced_samples_leave_run_cost_unknown(tmp_path, save):
    old, new = sample(1), sample(2)
    old.model_usage[CANARY].total_cost = None
    new.model_usage[CANARY].total_cost = 0.5
    source = save(log_for([old, new]))
    _, run, samples = exporter.read_run("Model A", source)
    result = exporter.public_results([run], samples)[0]
    assert result["recorded_cost_usd"] == result["cost_per_case_usd"] == ""
    with pytest.raises(ExportError, match="complete costs"):
        export_results([("Model A", source)], tmp_path / "export")
    assert not (tmp_path / "export").exists()


@pytest.mark.parametrize("whole_cost", [0.5, 0.75])
def test_unallocated_retry_usage_cannot_prove_complete_pricing(tmp_path, save, whole_cost):
    item = sample(1)
    item.model_usage[CANARY].total_cost = 0.5
    log = log_for([item])
    log.stats.model_usage = {CANARY: ModelUsage(total_tokens=200, total_cost=whole_cost)}
    source = save(log)
    _, run, _ = exporter.read_run("Model A", source)
    assert run["recorded_cost_usd"] == ""
    with pytest.raises(ExportError, match="complete costs"):
        export_results([("Model A", source)], tmp_path / "export")
    assert not (tmp_path / "export").exists()


def test_estimates_include_cached_usage_and_retries(tmp_path, save, offline):
    source = save(unpriced_log_with_retry())
    before = source.read_bytes()
    export_results([("Model A", source)], tmp_path / "export", prices=cost_config(tmp_path))
    result = rows(tmp_path / "export/results.csv")[0]
    # Normal input 100 + cached reads 4 + cache writes 50 + output 80, per million.
    assert float(result["estimated_cost_usd"]) == pytest.approx(234 / 1_000_000)
    assert result["recorded_cost_usd"] == ""
    assert result["cost_per_case_usd"] == result["estimated_cost_usd"]
    assert float(result["tokens_per_case"]) == 200
    assert source.read_bytes() == before
    for path in (tmp_path / "export").iterdir():
        assert CANARY.encode() not in path.read_bytes()
    assert exporter.DEFAULT_COST_NOTE in (tmp_path / "export/index.md").read_text()


@pytest.mark.parametrize("model,version,writes", [
    ("openai/" + CANARY, "0.3.260", None),
    ("openai/" + CANARY, "0.3.255", 20),
    ("openai/" + CANARY, "0.3.255", 0),
    (CANARY, "0.3.255", None),
])
def test_complete_recorded_cost_is_used_without_prices(tmp_path, save, model, version, writes):
    item = sample(1)
    item.model_usage = {model: token_usage(
        input_tokens=70 - (writes or 0), input_tokens_cache_write=writes, total_cost=0.5,
    )}
    log = log_for([item])
    log.eval.packages["inspect_ai"] = version
    export_results([("Model A", save(log))], tmp_path / "export")
    row = rows(tmp_path / "export/results.csv")[0]
    assert row["recorded_cost_usd"] == "0.5"
    assert row["estimated_cost_usd"] == ""
    assert "## Cost estimates" not in (tmp_path / "export/index.md").read_text()


@pytest.mark.parametrize("epochs", [1, 2])
def test_supplied_prices_use_one_basis_and_preserve_recorded_costs(tmp_path, save, epochs):
    runs = []
    for condition in ("baseline", "codeguard"):
        cases = []
        for epoch in range(1, epochs + 1):
            item = sample(1, condition=condition)
            item.epoch = epoch
            # Both conditions use identical tokens. The recorded baseline used double the prices.
            cost = 0.000234 * epoch if condition == "baseline" else None
            item.model_usage = {CANARY: token_usage(epoch, total_cost=cost)}
            cases.append(item)
        log = log_for(cases, condition=condition, task_id=condition)
        log.eval.config.epochs = epochs
        runs.append(("Model A", save(log, f"{condition}.eval")))
    before = [path.read_bytes() for _, path in runs]
    export_results(runs, tmp_path / "export", prices=cost_config(tmp_path))
    results = rows(tmp_path / "export/results.csv")
    assert len(results) == 2 * epochs
    for row in results:
        epoch = int(row["epoch"])
        if row["condition"] == "baseline":
            assert float(row["recorded_cost_usd"]) == pytest.approx(0.000234 * epoch)
        else:
            assert row["recorded_cost_usd"] == ""
        assert float(row["estimated_cost_usd"]) == pytest.approx(0.000117 * epoch)
        assert float(row["cost_per_case_usd"]) == pytest.approx(0.000117 * epoch)
        assert float(row["cost_change_pct"]) == 0
    assert [path.read_bytes() for _, path in runs] == before


@pytest.mark.parametrize("known_zero", [False, True])
def test_errored_attempt_usage_is_unknown_unless_zero_is_recorded(tmp_path, save, known_zero):
    log = repeated_log()
    for item in log.samples:
        item.model_usage = {CANARY: token_usage(item.epoch)}
    failed = log.samples[0]
    failed.scores = None
    failed.error = EvalError(message=CANARY, traceback=CANARY, traceback_ansi=CANARY)
    failed.model_usage = {CANARY: token_usage(0)} if known_zero else {}
    log.stats.model_usage = {CANARY: token_usage(5)}
    source = save(log)
    output = tmp_path / "export"
    prices = cost_config(tmp_path)
    if not known_zero:
        with pytest.raises(ExportError, match="complete usage"):
            export_results([("Model A", source)], output, prices=prices)
        assert not output.exists()
    else:
        export_results([("Model A", source)], output, prices=prices)
        first, second = rows(output / "results.csv")
        assert first["unfinished"] == "1"
        assert float(first["tokens_per_case"]) == 50
        assert float(first["estimated_cost_usd"]) == pytest.approx(0.000117)
        assert float(second["estimated_cost_usd"]) == pytest.approx(0.000468)


@pytest.mark.parametrize("epochs,version", [(1, "0.3.255"), (2, "0.3.255"), (1, None)])
def test_old_openai_recorded_cost_requires_an_estimate(tmp_path, save, epochs, version):
    cases = []
    for epoch in range(1, epochs + 1):
        item = sample(1)
        item.epoch = epoch
        # Old Inspect priced 70 input, 20 cache-read, and 10 output tokens.
        item.model_usage = {"openai/" + CANARY: token_usage(
            epoch, input_tokens=70 * epoch, input_tokens_cache_write=None,
            total_cost=112 * epoch / 1_000_000,
        )}
        cases.append(item)
    log = log_for(cases)
    log.eval.config.epochs = epochs
    log.eval.packages = {"inspect_ai": version} if version else {}
    source = save(log)
    before = source.read_bytes()
    output = tmp_path / "export"
    with pytest.raises(ExportError, match="complete costs"):
        export_results([("Model A", source)], output)
    assert not output.exists()

    export_results([("Model A", source)], output, prices=cost_config(tmp_path))
    for epoch, row in enumerate(rows(output / "results.csv"), start=1):
        assert row["recorded_cost_usd"] == ""
        # Non-cached input uses 1.25 until the missing write split is known.
        assert float(row["estimated_cost_usd"]) == pytest.approx(129.5 * epoch / 1_000_000)
    assert source.read_bytes() == before


def test_partial_recorded_cost_is_not_added_to_estimate(tmp_path, save):
    log = unpriced_log_with_retry()
    log.samples[0].model_usage[CANARY].total_cost = 0.5
    log.stats.model_usage[CANARY].total_cost = 0.5
    export_results([("Model A", save(log))], tmp_path / "export", prices=cost_config(tmp_path))
    row = rows(tmp_path / "export/results.csv")[0]
    assert row["recorded_cost_usd"] == ""
    assert float(row["estimated_cost_usd"]) == pytest.approx(234 / 1_000_000)


@pytest.mark.parametrize("bad", [-1, True, "4.00", None, math.inf, math.nan])
def test_invalid_prices_write_nothing(tmp_path, save, bad):
    path = cost_config(tmp_path)
    data = json.loads(path.read_text())
    data["Model A"]["input"] = bad
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        export_results([("Model A", save(unpriced_log_with_retry()))], tmp_path / "export", prices=path)
    assert not (tmp_path / "export").exists()


@pytest.mark.parametrize("bad", [
    '{"model":{"input":1,"input":2}}',
    '{"note":"<script>private</script>","models":{}}',
    '{"model":{"input":1}}',
    '{}',
])
def test_bad_cost_config_writes_nothing(tmp_path, save, bad):
    path = tmp_path / "prices.json"
    path.write_text(bad)
    with pytest.raises(ValueError):
        export_results([("Model A", save(unpriced_log_with_retry()))], tmp_path / "export", prices=path)
    assert not (tmp_path / "export").exists()


@pytest.mark.parametrize("change", ["multiple_models", "missing_usage", "inconsistent_tokens"])
def test_ambiguous_usage_is_not_priced(tmp_path, save, change):
    log = unpriced_log_with_retry()
    if change == "multiple_models":
        log.stats.model_usage["another-model"] = token_usage()
    elif change == "missing_usage":
        log.stats.model_usage = {}
    else:
        log.stats.model_usage[CANARY].total_tokens += 1
    with pytest.raises(ValueError):
        export_results([("Model A", save(log))], tmp_path / "export", prices=cost_config(tmp_path))
    assert not (tmp_path / "export").exists()


@pytest.mark.parametrize("epoch,expected_epochs", [(None, ["1", "2"]), (2, ["2"])])
def test_epoch_estimates_use_saved_samples_and_exclude_unallocated_retries(tmp_path, save, epoch, expected_epochs):
    log = repeated_log()
    log.eval.packages["inspect_ai"] = "0.3.260"
    for item in log.samples:
        item.model_usage = {CANARY: token_usage(item.epoch)}
    log.stats.model_usage = {CANARY: token_usage(100)}
    export_results([("Model A", save(log))], tmp_path / "export", epoch=epoch, prices=cost_config(tmp_path))
    results = rows(tmp_path / "export/results.csv")
    assert [row["epoch"] for row in results] == expected_epochs
    expected = {"1": (0.000234, 0.000117), "2": (0.000468, 0.000234)}
    for row in results:
        assert (float(row["estimated_cost_usd"]), float(row["cost_per_case_usd"])) == pytest.approx(expected[row["epoch"]])
        assert row["recorded_cost_usd"] == ""


def test_pricing_cli_uses_public_labels_and_method_note(tmp_path, save):
    source = save(unpriced_log_with_retry())
    prices = cost_config(tmp_path, "Public label")
    exporter.main([
        "--run", "Public label", str(source), "--prices", str(prices),
        "--cost-note", "USD estimates at fixed standard rates.", "-o", str(tmp_path / "export"),
    ])
    row = rows(tmp_path / "export/results.csv")[0]
    assert row["model"] == "Public label"
    assert float(row["estimated_cost_usd"]) == pytest.approx(234 / 1_000_000)
    page = (tmp_path / "export/index.md").read_text()
    assert "USD estimates at fixed standard rates." in page
    assert CANARY not in page


@pytest.mark.parametrize("note", ["<script>private</script>", "[private](https://private.invalid)", ""])
def test_invalid_public_cost_note_writes_nothing(tmp_path, save, note):
    with pytest.raises(ValueError):
        export_results([("Model A", save(unpriced_log_with_retry()))], tmp_path / "export",
                       prices=cost_config(tmp_path), cost_note=note)
    assert not (tmp_path / "export").exists()


def test_missing_model_prices_are_not_silently_ignored(tmp_path, save):
    prices = cost_config(tmp_path)
    data = json.loads(prices.read_text())
    prices.write_text(json.dumps({"different-model": data["Model A"]}))
    with pytest.raises(ExportError, match="no configured prices"):
        export_results([("Model A", save(unpriced_log_with_retry()))], tmp_path / "export", prices=prices)
    assert not (tmp_path / "export").exists()


@pytest.mark.parametrize("epoch", [None, 1])
def test_adding_another_model_does_not_change_a_runs_usage(tmp_path, save, epoch):
    single = save(unpriced_log_with_retry(), "single.eval")
    multiple = repeated_log("baseline", 2)
    for item in multiple.samples:
        item.model_usage = {CANARY: token_usage(item.epoch)}
    multiple.stats.model_usage = {CANARY: token_usage(100)}
    multiple_source = save(multiple, "multiple.eval")
    prices = cost_config(tmp_path)
    rates = json.loads(prices.read_text())
    rates["Model B"] = rates["Model A"]
    prices.write_text(json.dumps(rates))
    export_results([("Model A", single)], tmp_path / "alone", epoch=epoch, prices=prices)
    export_results([("Model A", single), ("Model B", multiple_source)], tmp_path / "together",
                   epoch=epoch, prices=prices)
    alone = rows(tmp_path / "alone/results.csv")[0]
    together = rows(tmp_path / "together/results.csv")[0]
    assert together == alone
    assert float(together["tokens_per_case"]) == 200
    assert float(together["estimated_cost_usd"]) == pytest.approx(234 / 1_000_000)


@pytest.mark.parametrize("version,writes,expected", [
    ("0.3.255", None, 131.5),  # 70 non-cached input tokens at the higher rate.
    ("0.3.272", None, 114),    # Missing writes mean zero in the fixed version.
    ("0.3.255", 20, 119),     # Explicit cache-write counts are used as recorded.
])
def test_known_and_missing_cache_writes_use_the_right_rates(tmp_path, save, version, writes, expected):
    model = "openai/" + CANARY
    item = sample(1)
    usage = ModelUsage(input_tokens=70 if writes is None else 50, input_tokens_cache_read=40,
                       input_tokens_cache_write=writes, output_tokens=10, total_tokens=120)
    item.model_usage = {model: usage}
    log = log_for([item])
    log.eval.packages["inspect_ai"] = version
    source = save(log)
    before = source.read_bytes()
    export_results([("Model A", source)], tmp_path / "export", prices=cost_config(tmp_path))
    assert float(rows(tmp_path / "export/results.csv")[0]["estimated_cost_usd"]) == pytest.approx(expected / 1_000_000)
    assert source.read_bytes() == before
