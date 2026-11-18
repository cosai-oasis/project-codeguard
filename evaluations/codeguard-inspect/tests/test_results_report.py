"""Results page and chart tests; figures show recorded values, never re-aggregate."""

from __future__ import annotations

import io
import math
import warnings
from pathlib import Path

import pytest
from inspect_ai.log import EvalError, EvalSampleLimit, write_eval_log
from matplotlib import rc_context
from matplotlib.text import Text
from PIL import Image

import codeguard_evals.export_results as exporter
import codeguard_evals.results_report as report
from codeguard_evals.export_results import SCORER
from tests.synthetic_logs import CANARY, log_for, sample, values, save, repeated_log


@pytest.fixture
def exported(tmp_path: Path):
    """One run with a time stop, a turn stop, an invalid output, and an error."""
    timeout = sample(
        1, values(changed=0), limit=EvalSampleLimit(type="time", limit=600)
    )
    flagged = sample(
        2, values(findings=2), limit=EvalSampleLimit(type="turn", limit=16)
    )
    invalid = sample(3, values(valid=0))
    for metric in exporter.METRICS:
        if metric not in {"changed_output", "valid_output", "loc", "skill_loaded"}:
            invalid.scores[SCORER].value[metric] = math.nan
    failure = sample(4)
    failure.scores = None
    failure.error = EvalError(message=CANARY, traceback=CANARY, traceback_ansi=CANARY)
    source = tmp_path / "synthetic.eval"
    write_eval_log(log_for([timeout, flagged, invalid, failure]), source)
    _, result, samples = exporter.read_run("Model A", source)
    return [result], samples


def public_data(results, samples):
    return exporter.public_results(results, samples), exporter._public_samples(samples)


def make_page(title, results, samples, **kwargs):
    return report.results_page(exporter.public_results(results, samples), title=title,
                               comparison_note=exporter.comparison_note(results),
                               multiple_epochs=any(row["epochs"] > 1 for row in results), **kwargs)


def figures(results, samples):
    with rc_context(dict(report.STYLE)):
        return report.build_figures(*public_data(results, samples), multiple=any(row["epochs"] > 1 for row in results))


def test_page_warns_when_run_settings_differ_or_are_missing(exported):
    results, samples = exported
    base = results[0]
    same = dict(base, run="same")
    assert "Check before comparing" not in make_page(
        "Title", [base, same], samples
    )

    other = dict(base, run="other", agent_turn_limit=8, harness_commit="0123456789")
    unrecorded = dict(base, run="unrecorded", agent_seconds="")
    page = make_page("Title", [base, other, unrecorded], [])
    assert "> **Check before comparing:** settings differ" in page
    assert all(label in page for label in ("turn limit", "agent time limit", "harness version"))

    unrecorded_b = dict(base, run="b", agent_seconds="")
    page = make_page("Title", [base, unrecorded_b], [])
    assert "> **Check before comparing:** settings differ for agent time limit." in page
    both = [dict(base, agent_seconds=""), dict(base, run="b", agent_seconds="")]
    page = make_page("Title", both, [])
    assert "> **Check before comparing:** not recorded: agent time limit." in page

    revised = dict(base, run="revised", harness_commit="0123456789")
    page = make_page("Title", [base, revised], [])
    assert "Check before comparing" not in page
    assert "Recorded comparison settings match; harness snapshots differ." in page


def test_shared_cases_exclude_unusable_outputs_but_keep_valid_limit_stops(exported):
    results, samples = exported
    # Case 1 is unchanged, 3 is invalid, and 4 errored: only case 2 is shared.
    other = dict(results[0], run="other", condition="baseline", codeguard_version="")
    copies = [dict(case, run="other", changed_output=1) for case in samples]
    copies[1]["finding_count"] = 5
    page = make_page("Title", [results[0], other], samples + copies)
    assert "### Model A (1 shared case)" in page
    assert "| Baseline | 5 | 0 | 0 |" in page
    assert "| CodeGuard 1.5.0 | 2 | 0 | 0 |" in page


@pytest.mark.parametrize(
    "field, value, label",
    [
        ("agent_output_tokens", 1, "output token limit"),
        ("inspect_swe_version", "0.1.0", "Inspect SWE version"),
        ("python_version", "3.13.1", "Python version"),
        ("sample_shuffle", "false", "sample order"),
        ("max_samples", 99, "sample concurrency"),
        ("max_sandboxes", 99, "sandbox concurrency"),
        ("max_connections", 99, "connection limit"),
        ("max_retries", 99, "retry limit"),
    ],
)
def test_material_setting_changes_warn(exported, field, value, label):
    results, _ = exported
    base = results[0]
    changed = dict(base, run="changed", **{field: value})
    page = make_page("Title", [base, changed], [])
    assert f"> **Check before comparing:** settings differ for {label}." in page


@pytest.mark.parametrize(
    "field, label",
    [
        ("dataset_sha256", "dataset"),
        ("rules_sha256", "scanner"),
        ("semgrep_image_digest", "scanner"),
        ("harness_dirty", "harness version"),
    ],
)
def test_missing_secondary_provenance_fields_warn(exported, field, label):
    results, _ = exported
    incomplete = dict(results[0], **{field: ""})
    page = make_page("Title", [incomplete], [])
    assert f"> **Check before comparing:** not recorded: {label}." in page


def test_limits_are_shown_once_when_equal_and_per_condition_when_different(exported):
    results, samples = exported
    page = make_page("Title", results, samples)
    assert "Limits: 16 turns; 600 s generation; 1,200 s per case; output token limit 32,768." in page
    older = dict(results[0], run="older", codeguard_version="1.4.0", agent_turn_limit=8, agent_seconds="")
    page = make_page("Title", results + [older], samples)
    assert "| Condition | Turns | Generation (s) | Case (s) | Output tokens |" in page
    assert "| CodeGuard 1.4.0 | 8 | n/a | 1,200 | 32,768 |" in page
    assert "| CodeGuard 1.5.0 | 16 | 600 | 1,200 | 32,768 |" in page


def test_key_numbers_use_shared_cases_and_tokens_per_case(exported):
    results, samples = exported
    samples[1]["subcategory_vuln"] = 1
    row = exporter.public_results(results, samples)[0]
    assert (row["shared_cases"], row["findings"], row["likely_vulnerabilities"]) == (1, 2, 1)
    assert row["tokens_per_case"] == 100
    assert row["unfinished"] == 3
    assert (row["cost_per_case_usd"], row["cost_change_pct"]) == (0.1, "")
    page = make_page("Title", results, samples)
    assert (
        "| Condition | Findings | High + Medium | Likely vulnerabilities "
        "| Tokens per case | Estimated cost per case (USD) |"
    ) in page
    assert "### Model A (1 shared case)" in page
    assert "| CodeGuard 1.5.0 | 2 | 0 | 1 | 100 | $0.1000 | $0.40 | n/a | 3 of 4 (75%) |" in page


@pytest.mark.parametrize("estimate,total,per_case", [("", 2, 0.5), (1.5, 1.5, 0.375), (0, 0, 0)])
def test_cost_table_and_chart_use_selected_cost_over_all_cases(exported, estimate, total, per_case):
    results, samples = exported
    results[0]["recorded_cost_usd"] = 2.0
    other = dict(results[0], run="other", codeguard_version="1.6.0", recorded_cost_usd="")
    copies = [dict(case, run="other") for case in samples]
    public, attempts = public_data(results + [other], samples + copies)
    with pytest.raises(report.ReportError, match="complete costs"):
        report.build_figures(public, attempts)
    public[0]["estimated_cost_usd"] = estimate
    public[1]["estimated_cost_usd"] = 1
    report.update_cost_columns(public)
    page = report.results_page(public, title="Title", cost_note="Supplied prices.")
    assert "Estimated cost per case (USD)" in page
    assert f"| CodeGuard 1.5.0 | 2 | 0 | 0 | 100 | ${per_case:.4f} | ${total:.2f} | n/a | 3 of 4 (75%) |" in page
    assert "| CodeGuard 1.6.0 | 2 | 0 | 0 | 100 | $0.2500 | $1.00 | n/a | 3 of 4 (75%) |" in page
    charts = report.build_figures(public, attempts)
    assert [dot.get_offsets().tolist()[0] for dot in charts["findings"].axes[0].collections] == [[total, 2], [1, 2]]
    for figure in charts.values():
        figure.clear()


@pytest.mark.parametrize("value,expected", [
    ("", "n/a"), (0, "0"), (999.49, "999"), (999.5, "1K"),
    (1000, "1K"), (999499, "999.5K"), (999949, "999.9K"),
    (999950, "1M"), (1_000_000, "1M"), (999_950_000, "1B"),
    (1_000_000_000, "1B"),
])
def test_token_display_promotes_rounded_unit_boundaries(value, expected):
    assert report.tokens(value) == expected


@pytest.mark.parametrize("confidence", [(1, 0, 1), (0, 0, 0), (0.5, 1.5, 2.5)])
def test_confidence_uses_shared_cases_and_keeps_low_findings(exported, confidence):
    results, samples = exported
    for metric, value in zip(("confidence_high", "confidence_medium", "confidence_low"), confidence):
        samples[1][metric] = value
    samples[1]["finding_count"] = sum(confidence)
    samples[0]["confidence_high"] = 99  # Unchanged output must not contribute.
    numbers = exporter.public_results(results, samples)[0]
    assert numbers["findings"] == sum(confidence)
    assert report.higher_confidence(numbers) == sum(confidence[:2])
    assert numbers["confidence_high"] == confidence[0]
    assert numbers["confidence_low"] == confidence[2]

    charts = figures(results, samples)
    (axis,) = charts["confidence"].axes
    assert [bar.get_width() for bar in axis.patches] == list(confidence)
    assert f"{sum(confidence):,}" in [text.get_text() for text in axis.texts]
    for figure in charts.values():
        figure.clear()


def test_missing_confidence_is_not_plotted_as_zero(exported):
    results, samples = exported
    samples[1]["confidence_high"] = ""
    numbers = exporter.public_results(results, samples)[0]
    assert numbers["findings"] == 2
    assert report.higher_confidence(numbers) == ""
    charts = figures(results, samples)
    (axis,) = charts["confidence"].axes
    assert not axis.patches
    assert "Not recorded" in [text.get_text() for text in axis.texts]
    for figure in charts.values():
        figure.clear()


def test_charts_plot_recorded_values_without_reaggregating(exported):
    results, samples = exported
    charts = figures(results, samples)
    assert set(charts) == set(report.CHARTS)

    (axis,) = charts["findings"].axes
    (dots,) = axis.collections
    assert dots.get_offsets().tolist() == [[0.4, 2]]
    assert "CodeGuard 1.5.0" in [
        text.get_text() for text in axis.texts
    ]
    assert axis.get_title(loc="left") == "Model A · 1 shared case"

    (outcomes,) = charts["outcomes"].axes
    assert [bar.get_width() for bar in outcomes.patches] == [1, 1, 1, 0, 1]
    assert [label.get_text() for label in outcomes.get_legend().get_texts()] == [
        "Completed", "Turn limit", "Time limit", "Error",
    ]
    page = make_page("Title", results, samples)
    for name, figure in charts.items():
        texts = [item.get_text() for item in figure.findobj(Text)]
        title = figure._suptitle.get_text()
        note = figure._supxlabel.get_text()
        assert f"![{title}]({name}.png)" in page
        assert note not in page
        assert not any(CANARY in text for text in texts)
        assert not any(item.get_usetex() for item in figure.findobj(Text))
        figure.clear()


def test_missing_token_counts_do_not_hide_known_costs(exported):
    results, samples = exported
    results[0]["recorded_tokens"] = ""
    samples[1]["subcategory_vuln"] = ""
    page = make_page("Title", results, samples)
    assert "| CodeGuard 1.5.0 | 2 | 0 | n/a | n/a | $0.1000 | $0.40 | n/a | 3 of 4 (75%) |" in page

    charts = figures(results, samples)
    (axis,) = charts["findings"].axes
    assert axis.collections[0].get_offsets().tolist() == [[0.4, 2]]
    for figure in charts.values():
        figure.clear()


def test_models_get_separate_cost_scales_and_shared_count_scales(exported):
    results, samples = exported
    larger = dict(
        results[0],
        model_label="Model B",
        run="other",
        recorded_cost_usd=2,
    )
    copies = [dict(case, run="other") for case in samples]
    copies[1]["finding_count"] = 9
    with rc_context(dict(report.STYLE)):
        charts = figures([results[0], larger], samples + copies)
        for name, figure in charts.items():
            figure.draw_without_rendering()
            first, second = figure.axes
            assert first.get_title(loc="left").startswith("Model A")
            assert second.get_title(loc="left").startswith("Model B")
            if name == "findings":
                assert first.get_xlim()[1] < second.get_xlim()[1]
            else:
                assert first.get_xlim() == second.get_xlim()
            assert first.get_ylim() == second.get_ylim()
            for axis in (first, second):
                right = axis.get_xlim()[1]
                ends = [bar.get_x() + bar.get_width() for bar in axis.patches]
                ends += [x for dots in axis.collections for x, _ in dots.get_offsets()]
                assert all(end <= right for end in ends)
            figure.clear()


def test_models_with_unequal_run_counts_render_without_warnings(exported):
    results, samples = exported
    runs = [dict(results[0], run=f"{n}", codeguard_version=f"1.{n}.0") for n in (6, 7)]
    runs.append(dict(results[0], run="solo", model_label="Model B"))
    # Matplotlib only warns, and skips the layout, when a panel runs out of room.
    with rc_context(dict(report.STYLE)), warnings.catch_warnings():
        warnings.simplefilter("error")
        charts = figures(results + runs, samples)
        figure = charts["outcomes"]
        figure.draw_without_rendering()
        first, second = figure.axes
        assert len(first.get_yticklabels()) == 3
        assert len(second.get_yticklabels()) == 1
        for figure in charts.values():
            figure.clear()


def test_images_carry_only_public_metadata(exported):
    rendered = report.render_charts(*public_data(*exported))
    assert set(rendered) == {f"{name}.png" for name in report.CHARTS}
    for name, content in rendered.items():
        assert CANARY.encode() not in content and b"/Users/" not in content, name
        with Image.open(io.BytesIO(content)) as image:
            assert image.info.get("Software") == "Project CodeGuard"
            assert set(image.info) <= {"Software", "dpi"}


@pytest.mark.parametrize("cost", [1, 2, 0.0002])
def test_total_cost_is_plotted_with_separate_model_scales_and_compact_labels(exported, cost):
    results, samples = exported
    first = dict(results[0], recorded_cost_usd=20)
    second = dict(first, model_label='Model B', run='other', recorded_cost_usd=cost)
    copies = [dict(case, run='other') for case in samples]
    charts = figures([first, second], samples + copies)
    figure = charts['findings']
    figure.draw_without_rendering()
    a, b = figure.axes
    assert a.collections[0].get_offsets().tolist() == [[20, 2]]
    assert b.collections[0].get_offsets().tolist() == [[cost, 2]]
    assert a.get_xlim()[1] > b.get_xlim()[1]
    assert a.get_xlabel() == b.get_xlabel() == 'Estimated total LLM cost (USD)'
    for axis in (a, b):
        labels = [tick.get_text() for tick in axis.get_xticklabels()]
        assert len(labels) == len(set(labels))
    assert 'CodeGuard 1.5.0' in [t.get_text() for t in a.texts]
    for figure in charts.values(): figure.clear()


def test_epoch_chart_notes_are_shown_once_and_exclude_unallocated_retries(exported):
    results, samples = exported
    results[0]["epochs"] = 2
    samples += [dict(case, epoch=2) for case in samples]
    public, attempts = public_data(results, samples)
    page = report.results_page(public, title="Title", multiple_epochs=True)
    charts = report.build_figures(public, attempts, multiple=True)
    for name, figure in charts.items():
        title = figure._suptitle.get_text().rsplit(" · Epoch ", 1)[0]
        note = figure._supxlabel.get_text()
        assert f"![{title}]({name}.png)" in page
        assert note not in page
        if name.startswith("findings"):
            assert "all cases in this epoch" in note
            assert "recorded retries" not in note
            axis_label = "Estimated total LLM cost (USD)"
            assert figure.axes[0].get_xlabel() == axis_label
        figure.clear()


def test_multi_epoch_chart_scales_match(save):
    _, run, samples = exporter.read_run("Model A", save(repeated_log()))
    charts = figures([run], samples)
    for name in ("findings", "outcomes", "confidence"):
        first, second = (charts[f"{name}-epoch-{n}"].axes[0] for n in (1, 2))
        assert first.get_xlim() == second.get_xlim()
        if name == "findings":
            assert first.get_ylim() == second.get_ylim()
            assert first.collections[0].get_offsets().tolist() == [[0.5, 2]]
            assert second.collections[0].get_offsets().tolist() == [[1.0, 4]]
    for figure in charts.values():
        figure.clear()
