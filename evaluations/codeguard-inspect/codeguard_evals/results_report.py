"""Render the validated public rows as CSVs, a page, and three charts."""

from __future__ import annotations

import csv
import io
import math
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Final

from matplotlib import rc_context
from matplotlib.axes import Axes
from matplotlib.backends.backend_agg import FigureCanvasAgg
from matplotlib.colors import to_rgb
from matplotlib.figure import Figure
from matplotlib.patches import Patch
from matplotlib.ticker import MaxNLocator

from codeguard_evals import results_costs as costs
from codeguard_evals.protocol import CONDITION_LABELS, condition_has_skill
from codeguard_evals.results_common import LIMIT_FIELDS, NOTE, TITLE, ReportError, Row, text

Numbers = Mapping[object, Mapping[str, object]]
Groups = Mapping[str, Sequence[Row]]
Column = tuple[str, Callable[[Row], str]]
INK: Final = "#162536"
MID: Final = "#536274"
RULE: Final = "#C9D1DB"  # zero lines and the dashed baseline cross
FIXED_STYLES: Final = MappingProxyType(
    {"Baseline": ("#666666", "o"), "Secure prompt": ("#D55E00", "s")}
)
# Categorical colours and built-in markers; skill series follow input order.
SKILL_COLORS: Final = ("#CC79A7", "#0072B2", "#009E73", "#E69F00", "#56B4E9")
SKILL_MARKERS: Final = ("^", "D", "P", "v", "X", "h")
OUTCOMES: Final = (
    ("Completed", "#D6E5F2"),
    ("Turn limit", "#CC824D"),
    ("Time limit", "#9A4A67"),
    ("Other limit", "#8793A3"),
    ("Error", "#AF3D47"),
)
FINDING_LEVEL_COLORS: Final = ("#236BB5", "#9BBDE3", "#E1E4E8", "#748A9E")


@dataclass(frozen=True)
class ReportDefinition:
    """Benchmark-specific fields and labels for the shared report renderer."""

    result_fields: Sequence[str]
    sample_fields: Sequence[str]
    intro: str
    chart_text: Callable[[str, bool], tuple[str, str]]
    detail_name: str
    finding_parts: Sequence[tuple[str, str]]
    empty_note: str
    table_note: str = (
        "**Findings:** We compare the same examples across all runs. If an example does not meet "
        "the benchmark's output and scan requirements in any run, it is excluded from every "
        "run's findings comparison.\n\n"
        "**Costs:** Totals cover recorded usage, including unfinished attempts. "
        "Attempts without token counts are listed below when present. "
        "n/a means a value is unavailable."
    )
    footer: str = (
        "Examples excluded from the findings comparison are still listed in samples.csv. "
        "Leaving them out can change how the runs compare. One epoch is one pass through the "
        "examples; it does not show how results vary across repeated runs."
    )
    data_note: str = (
        "[results.csv](results.csv) lists totals for each run and epoch. "
        "[samples.csv](samples.csv) lists every attempt, including unfinished generations "
        "and files the scanner could not fully check."
    )
    detail_table: Callable[[Groups, str], list[str]] | None = None

    @property
    def charts(self) -> tuple[str, ...]:
        return ("findings", "outcomes", self.detail_name)


FIGURE_WIDTH: Final = 7.0  # inches; 1,400 pixels at the PNG resolution
STYLE: Final = MappingProxyType(
    {
        "font.family": "DejaVu Sans",
        "font.size": 8.5,
        "axes.titlesize": 8,
        "axes.titlelocation": "left",
        "axes.titlecolor": MID,
        "axes.labelcolor": MID,
        "axes.labelsize": 8,
        "axes.spines.left": False,
        "axes.spines.right": False,
        "axes.spines.top": False,
        "axes.spines.bottom": False,
        "axes.grid": True,
        "axes.axisbelow": True,
        "grid.color": "#E8ECF1",
        "grid.linewidth": 0.8,
        "xtick.color": MID,
        "ytick.color": MID,
        "xtick.labelsize": 8,
        "ytick.labelsize": 8,
        "xtick.major.size": 0,
        "ytick.major.size": 0,
        "xtick.major.pad": 5,
        "ytick.major.pad": 6,
        "text.color": INK,
        "text.usetex": False,
        "legend.frameon": False,
        "legend.fontsize": 8,
    }
)
PNG_OPTIONS: Final = MappingProxyType(
    {"dpi": 200, "metadata": {"Software": "Project CodeGuard"}}
)


def _csv(rows: Sequence[Row], fields: Sequence[str]) -> bytes:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue().encode("utf-8")


def write_report(output: Path, results: Sequence[Row], samples: Sequence[Row], *,
                 title: str, comparison_note: str = "", cost_note: str = "", multiple_epochs: bool = False,
                 definition: ReportDefinition) -> None:
    """Render before creating a new directory; never replace an existing export."""
    if output.exists() or output.is_symlink():
        raise ReportError("The output directory already exists. Choose a new directory.")
    text(title, TITLE)
    if cost_note:
        text(cost_note, NOTE)
    if any(row["estimated_cost_usd"] != "" for row in results) and not cost_note:
        raise ReportError("Estimated costs require their public method note.")
    files = {
        "results.csv": _csv(results, definition.result_fields),
        "samples.csv": _csv(samples, definition.sample_fields),
        "index.md": results_page(results, title=title, comparison_note=comparison_note,
                                 cost_note=cost_note, multiple_epochs=multiple_epochs,
                                 definition=definition).encode("utf-8"),
        **render_charts(results, samples, multiple=multiple_epochs, definition=definition),
    }
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name, content in files.items():
        with (output / name).open("xb") as target:
            target.write(content)


def by_model(results: Sequence[Row]) -> dict[str, list[Row]]:
    groups: dict[str, list[Row]] = {}
    for row in results:
        groups.setdefault(row["model"], []).append(row)
    return groups


def by_epoch(results: Sequence[Row]):
    for epoch in sorted({row["epoch"] for row in results}):
        yield epoch, by_model([row for row in results if row["epoch"] == epoch])


def results_page(results: Sequence[Row], *, title: str, comparison_note: str = "", cost_note: str = "",
                 multiple_epochs: bool = False, definition: ReportDefinition) -> str:
    lines = [f"# {title}", "", definition.intro, ""]
    if comparison_note:
        lines += [comparison_note, ""]
    if multiple_epochs:
        lines += ["Each epoch is one pass through the examples. Its token and cost totals use the last "
                  "saved attempt for each example and may omit tokens from earlier retries.", ""]
    for epoch, groups in by_epoch(results):
        if multiple_epochs:
            lines += [f"## Epoch {epoch}", ""]
        heading = "###" if multiple_epochs else "##"
        lines += _key_table(groups, heading, note=definition.table_note)
        if definition.detail_table is not None:
            lines += definition.detail_table(groups, heading)
        lines += [f"{heading} Charts", ""]
        for name in definition.charts:
            image_title, _ = definition.chart_text(name, multiple_epochs)
            filename = _chart_name(name, epoch, multiple_epochs)
            lines += [f"![{image_title}]({filename}.png)", ""]
    if definition.footer:
        lines += [definition.footer, ""]
    if cost_note:
        lines += ["## Cost estimates", "", cost_note, ""]
    lines += ["## Data", "", definition.data_note, ""]
    return "\n".join(lines)


def build_figures(results: Sequence[Row], samples: Sequence[Row], *, multiple: bool = False,
                  definition: ReportDefinition) -> dict[str, Figure]:
    styles = series_styles(results)
    labels = _chart_labels(results)
    if any(costs.total_cost(row) == "" for row in results):
        raise ReportError("Every run needs complete costs. Supply --prices to estimate costs for all runs.")
    top = 1.3 * max((row["findings"] for row in results if row["findings"] != ""), default=0) or 1
    cost_limits = {
        model: max(1.32 * costs.total_cost(row) for row in rows) or 1
        for model, rows in by_model(results).items()
    }
    figures = {}
    for epoch, groups in by_epoch(results):
        selected = [row for row in samples if row["epoch"] == epoch]
        counts = _outcome_counts(groups, selected, OUTCOMES)
        charts = {
            "findings": _tradeoff_figure(
                groups, styles, top, cost_limits=cost_limits, empty_note=definition.empty_note,
                labels=labels,
            ),
            "outcomes": _stacked_figure(groups, counts, OUTCOMES, labels=labels),
            definition.detail_name: finding_breakdown_figure(groups, definition.finding_parts, labels=labels),
        }
        for name, figure in charts.items():
            title, note = definition.chart_text(name, multiple)
            if multiple:
                title += f" · Epoch {epoch}"
            figure.suptitle(title, x=0.01, ha="left", fontsize=11, fontweight="bold")
            figure.supxlabel(note, x=0.01, ha="left", fontsize=8, color=MID)
            figures[_chart_name(name, epoch, multiple)] = figure
    for name in ("outcomes", definition.detail_name):
        axes = [axis for key, figure in figures.items() if key.startswith(name) for axis in figure.axes]
        right = max(axis.get_xlim()[1] for axis in axes)
        for axis in axes:
            axis.set_xlim(0, right)
    return figures


def render_charts(results: Sequence[Row], samples: Sequence[Row], *, multiple: bool = False,
                  definition: ReportDefinition) -> dict[str, bytes]:
    rendered = {}
    with rc_context(dict(STYLE)):
        for name, figure in build_figures(results, samples, multiple=multiple, definition=definition).items():
            buffer = io.BytesIO()
            figure.savefig(buffer, format="png", bbox_inches="tight", **PNG_OPTIONS)
            rendered[f"{name}.png"] = buffer.getvalue()
            figure.clear()
    return rendered


def count(value: object, decimals: int = 0) -> str:
    """Format a recorded number; a missing value is never shown as zero."""
    return "n/a" if value == "" else f"{value:,.{decimals}f}"


def share(part: object, whole: object) -> str:
    fraction = _fraction(part, whole)
    if fraction is None:
        return "n/a"
    return f"{part:,.0f} of {whole:,.0f} ({fraction:.0%})"


def usd(value: object, decimals: int = 2) -> str:
    return "n/a" if value == "" else f"${value:,.{decimals}f}"


def series_label(row: Row) -> str:
    """Name a run by its skill label and ID, or by condition and historical CodeGuard version."""
    if row["condition"] == "skill":
        return f"{row['skill_label']} ({row['skill_id']})"
    name = CONDITION_LABELS[row["condition"]]
    version = row["codeguard_version"]
    return f"{name} {version}" if version else name


def series_styles(results: Sequence[Row]) -> dict[str, tuple[str, str]]:
    """Assign each series a colour and shape shared across models and epochs."""
    labels = list(dict.fromkeys(series_label(row) for row in results
                                if condition_has_skill(row["condition"])))
    styles = dict(FIXED_STYLES)
    for index, label in enumerate(labels):
        styles[label] = (SKILL_COLORS[index % len(SKILL_COLORS)],
                         SKILL_MARKERS[index % len(SKILL_MARKERS)])
    return styles


def _chart_labels(results: Sequence[Row]) -> dict[str, str]:
    """Shorten unique skill names while retaining IDs for ambiguous names."""
    names = {
        series_label(row): row["skill_label"] if row["condition"] == "skill" else series_label(row)
        for row in results
    }
    counts = Counter(names.values())
    return {
        full: name if counts[name] == 1 and (name not in names or name == full) else full
        for full, name in names.items()
    }


def _chart_name(name: str, epoch: int, multiple: bool) -> str:
    return f"{name}-epoch-{epoch}" if multiple else name


def listed(items: Sequence[str]) -> str:
    if len(items) == 1:
        return items[0]
    return f"{', '.join(items[:-1])} and {items[-1]}"


def _plural(amount: int, word: str) -> str:
    return f"{amount} {word}{'' if amount == 1 else 's'}"


def _fraction(part: object, whole: object) -> float | None:
    if part == "" or whole in ("", 0):
        return None
    return part / whole


def _key_table(
    groups: Groups, heading: str = "##", *,
    note: str,
) -> list[str]:
    lines = [f"{heading} Key numbers", "", note, ""]
    for model, runs in groups.items():
        shared = runs[0]["shared_cases"]
        lines += [
            f"{heading}# {model} ({_plural(shared, 'example')} compared)",
            "",
        ]
        lines += _limits_note(runs)
        lines += table(runs, KEY_COLUMNS)
        missing = [f"{series_label(row)}: {count(row['usage_missing_cases'])}"
                   for row in runs if row["usage_missing_cases"]]
        if missing:
            lines += ["Attempts without token counts: " + "; ".join(missing) + ". "
                      "Their cost may be missing from estimates.", ""]
    return lines


def table(rows: Sequence[Row], columns: Sequence[Column]) -> list[str]:
    """Render validated values with the report's standard table layout."""
    return [
        f"| {' | '.join(title for title, _ in columns)} |",
        f"| --- | {' | '.join(['---:'] * (len(columns) - 1))} |",
        *[f"| {' | '.join(format_value(row) for _, format_value in columns)} |" for row in rows],
        "",
    ]


def _limits_note(runs: Sequence[Row]) -> list[str]:
    limits = [tuple(row[field] for field in LIMIT_FIELDS) for row in runs]
    if len(set(limits)) == 1:
        turns, generation, case, output = map(count, limits[0])
        return [
            f"Limits: {turns} turns; {generation} s generation; "
            f"{case} s per case; output token limit {output}.", "",
        ]
    return [
        "| Condition | Turns | Generation (s) | Case (s) | Output tokens |",
        "| --- | ---: | ---: | ---: | ---: |",
        *[
            f"| {series_label(row)} | {' | '.join(map(count, values))} |"
            for row, values in zip(runs, limits)
        ],
        "",
    ]


def _figure(
    heights: Sequence[float], *, sharex: bool = True
) -> tuple[Figure, list[Axes]]:
    """One subplot per model; the caller adds the shared title and note."""
    figure = Figure(
        figsize=(FIGURE_WIDTH, 0.6 + 0.45 * len(heights) + sum(heights)),
        layout="constrained",
    )
    FigureCanvasAgg(figure)
    axes = figure.subplots(
        len(heights),
        1,
        sharex=sharex,
        squeeze=False,
        gridspec_kw={"height_ratios": heights},
    ).ravel().tolist()
    return figure, axes


def _tradeoff_figure(
    groups: Mapping[str, Sequence[Row]], styles: Mapping[str, tuple[str, str]],
    top: float, *, cost_limits: Mapping[str, float],
    empty_note: str, labels: Mapping[str, str],
) -> Figure:
    """Plot total USD cost and findings, with Matplotlib placing the legend."""
    figure, axes = _figure([2.6] * len(groups), sharex=False)
    for axis, (model, runs) in zip(axes, groups.items()):
        right = cost_limits[model]
        shared = runs[0]["shared_cases"]
        axis.set_title(
            f"{model} · {_plural(shared, 'shared case')}",
            loc="left", fontsize=9.5, fontweight="bold", color=INK,
        )
        missing = []
        for row in runs:
            resource = costs.total_cost(row)
            label = series_label(row)
            if row["findings"] == "":
                missing.append(label)
                continue
            dot = (resource, row["findings"])
            if row["condition"] == "baseline":
                axis.axhline(dot[1], color=RULE, linewidth=0.9, linestyle=(0, (4, 3)))
                axis.axvline(dot[0], color=RULE, linewidth=0.9, linestyle=(0, (4, 3)))
            axis.scatter(
                *dot,
                s=70,
                color=styles[label][0],
                marker=styles[label][1],
                edgecolor="white",
                linewidths=0.7,
                zorder=3,
                label=labels[label],
            )
        if axis.collections:
            axis.legend(loc="best", fontsize=7.2)
        if missing:
            note = (
                f"Not recorded: {listed(missing)}"
                if shared else empty_note
            )
            axis.text(0.01, 0.97, note, transform=axis.transAxes, va="top", color=MID)
        axis.set_xlim(0, right)
        axis.set_ylim(0, top)
        axis.axhline(0, color=RULE, linewidth=1)
        axis.axvline(0, color=RULE, linewidth=1)
        axis.xaxis.set_major_locator(MaxNLocator(5))
        axis.yaxis.set_major_locator(MaxNLocator(5, integer=True))
        axis.set_ylabel("Findings")
        axis.set_xlabel("Estimated total LLM cost (USD)")
    return figure


def finding_breakdown_figure(groups: Groups, parts: Sequence[tuple[str, str]], *,
                            labels: Mapping[str, str]) -> Figure:
    """Use one palette and layout for finding classifications."""
    counts = {
        row["run"]: {label: row[metric] for label, metric in parts}
        for runs in groups.values() for row in runs
    }
    shared = {model: runs[0]["shared_cases"] for model, runs in groups.items()}
    return _stacked_figure(
        groups, counts,
        list(zip((label for label, _ in parts), FINDING_LEVEL_COLORS[:len(parts)], strict=True)),
        shared=shared, labels=labels,
    )


def _outcome_counts(
    groups: Groups, samples: Sequence[Row], parts: Sequence[tuple[str, str]],
) -> dict[str, dict[str, int]]:
    counts = {row["run"]: dict.fromkeys((name for name, _ in parts), 0)
              for runs in groups.values() for row in runs}
    for sample in samples:
        if sample["run"] in counts:
            counts[sample["run"]][sample["outcome"]] += 1
    return counts


def _stacked_figure(
    groups: Mapping[str, Sequence[Row]], counts: Numbers,
    parts: Sequence[tuple[str, str]], *, labels: Mapping[str, str], shared: Mapping[str, int] | None = None,
) -> Figure:
    heights = [0.45 * len(runs) for runs in groups.values()]
    figure, axes = _figure(heights)
    handles = [
        Patch(color=color, label=name)
        for name, color in parts
        if any(run[name] for run in counts.values())
    ]
    legend_rows = 1
    if handles:
        columns = len(handles) if len(handles) <= 5 else 4
        legend_rows = math.ceil(len(handles) / columns)
        axes[0].legend(
            handles=handles, loc="lower left", bbox_to_anchor=(0, 1),
            ncols=columns, handlelength=1, borderaxespad=0,
        )
    widest = max(
        (sum(run.values()) for run in counts.values() if "" not in run.values()), default=0
    ) or 1
    for axis, (model, runs) in zip(axes, groups.items()):
        axis.set_title(
            model if shared is None else f"{model} · {_plural(shared[model], 'shared case')}",
            loc="left", fontsize=9.5, fontweight="bold", color=INK,
            pad=24 + 14 * (legend_rows - 1) if axis is axes[0] and handles else 6,
        )
        axis.set_yticks(range(len(runs)), [labels[series_label(row)] for row in runs])
        axis.set_ylim(len(runs) - 0.5, -0.5)
        axis.tick_params(axis="y", labelcolor=INK, labelsize=8.5)
        axis.grid(axis="y", visible=False)
        axis.axvline(0, color=RULE, linewidth=1)
        axis.xaxis.set_major_locator(MaxNLocator(5, integer=True))
        known = []
        for index, row in enumerate(runs):
            if "" in counts[row["run"]].values():
                axis.text(0.02 * widest, index, "Not recorded", va="center", color=MID)
            else:
                known.append((index, row["run"]))
        positions = [index for index, _ in known]
        left = [0] * len(known)
        for name, color in parts:
            values = [counts[run][name] for _, run in known]
            bars = axis.barh(
                positions, values, left=left, height=0.56,
                color=color, edgecolor="white", linewidth=1.2,
            )
            bar_labels = [
                f"{value:,}" if value >= (0.02 if shared is not None else 0.04) * widest else ""
                for value in values
            ]
            axis.bar_label(
                bars, labels=bar_labels, label_type="center", fontsize=7.5,
                color=INK if sum(to_rgb(color)) / 3 > 0.7 else "white",
            )
            left = [start + value for start, value in zip(left, values)]
        if shared is not None:
            axis.bar_label(bars, labels=[f"{total:,}" for total in left], padding=4, fontsize=8)
        axis.set_xlim(0, widest * (1.12 if shared is not None else 1))
    axes[-1].set_xlabel("Findings" if shared is not None else "Cases")
    return figure


KEY_COLUMNS: tuple[Column, ...] = (
    ("Condition", series_label),
    ("Findings", lambda row: count(row["findings"])),
    ("Flagged outputs", lambda row: share(row["flagged_outputs"], row["shared_cases"])),
    ("Estimated total cost (USD)", lambda row: usd(costs.total_cost(row))),
    ("Total USD vs baseline", lambda row: "—" if row["condition"] == "baseline" else
     "n/a" if row["cost_change_pct"] == "" else f"{row['cost_change_pct']:+.1f}%"),
    ("Unfinished", lambda row: share(row["unfinished"], row["cases"])),
)
