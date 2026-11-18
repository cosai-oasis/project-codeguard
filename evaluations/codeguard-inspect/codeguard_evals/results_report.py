"""Render the validated public rows as CSVs, a page, and three charts."""

from __future__ import annotations

import csv
import io
import math
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import MappingProxyType
from typing import Final

from matplotlib import rc_context
from matplotlib.axes import Axes
from matplotlib.backends.backend_agg import FigureCanvasAgg
from matplotlib.colors import to_hex, to_rgb
from matplotlib.figure import Figure
from matplotlib.patches import Patch
from matplotlib.ticker import MaxNLocator


Row = dict[str, object]
Numbers = Mapping[object, Mapping[str, object]]
DEFAULT_TITLE = "SecurityEval results"
MODEL_LABEL = r"[A-Za-z0-9][A-Za-z0-9 ._()+-]{0,59}"
TITLE = r"[A-Za-z0-9][A-Za-z0-9 .,:;()/+-]{0,119}"
VERSION = r"[0-9]+(?:\.[0-9]+){1,3}[A-Za-z0-9.+-]*"
NOTE = r"[A-Za-z0-9][A-Za-z0-9 .,;:()/%+$-]{0,999}"
LIMIT_FIELDS = (
    "agent_turn_limit", "agent_seconds", "sample_seconds_limit", "agent_output_tokens",
)
RESULT_FIELDS = (
    "run", "epoch", "model", "condition", "codeguard_version",
    *LIMIT_FIELDS,
    "cases", "shared_cases", "findings", "likely_vulnerabilities", "tokens_per_case",
    "unfinished", "recorded_cost_usd", "estimated_cost_usd", "cost_per_case_usd",
    "cost_change_pct", "confidence_high", "confidence_medium", "confidence_low",
)
SAMPLE_FIELDS = (
    "run", "case_id", "epoch", "outcome", "changed_output", "valid_output",
    "findings", "likely_vulnerabilities",
)



class ReportError(ValueError):
    """A validation error that is safe to display without private input values."""


INK: Final = "#162536"
MID: Final = "#536274"
RULE: Final = "#C9D1DB"  # zero lines and the dashed baseline cross
CONDITION_NAMES: Final = MappingProxyType(
    {
        "baseline": "Baseline",
        "secure_prompt": "Secure prompt",
        "codeguard": "CodeGuard",
    }
)
FIXED_COLORS: Final = MappingProxyType(
    {"Baseline": "#CA6034", "Secure prompt": "#16816B"}
)
CODEGUARD_COLORS: Final = ("#9BBDE3", "#236BB5")  # blue endpoints; versions follow input order
OUTCOMES: Final = (
    ("Completed", "#D6E5F2"),
    ("Turn limit", "#CC824D"),
    ("Time limit", "#9A4A67"),
    ("Other limit", "#8793A3"),
    ("Error", "#AF3D47"),
)
CONFIDENCE: Final = (
    ("High", "confidence_high", "#236BB5"),
    ("Medium", "confidence_medium", "#9BBDE3"),
    ("Low", "confidence_low", "#E1E4E8"),
)
CHARTS: Final = ("findings", "outcomes", "confidence")
INTRO: Final = (
    "Findings are Semgrep scanner results, not confirmed vulnerabilities. "
    "[Evaluation Results](../index.md) explains how the evaluation works and its "
    "limits."
)
DATA: Final = (
    "## Data",
    "",
    "[results.csv](results.csv) has the summary numbers for each run and epoch, and "
    "[samples.csv](samples.csv) has one row per attempt.",
    "",
)
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


def text(value: object, pattern: str) -> str:
    """Return an allowlisted text value; ``None`` becomes blank."""
    if value is None:
        return ""
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
        raise ReportError("An approved text field has an unsupported format.")
    return value


def number(value: object) -> int | float | str:
    """Return a finite, non-negative number; missing or NaN stays blank, not zero."""
    if value is None:
        return ""
    if type(value) not in (int, float):
        raise ReportError("An approved numeric field is not numeric.")
    if math.isnan(value):
        return ""
    if not math.isfinite(value) or value < 0:
        raise ReportError("An approved numeric field is out of range.")
    return value


def _csv(rows: Sequence[Row], fields: Sequence[str]) -> bytes:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue().encode("utf-8")


def write_report(output: Path, results: Sequence[Row], samples: Sequence[Row], *,
                 title: str, comparison_note: str = "", cost_note: str = "", multiple_epochs: bool = False) -> None:
    """Render before creating a new directory; never replace an existing export."""
    if output.exists() or output.is_symlink():
        raise ReportError("The output directory already exists. Choose a new directory.")
    text(title, TITLE)
    if cost_note:
        text(cost_note, NOTE)
    if any(row["estimated_cost_usd"] != "" for row in results) and not cost_note:
        raise ReportError("Estimated costs require their public method note.")
    files = {
        "results.csv": _csv(results, RESULT_FIELDS),
        "samples.csv": _csv(samples, SAMPLE_FIELDS),
        "index.md": results_page(results, title=title, comparison_note=comparison_note,
                                 cost_note=cost_note, multiple_epochs=multiple_epochs).encode("utf-8"),
        **render_charts(results, samples, multiple=multiple_epochs),
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


def total_cost(row: Row):
    """Use supplied-price estimates when present; otherwise use recorded costs."""
    return row["estimated_cost_usd"] if row["estimated_cost_usd"] != "" else row["recorded_cost_usd"]


def higher_confidence(row: Row):
    values = [row["confidence_high"], row["confidence_medium"]]
    return "" if "" in values else sum(values)


def update_cost_columns(results: Sequence[Row]) -> None:
    """Derive cost per case and change from the same-model, same-epoch baseline."""
    for _, groups in by_epoch(results):
        for rows in groups.values():
            baseline = next((total_cost(r) for r in rows if r["condition"] == "baseline"), "")
            for row in rows:
                cost = total_cost(row)
                row["cost_per_case_usd"] = cost / row["cases"] if cost != "" and row["cases"] else ""
                row["cost_change_pct"] = 100 * (cost / baseline - 1) if cost != "" and baseline not in ("", 0) else ""


def results_page(results: Sequence[Row], *, title: str, comparison_note: str = "", cost_note: str = "", multiple_epochs: bool = False) -> str:
    lines = [f"# {title}", "", INTRO, ""]
    if comparison_note:
        lines += [comparison_note, ""]
    if multiple_epochs:
        lines += ["Runs with multiple epochs use their final attempts for each epoch. "
                  "Earlier retries may be missing from their token and cost totals.", ""]
    for epoch, groups in by_epoch(results):
        if multiple_epochs:
            lines += [f"## Epoch {epoch}", ""]
        heading = "###" if multiple_epochs else "##"
        lines += _key_table(groups, heading)
        lines += [f"{heading} Charts", ""]
        for name in CHARTS:
            image_title, _ = _chart_text(name, multiple_epochs)
            filename = _chart_name(name, epoch, multiple_epochs)
            lines += [f"![{image_title}]({filename}.png)", ""]
    if cost_note:
        lines += ["## Cost estimates", "", cost_note, ""]
    lines += DATA
    return "\n".join(lines)


def build_figures(results: Sequence[Row], samples: Sequence[Row], *, multiple: bool = False) -> dict[str, Figure]:
    colors = series_colors(results)
    if any(total_cost(row) == "" for row in results):
        raise ReportError("Every run needs complete costs. Supply --prices to estimate costs for all runs.")
    top = 1.3 * max((row["findings"] for row in results if row["findings"] != ""), default=0) or 1
    cost_limits = {
        model: max(1.32 * total_cost(row) for row in rows) or 1
        for model, rows in by_model(results).items()
    }
    figures = {}
    for epoch, groups in by_epoch(results):
        selected = [row for row in samples if row["epoch"] == epoch]
        counts = {
            row["run"]: {name: sum(s["run"] == row["run"] and s["outcome"] == name for s in selected) for name, _ in OUTCOMES}
            for rows in groups.values() for row in rows
        }
        charts = {
            "findings": _tradeoff_figure(groups, colors, top, cost_limits=cost_limits),
            "outcomes": _stacked_figure(groups, counts, OUTCOMES),
            "confidence": _confidence_figure(groups),
        }
        for name, figure in charts.items():
            title, note = _chart_text(name, multiple)
            if multiple:
                title += f" · Epoch {epoch}"
            figure.suptitle(title, x=0.01, ha="left", fontsize=11, fontweight="bold")
            figure.supxlabel(note, x=0.01, ha="left", fontsize=8, color=MID)
            figures[_chart_name(name, epoch, multiple)] = figure
    for name in ("outcomes", "confidence"):
        axes = [axis for key, figure in figures.items() if key.startswith(name) for axis in figure.axes]
        right = max(axis.get_xlim()[1] for axis in axes)
        for axis in axes:
            axis.set_xlim(0, right)
    return figures


def render_charts(results: Sequence[Row], samples: Sequence[Row], *, multiple: bool = False) -> dict[str, bytes]:
    rendered = {}
    with rc_context(dict(STYLE)):
        for name, figure in build_figures(results, samples, multiple=multiple).items():
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


def tokens(value: object) -> str:
    """Write a token count compactly, such as 61.1K or 20M."""
    if value == "":
        return "n/a"
    for suffix in ("", "K", "M", "B"):
        decimals = 1 if suffix else 0
        rounded = round(value, decimals)
        if rounded < 1000 or suffix == "B":
            return f"{rounded:,.{decimals}f}".removesuffix(".0") + suffix
        value /= 1000


def usd(value: object, decimals: int = 2) -> str:
    return "n/a" if value == "" else f"${value:,.{decimals}f}"


def series_label(row: Row) -> str:
    """Name a run by condition and, for CodeGuard, the skill version."""
    name = CONDITION_NAMES[row["condition"]]
    version = row["codeguard_version"]
    return f"{name} {version}" if version else name


def series_colors(results: Sequence[Row]) -> dict[str, str]:
    """Give each condition a fixed colour and CodeGuard versions progressively darker blues in input order."""
    versions = list(dict.fromkeys(row["codeguard_version"] for row in results if row["codeguard_version"]))
    light, dark = (to_rgb(color) for color in CODEGUARD_COLORS)
    colors = dict(FIXED_COLORS)
    for index, version in enumerate(versions, start=1):
        weight = index / max(2, len(versions))
        mixed = [low + (high - low) * weight for low, high in zip(light, dark)]
        colors[f"CodeGuard {version}"] = to_hex(mixed)
    return colors


def _chart_name(name: str, epoch: int, multiple: bool) -> str:
    return f"{name}-epoch-{epoch}" if multiple else name


def _chart_text(name: str, multiple: bool) -> tuple[str, str]:
    """Keep each chart's reading note on the image so it can be shared alone."""
    if name == "findings":
        basis = "all cases in this epoch" if multiple else "all attempted cases and recorded retries"
        return (
            "Semgrep findings against estimated total USD cost",
            f"Findings use shared cases; total USD cost covers {basis}. Cost scales differ by model.",
        )
    if name == "outcomes":
        return ("How each attempt ended", "Attempts that hit a turn or time limit may have left the code unfinished.")
    return ("Findings by rule confidence", "Shared cases only. Rule confidence is not confirmation of a vulnerability.")


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
    groups: Mapping[str, Sequence[Row]], heading: str = "##"
) -> list[str]:
    headers = ["Condition", "Findings", "High + Medium", "Likely vulnerabilities", "Tokens per case"]
    headers += ["Estimated cost per case (USD)", "Estimated total cost (USD)", "Total USD vs baseline"]
    headers.append("Unfinished")
    lines = [
        f"{heading} Key numbers",
        "",
        "Findings use shared cases; tokens and costs per case use all attempted cases. "
        "n/a means a value was not recorded.",
        "",
    ]
    for model, runs in groups.items():
        shared = runs[0]["shared_cases"]
        lines += [
            f"{heading}# {model} ({_plural(shared, 'shared case')})",
            "",
        ]
        lines += _limits_note(runs)
        lines += [
            f"| {' | '.join(headers)} |",
            f"| --- | {' | '.join(['---:'] * (len(headers) - 1))} |",
        ]
        for row in runs:
            cells = [
                series_label(row), count(row["findings"]),
                count(higher_confidence(row)), count(row["likely_vulnerabilities"]),
                tokens(row["tokens_per_case"]),
            ]
            change = "n/a" if row["cost_change_pct"] == "" else f"{row['cost_change_pct']:+.1f}%"
            if row["condition"] == "baseline":
                change = "—"
            cells += [usd(row["cost_per_case_usd"], 4), usd(total_cost(row)), change]
            cells.append(share(row["unfinished"], row["cases"]))
            lines.append(f"| {' | '.join(cells)} |")
        lines.append("")
    return lines


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
    groups: Mapping[str, Sequence[Row]], colors: Mapping[str, str],
    top: float, *, cost_limits: Mapping[str, float],
) -> Figure:
    """Plot total USD cost and findings, with compact labels beside round dots."""
    figure, axes = _figure([2.6] * len(groups), sharex=False)
    for axis, (model, runs) in zip(axes, groups.items()):
        right = cost_limits[model]
        shared = runs[0]["shared_cases"]
        axis.set_title(
            f"{model} · {_plural(shared, 'shared case')}",
            loc="left", fontsize=9.5, fontweight="bold", color=INK,
        )
        missing = []
        for index, row in enumerate(runs):
            resource = total_cost(row)
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
                color=colors[label],
                edgecolor="white",
                zorder=3,
            )
            on_right = dot[0] > right / 2
            dy = (-13 if on_right else -10) if row["condition"] == "secure_prompt" else 0
            if row["condition"] == "codeguard":
                dy = 15 if index % 2 == 0 else (-17 if on_right else 4)
            axis.annotate(
                label,
                dot,
                xytext=(-8 if on_right else 8, dy),
                textcoords="offset points",
                ha="right" if on_right else "left",
                va="bottom" if dy > 0 else "top" if dy < 0 else "center",
                fontsize=7.2,
                bbox={"facecolor": "white", "edgecolor": "none", "pad": 1.5},
                arrowprops={"arrowstyle": "-", "color": MID, "linewidth": 0.55} if abs(dy) > 6 else None,
            )
        if missing:
            note = (
                f"Not recorded: {listed(missing)}"
                if shared else "No case produced changed, valid code in every run"
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


def _confidence_figure(groups: Mapping[str, Sequence[Row]]) -> Figure:
    counts = {
        row["run"]: {label: row[metric] for label, metric, _ in CONFIDENCE}
        for runs in groups.values() for row in runs
    }
    shared = {model: runs[0]["shared_cases"] for model, runs in groups.items()}
    return _stacked_figure(
        groups, counts, [(label, color) for label, _, color in CONFIDENCE],
        shared=shared,
    )


def _stacked_figure(
    groups: Mapping[str, Sequence[Row]], counts: Numbers,
    parts: Sequence[tuple[str, str]], *, shared: Mapping[str, int] | None = None,
) -> Figure:
    heights = [0.45 * len(runs) for runs in groups.values()]
    figure, axes = _figure(heights)
    handles = [
        Patch(color=color, label=name)
        for name, color in parts
        if any(run[name] for run in counts.values())
    ]
    if handles:
        axes[0].legend(
            handles=handles, loc="lower left", bbox_to_anchor=(0, 1),
            ncols=len(handles), handlelength=1, borderaxespad=0,
        )
    widest = max(
        (sum(run.values()) for run in counts.values() if "" not in run.values()), default=0
    ) or 1
    for axis, (model, runs) in zip(axes, groups.items()):
        axis.set_title(
            model if shared is None else f"{model} · {_plural(shared[model], 'shared case')}",
            loc="left", fontsize=9.5, fontweight="bold", color=INK,
            pad=24 if axis is axes[0] and handles else 6,
        )
        axis.set_yticks(range(len(runs)), [series_label(row) for row in runs])
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
            labels = [
                f"{value:,}" if value >= (0.02 if shared is not None else 0.04) * widest else ""
                for value in values
            ]
            axis.bar_label(
                bars, labels=labels, label_type="center", fontsize=7.5,
                color=INK if name in {"Completed", "Medium", "Low"} else "white",
            )
            left = [start + value for start, value in zip(left, values)]
        if shared is not None:
            axis.bar_label(bars, labels=[f"{total:,}" for total in left], padding=4, fontsize=8)
        axis.set_xlim(0, widest * (1.12 if shared is not None else 1))
    axes[-1].set_xlabel("Findings" if shared is not None else "Cases")
    return figure
