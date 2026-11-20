# SecurityEval

Follow the [shared workflow](index.md) using `securityeval` in commands and log
paths. To recalculate scores from saved scanner results, set `SCORER` to
`codeguard_evals/securityeval/scorers.py@static_safety_scorer`.

## Dataset and rules

SecurityEval has 121 Python tasks, each with starter code for the model to
complete. An epoch is one pass through those tasks. Running baseline, secure
prompt and CodeGuard creates 363 generations per epoch, or 1,089 over three epochs.
The harness checks file size, UTF-8 encoding and Python syntax. It does not check
whether the code solves the task.

The version and hashes of the official Semgrep rules are recorded in
`semgrep.lock.json`. The
[Semgrep Rules License](https://semgrep.dev/legal/rules-license/) permits internal
business use and prohibits redistribution. Rules are downloaded locally and
mounted read-only to keep them out of distributed images. The host verifies them
before scanning.

Prefetch downloads only pinned YAML rule files and `LICENSE` into
`.cache/codeguard-evals/semgrep-rules-only/`, verifying each file's size and
SHA-256 before writing it. The manifest's tree hash covers the complete bundle,
including the license. Executable test fixtures are excluded.

## Scoring

| SecurityEval metric | Meaning |
| --- | --- |
| `valid_output` | Saved code passes size, encoding and syntax checks |
| `changed_output` | Saved code differs from the starter code (byte comparison) |
| `loc` | Nonblank source lines |
| `finding_count` | Number of included Semgrep security findings |
| `semgrep_flagged_output` | The fully checked file has at least one included finding |
| `subcategory_*`, `severity_*`, `confidence_*` | Findings grouped by category, severity or confidence |
| `skill_loaded` | The trace shows the full installed skill was read; skill runs only |

Missing or invalid code and files the scanner could not fully check have no
finding score. Incomplete scans are recorded as errors. The command still
processes the remaining logs, then exits with an error status.
SecurityEval retains `category: security` findings except `EXPERIMENT` and `INVENTORY`.
`CRITICAL`/`HIGH`, `MEDIUM` and `LOW` map to error, warning and info bands.
Rule confidence is not a measured probability of a vulnerability.
Reading the skill does not prove its guidance was followed.

These rules flag only 48 of the 121 known-insecure reference programs. A clean
scan does not prove the generated code is secure.

## Export results

Run export commands from `evaluations/codeguard-inspect`. The exporter creates a
page, charts, `results.csv` and `samples.csv` from scored SecurityEval logs.

```bash
uv run --locked --group reporting python -m codeguard_evals.export_results \
  --title "CodeGuard on SecurityEval" \
  --run "Model A" logs/securityeval-scored/BASELINE.eval \
  --run "Model A" logs/securityeval-scored/SECURE_PROMPT.eval \
  --run "Model A" logs/securityeval-scored/CODEGUARD.eval \
  --output-dir ../../docs/results/securityeval-comparison
```

Use model names that are safe to share, with matching cases and epochs across
conditions. `--epoch N` exports one epoch. The output directory must be new.

Findings compare the same examples across runs. An example is included only if
every compared run produced changed, valid Python with a complete finding score.
Costs include recorded usage from unfinished attempts. Missing token counts are
noted when present; estimates may leave out some spending. Detailed metrics remain
in the CSVs.

To include costs, use `--model-cost-config` when generating, or supply
`--prices FILE.json` when exporting. The price file maps each model label to
rates per million tokens. The same supplied rates apply to every run; estimated
costs are kept separate from costs saved in the logs.

Use `--cost-note` to explain the prices used. Estimates may differ from actual
charges. See
`reporting/model-prices.json` for the price-file format and
[Evaluation Results](../results/index.md) for guidance on reading reports.
