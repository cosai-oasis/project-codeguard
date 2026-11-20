# Run the evaluation harness

Compare Codex with and without CodeGuard using [Inspect AI](https://inspect.aisi.org.uk/)
and [Inspect SWE](https://meridianlabs-ai.github.io/inspect_swe/).
The model writes code and saves it in a log. A separate scanner checks that
code without compiling, importing or executing it.

## Benchmarks

| Guide | Name to use in commands |
| --- | --- |
| [SecurityEval](securityeval.md) | `securityeval` |
| [CyberSecEval instruct-v2](cyberseceval.md) | `cyberseceval` |

Each guide explains which cases to run, how scores are calculated, rule licenses
and known limitations.
For skill comparisons, select a no-skill baseline and one or more catalog entries.
A skill run installs the selected snapshot and uses the baseline's task prompt.
The catalog label identifies the released version, candidate or reminder being evaluated.

| Run type | Prompt | Installed skill |
| --- | --- | --- |
| Baseline (`baseline`) | Standard task | None |
| Selected skill (`skill`) | Same as baseline | Selected frozen catalog snapshot |
| Prompt reminder (`secure_prompt`, optional) | Standard task plus a security reminder | None |

The matrix command lets you choose these runs. The benchmark-package commands
below run the baseline, prompt reminder and configured CodeGuard catalog entry.

## Prepare

Use Python 3.13, `uv`, Git and Docker Compose 2.17+ with BuildKit.
Run commands from `evaluations/codeguard-inspect`. These examples use SecurityEval;
replace `securityeval` with `cyberseceval` in the commands and log paths for CyberSecEval.

```bash
uv sync --locked --managed-python
uv run --locked python -m codeguard_evals.prefetch --benchmark securityeval
```

Configure the ignored `.env` from `.env.example`; choose a model and budget.
Provider credentials stay on the host. HTTPS uses the host's trusted certificate
store. Retain the seven-day dependency cooldown without exceptions or overrides.

Prefetch downloads fixed versions of datasets and scanner rules, checks their
hashes, and saves them in `.cache/codeguard-evals`. Use `--stage generation`
for datasets only or `--stage scan` for scanner files only. Do not change the
harness or prepared files during an experiment.

## Generate and resume

Start with one case per condition to check the full pipeline before a larger run.
Replace `openai/MODEL` with your chosen model:

```bash
uv run --locked inspect eval-set codeguard_evals/securityeval \
  --limit 1 --model openai/MODEL --reasoning-effort medium \
  --epochs 1 --no-epochs-reducer --retry-attempts 0 --max-retries 0 \
  --max-tasks 1 --max-samples 1 --max-sandboxes 1 --max-subprocesses 1 \
  --continue-on-fail --log-dir logs/securityeval-smoke
```

Use the benchmark guide's selection options, or remove `--limit 1` for all cases.
Repeat the same command to resume. Completed attempts are reused; interrupted
or errored attempts run again. An attempt that finished at a normal turn or time
limit is still considered complete. Use one generation process per log directory
and a new directory when settings change.

Default limits are 16 turns, 32,768 output tokens and 600 seconds.
`-T agent_turn_limit=N` changes the turn limit. Normal turn or time limits keep
any saved code. A separate 1,200-second overall timeout records an error.

## Select a skill variant

Use `codeguard_evals/experiments.py@skill` to select one entry from
`evaluations/codeguard-inspect/skill_snapshots/catalog.json`. The task uses the
baseline prompt and installs only the selected skill for normal agent discovery.
A skill directory may contain only `SKILL.md`; Markdown guidance in `references/`
or the existing CodeGuard `rules/` layout is also supported. Names and contents
are preserved. Executable scripts and remote skill downloads are not supported.

```bash
uv run --locked inspect eval-set codeguard_evals/experiments.py@skill \
  -T benchmark=securityeval -T variant=security-reminder-v1 \
  --model openai/MODEL --limit 1 --max-samples 1 --max-sandboxes 1 \
  --retry-attempts 0 --max-retries 0 --log-dir logs/reminder-smoke
```

For the matching control, use `@baseline`, omit `-T variant`, and choose a separate
log directory. Set `benchmark=cyberseceval` for CyberSecEval; its `languages` option
works as usual. Scan and export the resulting logs with the existing commands.

To add a candidate:

1. Place its reviewed Agent Skills directory under `skill_snapshots/REVISION/`.
   `SKILL.md` needs standard frontmatter, and its name must match its directory.
2. Compute its fingerprint with the command below. Paths are relative to the
   repository root, even when running the command from this harness directory.
3. Add a catalog entry with a stable ID, `label`, `path` and `content_sha256`.
   Use a new ID for revised guidance. Do not edit selected inputs during a run.

```bash
uv run --locked python -m codeguard_evals.skill_catalog \
  evaluations/codeguard-inspect/skill_snapshots/CANDIDATE/SKILL-NAME
```

The fingerprint covers the accepted file paths and original bytes. Mismatches
fail before generation. Saved logs retain the variant identity and installed
document, so scoring and reporting do not depend on the current catalog.

To evaluate a new CodeGuard release with the benchmark commands, add its snapshot
and catalog entry, then set `CODEGUARD_VARIANT` in `codeguard_evals/skill_catalog.py`
to the new ID.

## Run an experiment matrix

Set models, skills and benchmarks in a JSON file, starting with
`evaluations/codeguard-inspect/experiments/compare-skills.example.json`.
Replace its model placeholders with your provider/deployment IDs. Prepare each
selected benchmark with the existing prefetch command, then preview the run:

```bash
uv run --locked python -m codeguard_evals.experiments \
  --matrix experiments/compare-skills.example.json \
  --log-dir logs/skill-comparison --dry-run
```

Remove `--dry-run` to generate and batch-scan (`--stage all`, the default).
Use `--stage generation` to generate now and scan later. Preview validates inputs and shows
the number of evaluations and samples before retries; it makes no model calls
and starts no containers. Codex is the supported coding agent for this command.
`--log-dir` must be new, or a private (`0700`) directory from an earlier run of
the same matrix; the command creates new directories as private, and preview
applies the same checks.

`defaults` applies to each benchmark. Benchmark entries replace individual
values; lists replace lists. Use `"all"` for benchmarks, skills or supported
agents, or select names explicitly. The example compares the no-skill baseline
with installed skills. The prompt-based `secure_prompt` control remains optional
and is off by default. CyberSecEval accepts `languages`; `limit` caps samples per
task and epoch.
Execution options use Inspect's names, including concurrency, retries and display.
An optional `model_cost_config` points to native Inspect pricing, relative to the
matrix file. Pricing keys must match provider/deployment IDs, rather than the
display labels used by the report exporter's `--prices` file.
The rates are validated, recorded in `resolved.json` and passed directly to Inspect.

The command records its selections in `resolved.json`. Rerun the same command to
resume generation; new catalog entries do not join an existing run. Keep the
effective selections, settings and prices unchanged between resumes. Any change,
including concurrency, retries or display, requires a new run directory.
Use `--debug` for a local traceback if startup or execution fails unexpectedly.
Debug output can include private provider details; review it before sharing.

To scan saved generations without running models:

```bash
uv run --locked python -m codeguard_evals.experiments \
  --stage scan --log-dir logs/skill-comparison
```

Scan-only uses `resolved.json` and the generation logs, so it rejects `--matrix`
and does not read the pricing file or current skill catalog. Prepare the scanner
artifacts first; `--dry-run` previews the saved logs without starting containers.

Logs are grouped under `generation/BENCHMARK/` and `scored/BENCHMARK/`. Scanning
calculates scores from saved outputs. Incomplete generation or scans return a
nonzero exit status. Scanning repeats on resume; no separate scan cache is created.
Export reports from the scored logs with the existing export command.

## Scan

After generation completes:

```bash
uv run --locked python -m codeguard_evals.scan \
  logs/securityeval-smoke --output-dir logs/securityeval-smoke-scored
```

The scanner uses one container per log. If you pass a directory, the command
selects the latest log for each task. Pass individual log paths to choose them
yourself. Running the scan again checks every saved output without calling the
model. Scanner diagnostics go in `<output-dir>/.scan-control/`.

Scanners can use up to four CPUs by default; set `CODEGUARD_SCANNER_CPUS=2.0` before
scanning to use CI's limit. Use one scanner per output directory, retain `.scan.lock`,
and use a new output directory when scanner settings change.

If the scanner cannot fully check a file, it is not counted as having zero
findings. Each benchmark guide explains how these files are reported. A scanner
crash or batch timeout stops processing and removes the container without writing
new results for that log. Saved generations and earlier results remain intact.

## Replay saved scores

This recalculates scores from saved scanner results without generating or
scanning code again. Replace `SCORER` with the path in the benchmark guide:

```bash
uv run --locked inspect score logs/RUN-scored/FILE.eval \
  --model mockllm/model --stream 1 --scorer SCORER \
  --action overwrite --output-file logs/RUN-rescored/FILE.eval --display none
```

This command needs no Docker, downloaded rules or model calls. Compare runs
that used the same scanner code, rules and settings. Use the original harness
and dependencies for logs from an older evaluation format.

## Safety and maintenance

Agent commands and scanner processes run as non-root, without network access
and with resource limits. Provider credentials and the Docker socket stay outside them. Scanners have read-only filesystems,
bounded temporary storage and strict evidence validation; they ignore `nosemgrep`.
Logs contain prompts, source, tool traces, skill content and local paths. Review
them before sharing. Keep the log viewer accessible only from your own machine
and use `--no-trust-content`.
On shared machines, optionally run `umask 077` before generation to keep new logs private.

Report missing outputs, files the scanner could not check, and unfinished
generations alongside finding rates. A clean scan does not prove code is secure
or works correctly. A small test run checks that the tools work together; it does
not establish whether CodeGuard improves security.

```bash
uv run --locked --group reporting pytest
```

CI also runs benchmark artifact checks and Docker tests with fixtures and mock
generation. New benchmarks provide a `StaticBenchmark` and `StaticGrader`, registered
in `prefetch.PREPARERS` and `scan.GRADERS`, plus a guide and navigation entry.
Keep rules and scoring benchmark-specific. Executing candidate programs requires
a separate isolation design.

To add reports, create `reporting.py` in the benchmark folder and register it in
`export_results.REPORTERS`. It validates saved scores, reads recorded scanner and
skill versions, selects the examples to compare, and defines tables and charts.
Reuse the shared functions for reading logs, comparing settings, pricing and rendering.
