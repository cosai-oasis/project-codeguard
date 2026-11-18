# Evaluation Results

These pages publish results from the
[CodeGuard evaluation harness](https://github.com/cosai-oasis/project-codeguard/tree/main/evaluations/codeguard-inspect),
which compares Semgrep findings in code written by an AI coding agent and
records model usage and available cost data. Results are exploratory.

## How the evaluation works

- **Tasks:** the 121 Python tasks of the
  [SecurityEval](https://github.com/s2e-lab/SecurityEval) benchmark, each built
  around a known weakness.
- **Agent:** the Codex coding agent, working in an isolated container with no
  network access. Each attempt has a turn and time limit.
- **Conditions:** every model runs the same tasks three ways:
    - **Baseline:** the standard task prompt.
    - **Secure prompt:** the same prompt plus a one-sentence request to write
      secure code.
    - **CodeGuard:** the standard prompt with the CodeGuard skill installed. The
      agent decides whether to use it.
- **Scoring:** the harness keeps the final file, checks its Python syntax, and scans it with a pinned version of Semgrep and its public rules.
  Generated code is never run.

## What the pages show

- **Epochs:** each pass over the cases is reported separately.
  For multi-epoch runs, token and cost totals use each case's final saved
  attempt. Retry usage recorded only for the whole run is excluded.
- **Limits:** recorded turn, generation-time, case-time, and output-token caps.
  Shown on the report and in `results.csv`. Missing limits stay blank in the CSV.
- **Findings:** Semgrep security findings at all confidence levels, counted on the shared cases,
  where every run for a model produced changed, valid code. Unchanged or
  invalid outputs are excluded. An attempt stopped by a limit can still
  contribute findings if its output passes those checks, and also counts
  as unfinished. Passing the checks does not establish functional correctness.
- **Likely vulnerabilities:** findings from rules tagged `vuln`.
  This is a rule category, not a confidence rating.
- **High + Medium:** findings from rules rated High or Medium confidence.
  The confidence chart shows High, Medium, and Low on the same shared cases.
  Low-confidence findings remain in the total.
- **Tokens per case:** recorded tokens divided by all attempted cases.
  Includes cached input and retries. Token counts are not costs.
- **Costs:** total USD and USD per case, using complete recorded costs or
  estimates calculated from supplied model prices. When prices are supplied,
  all runs use those rates. Per-case costs average all attempted cases,
  including unfinished ones. Every run needs a complete recorded or estimated
  cost.
- **Total USD vs baseline:** percentage change in total USD cost from the same
  model's baseline, calculated from unrounded amounts. Missing costs stay blank.
- **Unfinished attempts:** attempts that hit any limit or ended with an error.

## Limitations

- **Static analysis only.** Findings are scanner results, not confirmed
  vulnerabilities, and no findings does not mean the code is secure or even
  correct. SecurityEval has no functional or exploit tests.
- **Limited scanner coverage.** The pinned rules flag only 48 of the
  benchmark's 121 known-insecure reference programs, so many weaknesses go
  unseen.
- **One benchmark, one language.** All tasks are Python.
- **Small numbers.** Each epoch is one pass over 121 cases. A difference
  of a few findings can be chance.
- **Limits shape the results.** Attempts that hit a limit leave work unfinished.
  Compare runs only when their settings match; each page warns when they do
  not.
- **Using the skill is up to the agent.** Reading CodeGuard does not prove the
  agent followed it.

## Result sets

The [results exporter](https://github.com/cosai-oasis/project-codeguard/tree/main/evaluations/codeguard-inspect#export-results)
creates the page, charts, and public CSVs together from completed harness logs.

- [CodeGuard 1.4.0 on SecurityEval](2026-09-codeguard-1.4.0/index.md)
