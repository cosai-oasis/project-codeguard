# Evaluation Results

These reports compare security findings, token usage and costs across prompts
and skills. Each report identifies the benchmark, model, selected examples and
run settings.

## Reading the results

- **Findings:** We compare the same examples across runs for each model. If the
  scanner cannot fully check an example in any compared run, we leave it out of
  every run’s findings comparison.
- **Costs:** Pages show totals and changes versus baseline. Token and per-case
  averages are in the CSVs. Missing token counts are noted when present, and some
  spending may be missing from estimates. Check each report's pricing note for
  the rates used.
- **Unfinished examples:** Generation stopped because of a time limit, turn limit
  or error. Saved code may still have been scanned.

Compare runs with matching models, examples and settings. Findings are potential
issues, not confirmed vulnerabilities. A clean scan does not prove code is secure
or works correctly. Reading a skill does not prove its guidance was followed.
One pass through the examples does not show how results vary across repeated runs.

## Benchmark guides

See [SecurityEval](../evaluations/securityeval.md) and
[CyberSecEval](../evaluations/cyberseceval.md) for datasets, scoring, limitations
and export commands. The [harness guide](../evaluations/index.md) explains how
runs are generated and scanned.

## Reports

- [CodeGuard 1.4.0 on SecurityEval](2026-09-codeguard-1.4.0/index.md)
