# CyberSecEval instruct-v2

This harness asks the model to save one code file per case, often a function or
small snippet. We scan the saved code without compiling or executing it.

Follow the [shared workflow](index.md), using `cyberseceval` in commands and log
paths. To replay saved scores, set `SCORER` to
`codeguard_evals/cyberseceval/scorers.py@cyberseceval_scorer`.

## Dataset

Meta's [instruct-v2 dataset](https://github.com/meta-llama/PurpleLlama/blob/172c1074069eb88ec834124272c1b1c4f8893445/CybersecurityBenchmarks/datasets/instruct/instruct-v2.json)
is fixed to a commit and verified by SHA-256.

| Language | Cases | Security checks |
| --- | ---: | --- |
| C | 202 | Regex and Semgrep OSS |
| C++ | 242 | Regex and Semgrep OSS |
| C# | 218 | Regex and Semgrep OSS |
| Java | 164 | Regex and Semgrep OSS |
| JavaScript | 244 | Regex and Semgrep OSS |
| PHP | 151 | Regex |
| Python | 282 | Regex and Semgrep OSS |
| Rust | 178 | Regex |
| Total | 1,681 | |

An epoch is one pass through the selected cases. All cases under baseline,
secure prompt and CodeGuard produce 5,043 generations per epoch.

Use `-T languages=c,cpp` to select C and C++. `--limit N` takes the first N cases
per condition, without balancing languages. For a small real-model check,
`-T languages=cpp --limit 1` runs one C++ case per condition: three generations
at one epoch. Use `--sample-id` to select specific sample IDs instead.

The agent receives the coding request, not the original source snippets
(`origin_code`) or scanner rules. Those snippets are often incomplete. Our agent
setup and scoring differ from Meta's, so our results are not directly comparable
with Meta's published scores.

## Rules and scoring

We use Meta's Insecure Code Detector (ICD) rules from
[CodeShield](https://github.com/meta-llama/PurpleLlama/tree/172c1074069eb88ec834124272c1b1c4f8893445/CodeShield).
Regex rules match text patterns; Semgrep checks code structure. The C/C++ bundle
has 19 Semgrep rules, and C++ also uses C regex rules. No account or Pro rules
are required.

`icd.lock.json` records the commit, sizes and hashes of 17 rule, configuration
and license files, plus the expected hash of the prepared JSON bundle.
Preparation verifies the source files and converts YAML rules to JSON.
The scanner image verifies its rules during build and keeps them read-only.
It retains Meta's MIT license and copyright notice. Normal runs use our scanner
code, not Meta's Python modules or test programs.

| Metric | Meaning |
| --- | --- |
| `output_present` | The agent's output file was saved |
| `output_nonempty` | The file contains more than whitespace |
| `scan_complete` | All required checks finished without errors |
| `icd_flagged_output` | The fully checked file has at least one finding |
| `icd_finding_count` | Findings in the fully checked file |
| `loc` | Nonblank source lines |
| `skill_loaded` | The trace shows the full skill was read; skill runs only |

Missing or empty files, parsing errors, timeouts and resource limits leave
finding scores blank. Partial findings are discarded. These examples never
count as having zero findings. The scan command can still finish successfully;
check scan coverage to see how many files were fully checked.

Regex checks have five seconds per file; a timeout records `rule_timeout`.
They follow Meta's first-match behavior: a match in a comment can hide a later
match in code. Semgrep requires complete checks and ignores `nosemgrep` comments
that would hide findings. Crashes and batch timeouts follow the
[shared scan policy](index.md#scan).

## Reporting

Export scored logs as a page, charts and CSVs:

```bash
uv run --locked --group reporting python -m codeguard_evals.export_results \
  --run "Model name" BASELINE.eval \
  --run "Model name" SECURE_PROMPT.eval \
  --run "Model name" CODEGUARD.eval \
  --language c --prices PRICES.json --output-dir REPORT_DIRECTORY
```

Use `--language` for one language, or omit it for all languages in the selected
logs. Each export needs a new output directory. Reports use the same chart style
and price-file format as SecurityEval.

Charts show findings versus cost, generation outcomes and rule severity.
`results.csv` lists totals for each run and epoch; `samples.csv` lists every
attempt, including unfinished generations and files the scanner could not check.

For each model and epoch, findings compare the same examples across runs. If the
scanner cannot fully check an example in any compared run, we leave it out of
every run's findings comparison. Scan coverage still counts all attempts.

Error, Warning, Info and Advice are rule labels, not scanner failures or confirmed
vulnerabilities. Meta's rules lack consistent confidence and vulnerability
categories, so SecurityEval's confidence and "likely vulnerabilities" columns
are omitted.

### Tokens and costs

Use `--prices` when logs lack complete costs. Historical rates are never selected
automatically. Estimated costs are separate from recorded costs and are not
actual charges.

A single-epoch report covering the whole run uses its total recorded tokens,
including retries. Other reports add the token counts saved for each selected
attempt. A language filter that excludes nothing keeps the same totals.

Some attempts have no saved token count. Reports that add up individual attempts
leave out those costs, so the estimated total may be too low. The page shows these counts only when any
are missing; the CSV keeps them for every run. Retry costs are also left
out when the logs do not say which example used those tokens.

## Interpreting results

- Compare matching models, cases, settings and epochs. One epoch does not show
  variation across repeated generations.
- Show missing outputs, scan coverage and unfinished generations alongside
  finding rates, by language and CWE (weakness type).
- Review whether outputs solve the task and whether findings are false alarms.
  Hide condition labels during review; check rules and matches hidden by comments.
- Treat raw finding counts as secondary: regex reports at most one match per
  pattern, while Semgrep can report several. Shorter code is not proof of security.

## Maintaining the rules

Review upstream changes and update the source pins and `prepared_tree_sha256`
in `icd.lock.json`, plus the matching build-context path in `sandbox/icd.yaml`.
Prefetch the new files, then run the reference checks and container tests from
`evaluations/codeguard-inspect`.

```bash
uv run --locked pytest -m artifacts tests/test_icd_parity.py
```

The reference fixture stores expected findings and file hashes, not source code.
Its 6,724 checks cover 1,681 snippets in four forms and verify regex behavior only,
not equivalent Semgrep results.

Regenerating that fixture is a separate offline maintainer step. Review its pinned
versions and supply the verified local reference bundle:

```bash
uv run --locked python -B -m tests.icd_regex_reference --reference-root /PATH/TO/VERIFIED-BUNDLE
```

Only this command imports Meta's Python, after checking its hashes. It never
executes generated source. Normal tests use our scanner and the saved results.
