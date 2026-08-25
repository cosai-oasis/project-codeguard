# CodeGuard Inspect Evaluation

This application evaluates a pinned Codex CLI against a fixed revision of the
SecurityEval benchmark. [Inspect AI](https://inspect.aisi.org.uk/) manages tasks,
sandboxes, logs, and scoring, while
[Inspect SWE](https://meridianlabs-ai.github.io/inspect_swe/) provisions Codex.
Codex generates code in one networkless container, and a separately isolated,
digest-pinned Semgrep service analyses the captured source. The generated source
is never executed by the harness.

The experiment compares three conditions:

| Task | Condition | Metrics |
| --- | --- | --- |
| `securityeval_static_safety_baseline` | Standard task prompt, no skill | `valid_output`, `loc`, `implemented_output`, `finding_count` |
| `securityeval_static_safety_secure_prompt` | Security-focused prompt, no skill | `valid_output`, `loc`, `implemented_output`, `finding_count` |
| `securityeval_static_safety_codeguard` | Standard prompt with repository CodeGuard available for automatic routing | `valid_output`, `loc`, `implemented_output`, `finding_count`, `skill_loaded` |

The baseline and CodeGuard conditions receive the same prompt. The CodeGuard
condition installs the repository skill but does not explicitly ask Codex to load
it. The secure-prompt condition measures a plain request to implement securely
without a skill.

## What It Measures

All 121 pinned SecurityEval cases run in each condition:

- `valid_output` is one when `solution.py` is bounded UTF-8 Python that parses,
  changes the scaffold, and preserves its requested top-level interface.
- `loc` is the number of non-blank generated lines.
- `implemented_output` is one only for a valid output that is not an obvious
  stub. Invalid and stub outputs remain in this metric's denominator as zero.
- `finding_count` counts Semgrep `category: security` findings classified as
  `vuln` or `secure default`, except `EXPERIMENT` and `INVENTORY` severities.
  Audit findings are retained for secondary analysis. Invalid and stub outputs
  leave this metric unscored rather than appearing clean.
- `skill_loaded` records a recognized successful read of CodeGuard's `SKILL.md`.
  It is scored only in the CodeGuard condition.

These are structural and static-analysis measurements. They do not prove
functional correctness or security.

## Reproducible Scanner Contract

The tracked `semgrep.lock.json` pins:

- Semgrep 1.173.0's official non-root, multi-platform image by OCI index digest.
- The public `semgrep/semgrep-rules` repository at commit
  `40b8c63f75dc7c22c8a77482d73bfb864b146f7e`, its `python/` directory,
  reviewed rule counts, and finding selection.

Semgrep loads all 378 rules from the checkout's 337 YAML files. The harness
retains findings only from the 269 rules whose metadata category is `security`:
133 `vuln`, 135 `audit`, and one `secure default`. Compare results only when the
image digest, rules commit, and finding filter recorded in the logs match. The
provenance records the working-tree validation boundary as `operator-trusted`.

The operator prepares the checkout locally; the harness neither downloads nor
modifies it, and the checkout is not committed. Its use and redistribution are
subject to the [Semgrep Rules License](https://semgrep.dev/legal/rules-license/).
The commit remains publicly reconstructable. A rules update is a reviewed lock
change followed by a complete rerun of every condition; there is no runtime
refresh flag.

## Prepare

Requirements are Python 3.11 or newer, Git, `uv`, and a current local Docker
installation. Git is used only by the operator to prepare the rules; the Python
harness never invokes it.

From `evaluations/codeguard-inspect`, prepare the standalone checkout if it is
not already present:

```bash
umask 022
rules_commit=40b8c63f75dc7c22c8a77482d73bfb864b146f7e
rules_checkout=".cache/codeguard-evals/semgrep-rules/$rules_commit"
install -d -m 0700 "$(dirname "$rules_checkout")"
git clone --quiet --filter=blob:none --no-checkout \
  https://github.com/semgrep/semgrep-rules "$rules_checkout"
git -C "$rules_checkout" checkout --quiet --detach "$rules_commit"
chmod 0700 "$rules_checkout"
```

Keep this checkout unmodified. The harness trusts the operator-supplied working
tree and does not run Git to check its cleanliness.

Then prepare the remaining artifacts and generation image:

```bash
uv sync --locked
uv run --locked python -m codeguard_evals.prefetch
docker compose --file sandbox/compose.yaml build
```

The prefetch command:

1. Verifies the operator checkout's private filesystem boundaries and literal
   detached Git HEAD without running Git.
2. Downloads and semantically validates the pinned SecurityEval dataset.

The cache and checkout roots must be mode `0700`; `.git` and the mounted
`python/` path must be real directories, and `.git/HEAD` must contain the locked
commit directly. Missing or invalid content fails closed. The runtime service
uses `pull_policy: missing`, so Compose reuses the locally cached Semgrep image
or pulls the exact locked digest before starting samples. The scanner itself
remains networkless and never contacts the Semgrep Registry. Docker Scout is not
used.

To populate the image cache explicitly before an offline evaluation, run:

```bash
docker compose --file sandbox/compose.yaml pull --policy missing semgrep
```

Inspect SWE obtains the pinned Codex 0.146.0 asset and verifies the release digest
before copying the binary into the generation container. Treat its user-writable
binary cache and the Semgrep cache as trusted local state; do not restore either
from an untrusted or cross-tenant cache, and do not modify the rules checkout
during an evaluation.

Use a trusted local Docker daemon for evaluation. The harness does not mount a
Docker socket into either service, but Inspect itself uses the operator's
configured Docker daemon to create the Compose environment and pull a missing
scanner image.

## Run

Use a clean committed harness checkout so the recorded revision identifies the
experiment. Replace `openai/MODEL` with the model under evaluation. Prefer an
immutable model identifier when available.

Start with one sample:

```bash
uv run --locked inspect eval \
  codeguard_evals/securityeval/securityeval.py@securityeval_static_safety_codeguard \
  --model openai/MODEL \
  --sample-id static_safety/codeguard/CWE-078_author_1.py \
  --max-retries 0 \
  --max-samples 1 \
  --log-dir logs/securityeval-smoke
```

Run the full matrix:

```bash
uv run --locked inspect eval-set \
  codeguard_evals/securityeval/securityeval.py \
  --model openai/MODEL \
  --epochs 3 \
  --no-epochs-reducer \
  --retry-attempts 0 \
  --max-retries 0 \
  --max-tasks 1 \
  --max-samples 1 \
  --max-sandboxes 1 \
  --max-subprocesses 1 \
  --continue-on-fail \
  --log-dir logs/securityeval-matrix
```

This launches 1,089 generations: 3 conditions x 121 cases x 3 epochs. The
documented settings intentionally run serially. `--no-epochs-reducer` preserves
each generation because invalid and stub outputs have no `finding_count`, and
standard errors are clustered by case.

After each normal generation—or one stopped by the configured output-token,
turn, or generation-time limit—the solver captures the source, classifies it,
and scans valid non-stub implementations. Invalid and obvious-stub outputs skip
Semgrep. A scanner or evidence failure fails the sample rather than recording
zero findings. `--retry-attempts 0` prevents a completed model generation from
being repeated because later scanner infrastructure failed.

Inspect checkpointing is disabled because a checkpoint would retain more sandbox
state than the bounded `solution.py` artifact.

## Review and Re-score Logs

View logs with:

```bash
uv run --locked inspect view --log-dir logs/securityeval-matrix
```

Keep the viewer loopback-only. Logs contain prompts, generated source, model
messages, tool activity, and normalized scanner findings. The harness does not
redact them, so use only public, non-sensitive benchmark inputs.

The solver stores two independently validated records:

- `SavedOutput` preserves the bounded source even if scanning later fails.
- `SemgrepEvidence` binds normalized findings to that source's SHA-256, the
  evaluation contract, the image digest, and the rules commit.

`SemgrepEvidence` is absent when evidence finalization does not run or fails.
Within a stored evidence record, `findings: null` means scanning was not
applicable; an empty findings collection means Semgrep ran successfully and
found no retained security findings.

`--no-score` still performs Semgrep during solving. Consequently, a completed log
can be re-scored without Docker, the rules cache, Registry access, or provider
credentials:

```bash
uv run --locked inspect score \
  logs/securityeval-matrix/RUN.eval \
  --model mockllm/model \
  --stream 1 \
  --scorer codeguard_evals/scorers.py@static_safety_scorer \
  --action overwrite \
  --output-file logs/securityeval-rescored/RUN.eval \
  --display none
```

The scorer revalidates the source and evidence identity, recalculates the metric,
and never launches a sandbox. A log whose original Semgrep scan failed has no
findings evidence and cannot be recovered with `inspect score`; a separate
source re-scan workflow is intentionally deferred. Re-score only trusted logs
from the matching checkout because logs are trusted input, not authenticated
artifacts.

## Measurement Details

### Skill routing

Codex uses normal implicit skill routing. `skill_loaded` is one when the logged
tool-call pair shows a successful recognized reader command for the exact
installed `SKILL.md`. It is a lower bound: an unrecognized read path can produce
zero, and a successful read does not prove that the guidance was followed.

The CodeGuard condition validates and hashes the repository's
`skills/codeguard` directory, installs those exact bytes under
`/workspace/.codex/skills/codeguard`, and makes the snapshot read-only before
generation. It does not reshape the published skill.

### Generation limits and evidence

The output-token, turn, and generation-time limits are scoped to the agent. A
limit-stopped sample is therefore captured and scanned rather than disappearing
from the metric denominators. Exact `LimitExceededError` provenance, or Inspect's
matching recent sample-limit event for a bridge-promoted cancellation, identifies
these cases.

Operator interruption, shutdown, and unrelated errors capture the source but do
not start Semgrep; they re-raise promptly. Output capture is shielded only long
enough to preserve the bounded artifact. Scanner evidence collection for normal
and configured-limit completions is in the same finalization block so Inspect's
limit cancellation cannot skip it.

### Semgrep findings

The scanner runs the pinned local rules directory in strict, quiet, offline OSS
mode.
Metrics and version checks are disabled, generated `nosem` suppressions are
ignored, and target, rule, memory, process, wall time, and output bounds are
explicit. Semgrep's deterministic path-based rule-ID rewriting is enabled so
short IDs duplicated across different source files remain distinct.

The stored evidence retains only rule ID, severity, start line, and subcategory.
The parser strictly validates every field used by the metric while ignoring
unrelated optional Semgrep fields. `finding_count` includes `vuln` and
`secure default` findings across the stable severity labels and excludes
`EXPERIMENT`, `INVENTORY`, and all `audit` findings.

Semgrep is the only scanner in this contract. Bandit and CodeQL can be added
later as separately named evidence and metrics rather than silently changing
`finding_count`. The harness does not use Docker Scout or a custom Semgrep image.

### Contract version

The evaluation contract is `0.1.0`, taken from `project.version` in
`pyproject.toml`. Inspect records it as the task version, and both stored records
reject a different version rather than applying a compatibility fallback.

## Security Boundary

- Model-controlled Codex processes run as UID/GID 65532 in a fresh, networkless
  generation container with no host mounts, Docker socket, ports, devices, or
  provider credentials. The root filesystem is read-only, writable paths are
  bounded tmpfs mounts, capabilities are minimized, and resources are limited.
- A fixed exporter accepts only a stable regular `/workspace/solution.py` of at
  most 64 KiB in strict UTF-8. The host parses that text but never imports or
  executes it.
- Semgrep runs in a separate named Inspect service as UID/GID 1000. It has no
  network, capabilities, Docker socket, ports, devices, secrets, or writable root
  filesystem. Its only host mount is the pinned Python rules directory,
  read-only.
  Inspect writes source into a bounded container-only tmpfs before invoking
  Semgrep with a structured argument array; the source is not a host bind mount.
- Inspect owns creation and cleanup of both services. The scorer performs no
  Docker lifecycle or host subprocess work and can replay entirely from stored
  evidence.
- Ordinary containers still share the host kernel. The pinned public benchmark
  is the supported input. Run modified, private, or deliberately adversarial
  parser-exploit inputs in a disposable VM.

After an interrupted run, clean up only the exact environment ID reported by
Inspect:

```bash
uv run --locked inspect sandbox cleanup docker INSPECT_ENVIRONMENT_ID
```

Never omit the ID; unscoped cleanup can remove unrelated Inspect environments.

## Validation

Run non-live checks:

```bash
uv lock --check
uv run --locked pytest
uv run --locked python -m compileall -q codeguard_evals
uv run --locked inspect list tasks codeguard_evals/securityeval
docker compose --file sandbox/compose.yaml config --quiet
```

Audit the locked Python dependency graph with network access:

```bash
uv export --locked --all-groups --format requirements-txt --no-emit-project | \
  uvx pip-audit --requirement /dev/stdin --require-hashes --disable-pip \
  --progress-spinner off
```

The dedicated live test is excluded by default:

```bash
uv run --locked python -m codeguard_evals.prefetch
uv run --locked pytest -m docker --basetemp=logs/pytest-docker
```

It exercises the real named Semgrep service, a known positive finding, a clean
scanner result, Inspect's bridge turn limit, non-execution of generated source,
and Compose cleanup. Pytest recreates the ignored `logs/pytest-docker` directory
at the start of each run, so treat that directory as disposable and do not store
other artifacts in it. No manual cleanup is required. Real-provider smoke testing
remains a manual release gate.
