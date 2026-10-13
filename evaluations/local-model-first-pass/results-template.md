# Issue #73 first-pass observations

Status: NOT RUN. Replace placeholders only with recorded evidence.

## Configuration

- Run date and UTC timestamps:
- Model name, full digest/artifact hash, parameter size, and quantization:
- Model runtime and host/client version:
- OS, architecture, RAM, and accelerator:
- Repository revision and working-tree differences:
- Source rule file hashes, section headings, and assembled prompt hashes:
- Delivery path: explicit flattened subset, not implicit skill activation
- Requested context/output limits, observed context, temperature, and seed:
- Condition order, repetitions, and cold/warm state:
- Exact request/response evidence locations:

## Observations

| Task | Condition | Context requested / observed | Input / output tokens | Stop reason | Load / wall time | Manual rubric outcome |
| --- | --- | --- | --- | --- | --- | --- |
| Generation | Baseline | | | | | |
| Generation | CodeGuard subset | | | | | |
| Review | CodeGuard subset | | | | | |
| Review | Baseline | | | | | |

- Guidance delivery evidence:
- Accurate rule attribution evidence:
- Implementation or finding evidence:
- Unsupported findings, errors, truncation, and unclear outcomes:
- Differences observed at the smaller context, if tested:

## Proposed issue comment

First pass used [model/digest] with [runtime/version] through [delivery path].
I ran the same generation task and review task [conditions/repetitions] under
[requested and observed limits].

What worked: [specific observations with public evidence links].

What failed or remained unclear: [failures and limitations, including attribution
versus behavior].

Next useful test: [one bounded follow-up justified by these observations].

These are observations from one model and two small tasks. They do not establish
a causal improvement, complete security, or a comparison across delivery routes.

Assisted-by: AI Assistant. Human review: [named contributor and review completed].
