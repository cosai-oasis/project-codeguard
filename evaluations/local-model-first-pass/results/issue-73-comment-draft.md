First pass completed locally with **Qwen2.5-Coder 7B (Q4_K_M)** on Ollama 0.35.1,
Apple M4 Pro / 24 GiB RAM / macOS 27.0.1. Model digest:
`dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364`.

I ran one small SQLite generation task and one review task, each with a baseline
and an explicit flattened subset of CodeGuard v1.5.0 injection/authorization
guidance. Requested and observed context limits were **8,192 and 4,096 tokens**;
temperature 0, seed 73, output cap 1,024, fresh conversations. Eight responses
total, one per task/condition/context. Capture harness revision:
`32d9fe4649701f5e06b4b3c7c71c36a8bab97e76`.

**What worked:** all requests completed normally. Generation used bound SQL
parameters and scoped the lookup to the authenticated owner in both conditions.
Review found both SQL injection and cross-user access in both conditions.
Guided responses accurately cited `codeguard-0-input-validation-injection` and
`codeguard-0-authorization-access-control`, connecting them to choices/findings.

**What failed:** every generated function used `isinstance(value, int)` and
missed the task's explicit boolean rejection requirement. Baselines invented
rule IDs despite receiving no guidance; guided reviews quoted the right source
line but omitted requested numeric line references. Generated code was inspected
and parsed, never executed.

**Context and latency:** each task/condition output was byte-identical at 4K and
8K. Prompts were 253–1,020 tokens; outputs were 449–613. Wall times were
9.80–17.07 seconds, including an initial 3.71-second model load and a 2.16-second
context reload. Cache reuse and response length prevent a useful speed comparison.
The small prompts do not demonstrate behavior under severe context pressure.

**Next:** repeat with an explicit Python boolean/type-validation example, then
increase task size toward the 4K limit. This first pass shows accurate guided
attribution, but no observed SQL/ownership improvement over the baseline. It
does not test full-skill activation, MCP, or the reviewer integration, and cannot
establish a causal benefit or compare delivery paths.

Assisted-by: AI Assistant (OpenAI Codex) for experiment tooling and assessment;
Qwen2.5-Coder for experimental outputs.

<!-- Draft only: human contributor must review the results and confirm the right
to donate the material before submission under CoSAI's AI Usage Guidelines. -->
