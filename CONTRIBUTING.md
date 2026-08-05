# Contributing

Project CodeGuard is part of the [Coalition for Secure AI (CoSAI)](https://www.coalitionforsecureai.org/), an [OASIS Open Project](https://www.oasis-open.org/open-projects/). It supports the [WS3 Security of AI-Assisted Code Development SIG](https://github.com/cosai-oasis/ws3-ai-risk-governance/blob/main/SIG-Security-AI-Assisted-Code-Development/Scope-and-Deliverables.md).

The repository-specific instructions below supplement the [CoSAI Governance](https://github.com/cosai-oasis/oasis-open-project/blob/main/GOVERNANCE.md), [TSC and Workstream Governance](https://github.com/cosai-oasis/oasis-open-project/blob/main/TSC-WS-GOVERNANCE.md), [OASIS Participants Code of Conduct](https://www.oasis-open.org/policies-guidelines/oasis-participants-code-of-conduct/), and [CoSAI AI Usage Guidelines](https://github.com/cosai-oasis/oasis-open-project/blob/main/AI-USAGE-GUIDELINES.md).

New to CoSAI? Visit [Get Involved](https://www.coalitionforsecureai.org/get-involved/) and see the [CoSAI onboarding guide](https://github.com/cosai-oasis/oasis-open-project/blob/main/ONBOARDING.md) for information about workstreams, communication channels, meetings, and contributor agreements.

In general, a CoSAI Contributor is expected to:

* be knowledgeable in one or more fields related to the project
* contribute to developing and finalizing workstream deliverables
* be reliable in completing issues to which they have been assigned
* show commitment over time with one or more PRs merged
* follow the project style and testing guidelines
* follow branch, PR, and code style conventions
* contribute in ways that substantially improve the quality of the project and the experience of people who use it

Please note this project follows the [OASIS Participants Code of Conduct](https://www.oasis-open.org/policies-guidelines/oasis-participants-code-of-conduct/); please be respectful of differing opinions when discussing potential contributions.

## Finding or proposing work

When contributing to Project CodeGuard, please first create or find a GitHub issue and discuss the proposed change there.

Use the current Project CodeGuard repository channels:

* Browse [open issues](https://github.com/cosai-oasis/project-codeguard/issues) for existing work.
* Look for issues labeled [`good first issue`](https://github.com/cosai-oasis/project-codeguard/labels/good%20first%20issue) if you are new to the project.
* Use the [New Rule Request template](https://github.com/cosai-oasis/project-codeguard/issues/new?template=new-rule.yml) to propose a new CodeGuard rule.
* Use the [Rule Feedback template](https://github.com/cosai-oasis/project-codeguard/issues/new?template=rule-feedback.yml) to report rule problems, suggest improvements, or share feedback from an AI coding tool.
* Open a regular [new issue](https://github.com/cosai-oasis/project-codeguard/issues/new/choose) if the available templates do not fit.

If you want to work on an issue, comment on the issue and ask a maintainer to assign it to you. Contributors without repository write access cannot assign themselves. Wait for maintainer confirmation before doing substantial work, especially for larger rule, architecture, or governance-related changes.

## Submitting a pull request

Follow these steps when submitting a pull request:

1. Fork this repository into your GitHub account. Read more about [forking a repository on GitHub](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/fork-a-repo).
2. Create a branch in your fork from the latest `main` branch. Use a short descriptive branch name, such as `fix-rule-frontmatter`, `add-logging-rule-guidance`, or `docs-install-paths`.
3. Make the smallest complete change that addresses the issue or proposal.
4. Run the applicable validation listed below.
5. Push your branch to your fork and open a pull request against `cosai-oasis/project-codeguard:main`.
6. Link the issue your PR addresses, describe what changed, and list the validation you ran.

Commit messages should be concise and descriptive. This repository commonly uses conventional-style subjects for automation and maintenance work, for example `docs: Update contributing guide`, `fix: Validate rule metadata`, or `chore: Update CodeGuard rules to v1.4.0`. A strict commit-message format is not required, but avoid vague messages such as `update` or `fix stuff`.

Keep your branch current with `main` before review or merge. Rebasing is fine for your fork branch, but do not rewrite shared branches owned by other contributors.

## Authored sources and generated artifacts

Most contributions should edit authored sources, not generated bundles.

Authored files include:

* `sources/rules/core/` - core CodeGuard rule sources distributed in standard bundles.
* `sources/rules/owasp/` - supplementary OWASP-based rule sources used for deeper review and optional conversion.
* `sources/skills/` - authored skill workflows and their reference material.
* `sources/agents/` - authored CodeGuard reviewer agent source.
* `src/` - Python converters, validators, format emitters, and related tooling.
* `src/codeguard-mcp/` - the CodeGuard MCP server package and tests.
* `docs/`, `mkdocs.yml`, and top-level Markdown files - documentation.
* `.github/workflows/` and `.github/ISSUE_TEMPLATE/` - CI and contribution-channel configuration.

Generated or derived files include:

* `skills/codeguard/` - committed generated Agent Skill output for the core rules. Do not edit this directory by hand. If you change core rules, the skill template, converter behavior, or metadata that affects the generated skill, regenerate it with `uv run python src/convert_to_ide_formats.py` and commit the resulting `skills/codeguard/` changes.
* `dist/` - generated release bundle output for IDE and agent formats. This directory is ignored and should not be committed.
* `test-output/` - local conversion-validation output. This directory is ignored and should not be committed.
* Release ZIP archives such as `codeguard-cursor.zip`, `codeguard-claude.zip`, and `codeguard-all.zip` - built by release automation, not by normal PRs.

The conversion script reads `sources/rules/` and emits IDE-specific rule formats for Cursor, Windsurf, GitHub Copilot, Antigravity, OpenCode, Codex, OpenClaw, Hermes, and Claude. The default conversion source is `sources/rules/core/`; use `--source core owasp` when validating core and OWASP conversion together.

## Validation

Run the validation that matches the files you changed. The commands below include current GitHub Actions checks and recommended local checks.

For rule sources, converters, skill generation, or agent emission:

```bash
uv sync
uv run python src/validate_unified_rules.py sources/
uv run python src/convert_to_ide_formats.py
uv run python src/convert_to_ide_formats.py --output-dir test-output
uv run python src/convert_to_ide_formats.py --source core owasp --output-dir /tmp/validate-all-output
```

After running the default conversion, check whether `skills/codeguard/` changed. Commit those changes when they are expected. Do not commit `dist/` or `test-output/`.

For release-version or release-bundle changes, run from the repository root:

```bash
uv sync
uv run python src/validate_unified_rules.py sources/
uv run python src/convert_to_ide_formats.py
uv run python src/validate_versions.py <release-version>
```

The conversion step synchronizes generated skill and plugin metadata before the final version check. The `Build and Release IDE Bundles` workflow reruns these checks when a release is published, then creates and uploads the release ZIP assets.

For documentation changes under `docs/` or `mkdocs.yml`:

```bash
uv sync
uv run mkdocs build --strict
```

The `Deploy Documentation` workflow deploys the site from `main` when documentation paths change.

For CodeGuard MCP server changes under `src/codeguard-mcp/`:

```bash
uv sync
uv run pytest
```

Run those commands from `src/codeguard-mcp/`. The MCP server has its own `pyproject.toml`, dependency group, and tests. These tests are recommended local validation and are not currently a separate CI gate.

For top-level Python tooling changes under `src/`, also run the rule and conversion validation commands above because the `Validate Rules` workflow is the current CI gate for that tooling.

## AI-assisted contributions

AI-assisted contributions must follow the [CoSAI AI Usage Guidelines](https://github.com/cosai-oasis/oasis-open-project/blob/main/AI-USAGE-GUIDELINES.md).

## Code review process

Routine pull requests are reviewed by the Project CodeGuard maintainers. Maintainers may request changes for correctness, security impact, generated artifact freshness, documentation clarity, or validation coverage.

The project aims to review pull requests in a timely manner, with timing based on the scope and complexity of each change. Reviewers and contributors should keep discussions moving by responding to feedback and clearly identifying any blockers, decisions, or information needed for the pull request to proceed.

CoSAI uses [lazy consensus](https://openoffice.apache.org/docs/governance/lazyConsensus.html) where possible, consistent with the [TSC and Workstream Governance](https://github.com/cosai-oasis/oasis-open-project/blob/main/TSC-WS-GOVERNANCE.md).

Use routine PR review for ordinary fixes, documentation improvements, rule refinements, tests, and generated-artifact updates.

For major changes, follow the notice and review process in the [CoSAI TSC and Workstream Governance](https://github.com/cosai-oasis/oasis-open-project/blob/main/TSC-WS-GOVERNANCE.md#decision-making).

## Signing the eCLA/iCLA

Anyone can make a pull request and commit. In order for your work to be merged, you will need to sign the iCLA (individual contributor agreement) if you are just contributing for yourself. If you are contributing on behalf of your company, you will also need to sign the eCLA (entity contributor agreement). [Learn more about the CLAs here](https://www.oasis-open.org/open-projects/cla/).

You can sign the iCLA through [CoSAI's CLA Assistant](https://cla-assistant.io/cosai-oasis/oasis-open-project). The bot will also comment on your pull request and direct you to sign if you have not previously done so.

## Feedback

Questions or comments about this project's work may be composed as [GitHub issues](https://github.com/cosai-oasis/project-codeguard/issues) or comments. Current mailing-list and Slack information for WS3 discussions is available in the [WS3 support guidance](https://github.com/cosai-oasis/ws3-ai-risk-governance#support).
