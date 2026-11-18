# Contributing

Project CodeGuard is part of the [Coalition for Secure AI (CoSAI)](https://www.coalitionforsecureai.org/), an [OASIS Open Project](https://www.oasis-open.org/open-projects/). It supports the [WS3 Security of AI-Assisted Code Development SIG](https://github.com/cosai-oasis/ws3-ai-risk-governance/blob/main/SIG-Security-AI-Assisted-Code-Development/Scope-and-Deliverables.md).

The repository-specific instructions below supplement the [CoSAI Governance](https://github.com/cosai-oasis/oasis-open-project/blob/main/GOVERNANCE.md), [TSC and Workstream Governance](https://github.com/cosai-oasis/oasis-open-project/blob/main/TSC-WS-GOVERNANCE.md), [OASIS Participants Code of Conduct](https://www.oasis-open.org/policies-guidelines/oasis-participants-code-of-conduct/), and [CoSAI AI Usage Guidelines](https://github.com/cosai-oasis/oasis-open-project/blob/main/AI-USAGE-GUIDELINES.md).

New to CoSAI? Visit [Get Involved](https://www.coalitionforsecureai.org/get-involved/) and see the [CoSAI onboarding guide](https://github.com/cosai-oasis/oasis-open-project/blob/main/ONBOARDING.md) for information about workstreams, communication channels, meetings, and contributor agreements.

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

Commit messages should be concise and descriptive. This repository commonly uses conventional-style subjects for automation and maintenance work, for example `docs: Update contributing guide`, `fix: Correct security guidance`, or `chore: Update release workflow`. A strict commit-message format is not required, but avoid vague messages such as `update` or `fix stuff`.

Keep your branch current with `main` before review or merge. Rebasing is fine for your fork branch, but do not rewrite shared branches owned by other contributors.

## Authored skills and reference material

CodeGuard's primary skill is authored in `skills/codeguard/`. Changes to its security guidance belong in that folder because the release workflow packages these files directly, without a conversion or regeneration step.

Keep guidance changes consistent with the rest of the skill and update any affected references or documentation. Preserve source attribution and explain the intended security benefit so reviewers can assess the change.

The repository keeps optional workflows and supporting tooling separate from the primary skill. Use the following locations to find the files relevant to your contribution.

| Location | Contents |
|---|---|
| `skills/codeguard/` | The primary skill definition and its supporting guidance. |
| `sources/skills/` | The security-review and memory-safe-migration workflows and their supporting files. |
| `sources/rules/owasp/` | Supplementary references used by security-review. |
| `src/` | The version validation script. |
| `docs/`, `mkdocs.yml`, and top-level Markdown files | Project documentation and site configuration. |
| `.github/workflows/` and `.github/ISSUE_TEMPLATE/` | CI workflows and issue templates. |

Maintain detailed guidance in `skills/codeguard/references/<topic>.md` and link each topic from `skills/codeguard/SKILL.md` with the conditions for reading it. Use relative links between reference files. Keep `metadata.codeguard-version` in the skill aligned with the project and plugin versions when preparing a release.

## Validation

Before submitting changes to CodeGuard, version metadata, packaging, or documentation, run the following commands from the repository root. They check version consistency and build the documentation with strict validation.

```bash
uv sync --locked
uv run --locked python src/validate_versions.py "$(uv version --short)"
uv run --locked mkdocs build --strict
```

The `Validate Skills` workflow runs these version and documentation checks in CI. When a release is published, a separate workflow packages the tagged CodeGuard skill and license as `codeguard-skill.zip` and creates its `SHA256SUMS` file. The `security-review` and `memory-safe-migration` skills are still included in the Claude Code plugin. Their files remain in `sources/skills/`.

Changes to an auxiliary skill should also be checked against its referenced files and any affected scripts. Changes to the evaluation harness follow its own [validation instructions](evaluations/codeguard-inspect/README.md) and CI workflow.

The `Deploy Documentation` workflow deploys the site from `main` when documentation paths change.

## AI-assisted contributions

AI-assisted contributions must follow the [CoSAI AI Usage Guidelines](https://github.com/cosai-oasis/oasis-open-project/blob/main/AI-USAGE-GUIDELINES.md).

## Code review process

Routine pull requests are reviewed by the Project CodeGuard maintainers. Maintainers may request changes for correctness, security impact, generated artifact freshness, documentation clarity, or validation coverage.

CoSAI uses [lazy consensus](https://openoffice.apache.org/docs/governance/lazyConsensus.html) where possible, consistent with the [TSC and Workstream Governance](https://github.com/cosai-oasis/oasis-open-project/blob/main/TSC-WS-GOVERNANCE.md).

For major changes, follow the notice and review process in the [CoSAI TSC and Workstream Governance](https://github.com/cosai-oasis/oasis-open-project/blob/main/TSC-WS-GOVERNANCE.md#decision-making).

## Signing the eCLA/iCLA

Anyone can make a pull request and commit. In order for your work to be merged, you will need to sign the iCLA (individual contributor agreement) if you are just contributing for yourself. If you are contributing on behalf of your company, you will also need to sign the eCLA (entity contributor agreement). [Learn more about the CLAs here](https://www.oasis-open.org/open-projects/cla/).

You can sign the iCLA through [CoSAI's CLA Assistant](https://cla-assistant.io/cosai-oasis/oasis-open-project). The bot will also comment on your pull request and direct you to sign if you have not previously done so.

## Feedback

Questions or comments about this project's work may be composed as [GitHub issues](https://github.com/cosai-oasis/project-codeguard/issues) or comments. Current mailing-list and Slack information for WS3 discussions is available in the [WS3 support guidance](https://github.com/cosai-oasis/ws3-ai-risk-governance#support).
