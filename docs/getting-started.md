# Getting Started

The CodeGuard skill is maintained in [`skills/codeguard/`](https://github.com/cosai-oasis/project-codeguard/tree/main/skills/codeguard). This folder contains the skill definition and its supporting guidance. Use the complete folder when installing CodeGuard; no conversion step is required.

## Project CodeGuard Introduction Video

[This video](https://www.youtube.com/watch?v=O03MDxUWjsE) introduces Project CodeGuard and includes several demos on how to use it during code generation and code review with Claude Code, Codex, and other coding agents.

<div style="position: relative; width: 100%; padding-bottom: 56.25%; margin: 2em 0; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.2);">
  <iframe style="position: absolute; top: 0; left: 0; width: 100%; height: 100%;" src="https://www.youtube.com/embed/O03MDxUWjsE" title="Project CodeGuard Introduction Video and Demos" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>
</div>

## Choose an install path

For individual use, install a released version in your personal skill directory. This makes CodeGuard available across your projects. A project-level installation is useful when a team wants to track the skill with a particular repository.

## Install for yourself

1. Open the [latest release](https://github.com/cosai-oasis/project-codeguard/releases/latest), download **Source code (zip)**, and extract it.
2. Locate `skills/codeguard/` inside the extracted directory and copy the complete folder to your client's personal skill location:

   | Client | Personal skill location |
   |---|---|
   | Claude Code | `~/.claude/skills/codeguard/` |
   | Codex | `~/.agents/skills/codeguard/` |

3. Start a new client session and ask the agent to use CodeGuard for a coding or review task.

These paths apply to local client sessions; `~` means your home directory. For other clients, use their supported Agent Skills location.

If CodeGuard is already installed, preserve the previous copy and replace the complete folder rather than merging versions.

## Install for a project

Use the same released `skills/codeguard/` folder, but copy it into the target repository:

| Client | Project skill location |
|---|---|
| Claude Code | `.claude/skills/codeguard/` |
| Codex | `.agents/skills/codeguard/` |

These paths are relative to the target repository's root. Include the installed files in version control so the team can review updates with the project.

## Plugin installation

The [Claude Code plugin](claude-code-skill-plugin.md) and [Codex plugin](codex-skill-plugin.md) provide another installation option. Use one installation route per client to avoid competing copies of CodeGuard.

## Skill release archive

The release workflow packages the primary skill as `codeguard-skill.zip` and publishes its checksum in `SHA256SUMS`. For a release that includes these assets, download both files from that release into a new directory. The following command verifies the checksum before extracting the archive.

```bash
shasum -a 256 -c SHA256SUMS && unzip codeguard-skill.zip
```

The archive contains `codeguard/` and `LICENSE.md`. Install the complete `codeguard/` folder at your chosen skill location.

## CodeGuard guidance

The [skill definition](https://github.com/cosai-oasis/project-codeguard/blob/main/skills/codeguard/SKILL.md) describes CodeGuard's instructions and supporting guidance. CodeGuard is advisory; its availability or use does not establish that generated code is correct or secure.

## Additional workflows

The repository also contains the [security-review and memory-safe-migration workflows](skills.md) in `sources/skills/`. The Claude Code plugin registers both workflows, and their source folders are available for other integrations.

## Previous native integrations

Native rule bundles and the MCP server remain available in the [v1.5.0 release and source](https://github.com/cosai-oasis/project-codeguard/releases/tag/v1.5.0). Follow the [tagged installation guide](https://github.com/cosai-oasis/project-codeguard/blob/v1.5.0/docs/getting-started.md) for those assets. Existing `security-review` users should update their installed copy so its core-guidance links point to `skills/codeguard/references/`.

## Getting Help

Start with the [FAQ](faq.md) for common questions. You can also [report a bug or ask a question](https://github.com/cosai-oasis/project-codeguard/issues), or [join the community discussion](https://github.com/cosai-oasis/project-codeguard/discussions).
