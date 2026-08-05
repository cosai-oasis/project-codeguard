"""Emit APM package primitives under ``.apm/`` and sync ``apm.yml``.

Runs after core rule conversion so skill rules and instructions exist.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import yaml

from utils import parse_frontmatter_and_content

_APM_AGENT_RULES_DIR = ".agents/skills/codeguard/rules"
_APM_AGENT_RULE_EXT = ".md"
_APM_RULE_SEARCH_PATHS = (
    ".agents/skills/codeguard/rules",
    ".apm/skills/codeguard/rules",
    "skills/codeguard/rules",
)
_APM_EXCLUDE_PATHS = (
    ".agents/skills/codeguard/rules/",
    ".apm/",
    "skills/codeguard/rules/",
    ".claude/",
    ".cursor/",
    ".codex/",
    ".opencode/",
    ".windsurf/",
    ".github/instructions/",
    ".github/agents/",
    ".openclaw/",
    ".hermes/",
)
_APM_SKILL_REL = Path(".apm/skills/codeguard")
_APM_AGENTS_DIR = Path(".apm/agents")
_APM_YML = Path("apm.yml")


def _render_apm_agent_body(body: str) -> str:
    """Adapt the portable agent for APM multi-path rule discovery."""
    list_step = (
        "2. Resolve the active rules directory by checking, in order: "
        f"{', '.join(f'`{path}/`' for path in _APM_RULE_SEARCH_PATHS)}. "
        f"List all rule files matching `codeguard-*{_APM_AGENT_RULE_EXT}` "
        "in the first directory that exists. The rule\n   ID is the filename "
        "without the extension."
    )
    rendered = body.replace(
        "2. List all rule files matching `{RULES_DIR}/codeguard-*{RULE_EXT}`. "
        "The rule\n   ID is the filename without the extension.",
        list_step,
    )

    references = (
        "The CodeGuard rule files are `codeguard-*.md` under the first "
        "directory that exists and contains matches:\n"
        "- `.agents/skills/codeguard/rules/` (default after `apm install`)\n"
        "- `.apm/skills/codeguard/rules/` (APM package layout)\n"
        "- `skills/codeguard/rules/` (generated build output)"
    )
    rendered = rendered.replace(
        "The CodeGuard rule files live at `{RULES_DIR}/codeguard-*{RULE_EXT}` "
        "(one per rule).",
        references,
    )

    exclude_block = (
        "   - CodeGuard rule and package trees: "
        f"{', '.join(f'`{path}`' for path in _APM_EXCLUDE_PATHS)}. "
        "These contain CodeGuard-generated rules or agents (with example "
        "secrets and banned-API snippets) and must never be reported as "
        "findings."
    )
    old_exclude_start = (
        "   - Your own rule directory `{RULES_DIR}/` and any CodeGuard host\n"
        "     directories (`.claude/`, `.cursor/`, `.codex/`, `.opencode/`,\n"
        "     `.agents/`, `.windsurf/`, `.github/instructions/`, "
        "`.github/agents/`,\n     `.openclaw/`, `.hermes/`). These contain "
        "CodeGuard-generated rules or\n     agents (with example secrets and "
        "banned-API snippets) and must never be\n     reported as findings."
    )
    rendered = rendered.replace(old_exclude_start, exclude_block)

    missing_rules = (
        "If none of the rule directories above exist or all are empty, "
        "stop and report that the CodeGuard rule bundle is not installed. "
        "Do not fabricate rule content."
    )
    rendered = rendered.replace(
        "If `{RULES_DIR}/` is missing or empty, stop and report that the "
        "CodeGuard\n  rule bundle is not installed. Do not fabricate rule "
        "content.",
        missing_rules,
    )

    rendered = rendered.replace("{RULES_DIR}", _APM_AGENT_RULES_DIR)
    rendered = rendered.replace("{RULE_EXT}", _APM_AGENT_RULE_EXT)
    return rendered


def _write_apm_agent(*, agents_source: Path, output_root: Path) -> None:
    """Write ``codeguard-reviewer.agent.md`` for APM package distribution."""
    agent_src = agents_source / "codeguard-reviewer" / "AGENT.md"
    if not agent_src.exists():
        raise FileNotFoundError(f"Missing reviewer agent source: {agent_src}")

    frontmatter, body = parse_frontmatter_and_content(
        agent_src.read_text(encoding="utf-8")
    )
    if not isinstance(frontmatter, dict):
        raise ValueError(f"{agent_src}: missing YAML frontmatter")

    agent_body = _render_apm_agent_body(body)
    agent_dir = output_root / _APM_AGENTS_DIR
    agent_dir.mkdir(parents=True, exist_ok=True)
    agent_path = agent_dir / "codeguard-reviewer.agent.md"

    fm_yaml = yaml.safe_dump(frontmatter, sort_keys=False, allow_unicode=True)
    fm_yaml = fm_yaml.rstrip()
    agent_path.write_text(
        f"---\n{fm_yaml}\n---\n{agent_body}",
        encoding="utf-8",
    )
    print(f"Emitted APM agent -> {agent_path}")


def _copy_apm_skill(*, skill_source: Path, output_root: Path) -> None:
    """Copy generated Agent Skills bundle into ``.apm/skills/codeguard/``."""
    if not skill_source.is_dir():
        raise FileNotFoundError(
            f"Skill directory not found at {skill_source}; "
            "run core conversion before emit_apm"
        )

    skill_dest = output_root / _APM_SKILL_REL
    if skill_dest.exists():
        shutil.rmtree(skill_dest)

    shutil.copytree(skill_source, skill_dest)
    print(f"Copied skill bundle -> {skill_dest}")


def sync_apm_yml(*, version: str, output_root: Path) -> None:
    """Write or update root ``apm.yml`` with the current package version."""
    apm_path = output_root / _APM_YML
    description = (
        "CoSAI CodeGuard security rules and skills for AI coding agents. "
        "Install with: apm install cosai-oasis/project-codeguard"
    )

    if apm_path.exists():
        with apm_path.open(encoding="utf-8") as handle:
            manifest = yaml.safe_load(handle) or {}
    else:
        manifest = {}

    manifest["name"] = "project-codeguard"
    manifest["version"] = version
    manifest["description"] = description
    manifest["author"] = "cosai-oasis"
    manifest["license"] = "CC-BY-4.0"
    manifest.setdefault("dependencies", {})
    manifest["dependencies"].setdefault("apm", [])
    manifest["dependencies"].setdefault("mcp", [])

    apm_path.write_text(
        yaml.safe_dump(manifest, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    print(f"Synced apm.yml to version {version}")


def emit_apm(
    *,
    project_root: Path,
    version: str,
    agents_source_dir: Path | None = None,
    skill_source_dir: Path | None = None,
) -> None:
    """Emit the APM package layout at the project root.

    Args:
        project_root: Repository root.
        version: Package version string.
        agents_source_dir: Directory containing agent AGENT.md sources.
        skill_source_dir: Generated ``skills/codeguard`` directory.
    """
    if agents_source_dir is None:
        agents_source_dir = project_root / "sources" / "agents"
    if skill_source_dir is None:
        skill_source_dir = project_root / "skills" / "codeguard"

    _copy_apm_skill(skill_source=skill_source_dir, output_root=project_root)
    _write_apm_agent(agents_source=agents_source_dir, output_root=project_root)
    sync_apm_yml(version=version, output_root=project_root)
