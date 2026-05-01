"""Emit per-host agent bundles from ``sources/agents/<name>/AGENT.md``.

For each agent and each host in ``AGENT_HOSTS``, write
``<out>/<host>/agents/<agent>.md`` with frontmatter merged from the portable
AGENT.md and the host's ``fm`` additions, and with ``{RULES_DIR}`` /
``{RULE_EXT}`` substituted in the body. Rule bodies are not copied — the
agent reads them from ``rules_dir``, which the converter's per-host format
already populated.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from artifact_targets import AGENT_HOSTS, AgentHost
from utils import parse_frontmatter_and_content

_PLACEHOLDERS = ("{RULES_DIR}", "{RULE_EXT}")


def _parse_agent_md(path: Path) -> tuple[dict[str, object], str]:
    """Read AGENT.md and return (frontmatter, body); raise on authoring errors."""
    text = (
        path.read_text(encoding="utf-8")
        .replace("\r\n", "\n")
        .replace("\r", "\n")
    )
    frontmatter, body = parse_frontmatter_and_content(text)
    if not isinstance(frontmatter, dict):
        raise ValueError(f"{path}: missing or non-mapping YAML frontmatter")
    for required in ("name", "description"):
        if required not in frontmatter:
            raise ValueError(f"{path}: frontmatter missing required key '{required}'")
    missing = [p for p in _PLACEHOLDERS if p not in body]
    if missing:
        raise ValueError(
            f"{path}: body must reference {', '.join(missing)} so per-host "
            f"paths can be substituted"
        )
    return frontmatter, body


def _merge_frontmatter(
    portable: dict[str, object], additions: dict[str, object], agent: str, host: str
) -> dict[str, object]:
    """Combine portable + host frontmatter; raise on key collision."""
    overlap = sorted(set(portable) & set(additions))
    if overlap:
        raise ValueError(
            f"agent '{agent}' frontmatter collides with host '{host}' on {overlap}; "
            f"AGENT.md must not set host-specific keys"
        )
    return {**portable, **additions}


def _emit_one(
    *,
    agent_name: str,
    portable_fm: dict[str, object],
    body: str,
    host_dir: str,
    host_cfg: AgentHost,
    output_base: Path,
) -> None:
    rules_dir = output_base / host_cfg["rules_dir"]
    if not rules_dir.exists():
        raise FileNotFoundError(
            f"host '{host_dir}' rules_dir {rules_dir} does not exist; the "
            f"converter must emit it before emit_agents runs"
        )

    merged_fm = _merge_frontmatter(portable_fm, host_cfg["fm"], agent_name, host_dir)
    host_body = body.replace("{RULES_DIR}", host_cfg["rules_dir"]).replace(
        "{RULE_EXT}", host_cfg["rule_ext"]
    )

    agent_md = output_base / host_dir / "agents" / f"{agent_name}.md"
    agent_md.parent.mkdir(parents=True, exist_ok=True)
    fm_yaml = yaml.safe_dump(merged_fm, sort_keys=False, allow_unicode=True).rstrip()
    agent_md.write_text(f"---\n{fm_yaml}\n---\n{host_body}", encoding="utf-8")

    print(f"Emitted agent '{agent_name}' -> {agent_md}")


def emit_agents(
    *,
    agents_source_dir: Path,
    output_dir: Path,
    hosts: dict[str, AgentHost] | None = None,
) -> None:
    """Emit every agent under ``agents_source_dir`` to every host in ``hosts``.

    Must run after the converter has populated each host's ``rules_dir``.
    """
    if not agents_source_dir.exists():
        return
    if hosts is None:
        hosts = AGENT_HOSTS

    for agent_dir in sorted(p for p in agents_source_dir.iterdir() if p.is_dir()):
        agent_md_src = agent_dir / "AGENT.md"
        if not agent_md_src.exists():
            raise ValueError(f"{agent_dir}: missing AGENT.md")
        portable_fm, body = _parse_agent_md(agent_md_src)
        for host_dir, host_cfg in hosts.items():
            _emit_one(
                agent_name=agent_dir.name,
                portable_fm=portable_fm,
                body=body,
                host_dir=host_dir,
                host_cfg=host_cfg,
                output_base=output_dir,
            )
