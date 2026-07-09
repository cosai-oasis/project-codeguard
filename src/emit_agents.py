"""Emit per-host agent bundles from ``sources/agents/<name>/AGENT.md``.

For each agent and each host in ``AGENT_HOSTS``, write
the host-specific agent file with frontmatter merged from the portable AGENT.md
and the host's ``fm`` additions, and with ``{RULES_DIR}`` / ``{RULE_EXT}``
substituted in the body. Rule bodies are not copied — the agent reads them from
``rules_dir``, which the converter's per-host format already populated.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from artifact_targets import AGENT_HOSTS, TOML_AGENT_HOSTS, AgentHost, TomlAgentHost
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
        if not isinstance(frontmatter[required], str):
            raise ValueError(f"{path}: frontmatter key '{required}' must be a string")
    missing = [p for p in _PLACEHOLDERS if p not in body]
    if missing:
        raise ValueError(
            f"{path}: body must reference {', '.join(missing)} so per-host "
            f"paths can be substituted"
        )
    return frontmatter, body


def _frontmatter_string(
    frontmatter: dict[str, object], key: str, agent: str
) -> str:
    value = frontmatter[key]
    if not isinstance(value, str):
        raise ValueError(f"agent '{agent}' frontmatter key '{key}' must be a string")
    return value


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


def _render_body(body: str, *, rules_dir: str, rule_ext: str) -> str:
    return body.replace("{RULES_DIR}", rules_dir).replace("{RULE_EXT}", rule_ext)


def _require_rules_dir(
    *, output_base: Path, host_name: str, relative_path: str
) -> None:
    rules_dir = output_base / relative_path
    if not rules_dir.is_dir():
        raise FileNotFoundError(
            f"host '{host_name}' rules_dir {rules_dir} does not exist or is not "
            f"a directory; the converter must emit it before emit_agents runs"
        )


def _emit_markdown_one(
    *,
    agent_name: str,
    portable_fm: dict[str, object],
    body: str,
    host_dir: str,
    host_cfg: AgentHost,
    output_base: Path,
) -> None:
    _require_rules_dir(
        output_base=output_base,
        host_name=host_dir,
        relative_path=host_cfg["rules_dir"],
    )

    merged_fm = _merge_frontmatter(portable_fm, host_cfg["fm"], agent_name, host_dir)
    host_body = _render_body(
        body,
        rules_dir=host_cfg["rules_dir"],
        rule_ext=host_cfg["rule_ext"],
    )

    agent_filename = host_cfg["filename"].format(agent=agent_name)
    agent_md = output_base / host_dir / "agents" / agent_filename
    agent_md.parent.mkdir(parents=True, exist_ok=True)
    fm_yaml = yaml.safe_dump(merged_fm, sort_keys=False, allow_unicode=True).rstrip()
    agent_md.write_text(f"---\n{fm_yaml}\n---\n{host_body}", encoding="utf-8")

    print(f"Emitted agent '{agent_name}' -> {agent_md}")


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _toml_multiline_literal(value: str, *, agent: str) -> str:
    if "'''" in value:
        raise ValueError(
            f"agent '{agent}' body contains TOML multiline literal terminator"
        )
    return f"'''\n{value.rstrip()}\n'''"


def _emit_toml_one(
    *,
    agent_name: str,
    portable_fm: dict[str, object],
    body: str,
    host_name: str,
    host_cfg: TomlAgentHost,
    output_base: Path,
) -> None:
    _require_rules_dir(
        output_base=output_base,
        host_name=host_name,
        relative_path=host_cfg["rules_dir"],
    )
    agent_body = _render_body(
        body,
        rules_dir=host_cfg["rules_dir"],
        rule_ext=host_cfg["rule_ext"],
    )
    agent_toml = output_base / host_cfg["output_dir"] / f"{agent_name}.toml"
    agent_toml.parent.mkdir(parents=True, exist_ok=True)
    agent_name_value = _frontmatter_string(portable_fm, "name", agent_name)
    description_value = _frontmatter_string(portable_fm, "description", agent_name)
    instructions_value = _toml_multiline_literal(agent_body, agent=agent_name)
    agent_toml.write_text(
        "\n".join(
            (
                f"name = {_toml_string(agent_name_value)}",
                f"description = {_toml_string(description_value)}",
                f"developer_instructions = {instructions_value}",
                "",
            )
        ),
        encoding="utf-8",
    )

    print(f"Emitted agent '{agent_name}' -> {agent_toml}")


def emit_agents(
    *,
    agents_source_dir: Path,
    output_dir: Path,
    hosts: dict[str, AgentHost] | None = None,
    toml_hosts: dict[str, TomlAgentHost] | None = None,
) -> None:
    """Emit every agent under ``agents_source_dir`` to every configured host.

    Must run after the converter has populated each host's ``rules_dir``.
    """
    if not agents_source_dir.exists():
        return
    if hosts is None:
        hosts = AGENT_HOSTS
    if toml_hosts is None:
        toml_hosts = TOML_AGENT_HOSTS

    for agent_dir in sorted(p for p in agents_source_dir.iterdir() if p.is_dir()):
        agent_md_src = agent_dir / "AGENT.md"
        if not agent_md_src.exists():
            raise ValueError(f"{agent_dir}: missing AGENT.md")
        portable_fm, body = _parse_agent_md(agent_md_src)
        for host_dir, host_cfg in hosts.items():
            _emit_markdown_one(
                agent_name=agent_dir.name,
                portable_fm=portable_fm,
                body=body,
                host_dir=host_dir,
                host_cfg=host_cfg,
                output_base=output_dir,
            )
        for host_name, host_cfg in toml_hosts.items():
            _emit_toml_one(
                agent_name=agent_dir.name,
                portable_fm=portable_fm,
                body=body,
                host_name=host_name,
                host_cfg=host_cfg,
                output_base=output_dir,
            )
