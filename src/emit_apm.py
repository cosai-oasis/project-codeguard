"""Emit APM package skill primitive under ``.apm/`` and sync ``apm.yml``.

Runs after core rule conversion so the Agent Skills bundle exists. The APM
package ships the CodeGuard Agent Skill only — instructions and reviewer
agents remain available through other install paths (ZIP releases, MCP).
"""

from __future__ import annotations

import shutil
from pathlib import Path

import yaml

_APM_SKILL_REL = Path('.apm/skills/codeguard')
_APM_YML = Path('apm.yml')
_STALE_APM_DIRS = (
    Path('.apm/instructions'),
    Path('.apm/agents'),
)


def _remove_stale_apm_artifacts(*, output_root: Path) -> None:
    """Remove legacy APM primitives no longer shipped in the skill-only package."""
    for stale_dir in _STALE_APM_DIRS:
        stale_path = output_root / stale_dir
        if stale_path.exists():
            shutil.rmtree(stale_path)
            print(f'Removed stale APM path -> {stale_path}')


def _copy_apm_skill(*, skill_source: Path, output_root: Path) -> None:
    """Copy generated Agent Skills bundle into ``.apm/skills/codeguard/``."""
    if not skill_source.is_dir():
        raise FileNotFoundError(
            f'Skill directory not found at {skill_source}; '
            'run core conversion before emit_apm'
        )

    skill_dest = output_root / _APM_SKILL_REL
    if skill_dest.exists():
        shutil.rmtree(skill_dest)

    shutil.copytree(skill_source, skill_dest)
    print(f'Copied skill bundle -> {skill_dest}')


def sync_apm_yml(*, version: str, output_root: Path) -> None:
    """Write or update root ``apm.yml`` with the current package version."""
    apm_path = output_root / _APM_YML
    description = (
        'CoSAI CodeGuard Agent Skill for AI coding agents. '
        'Install with: apm install cosai-oasis/project-codeguard'
    )

    if apm_path.exists():
        with apm_path.open(encoding='utf-8') as handle:
            manifest = yaml.safe_load(handle) or {}
    else:
        manifest = {}

    manifest['name'] = 'project-codeguard'
    manifest['version'] = version
    manifest['description'] = description
    manifest['author'] = 'cosai-oasis'
    manifest['license'] = 'CC-BY-4.0'
    manifest.setdefault('dependencies', {})
    manifest['dependencies'].setdefault('apm', [])
    manifest['dependencies'].setdefault('mcp', [])

    apm_path.write_text(
        yaml.safe_dump(manifest, sort_keys=False, allow_unicode=True),
        encoding='utf-8',
    )
    print(f'Synced apm.yml to version {version}')


def emit_apm(
    *,
    project_root: Path,
    version: str,
    skill_source_dir: Path | None = None,
) -> None:
    """Emit the APM skill package layout at the project root.

    Args:
        project_root: Repository root.
        version: Package version string.
        skill_source_dir: Generated ``skills/codeguard`` directory.
    """
    if skill_source_dir is None:
        skill_source_dir = project_root / 'skills' / 'codeguard'

    _remove_stale_apm_artifacts(output_root=project_root)
    _copy_apm_skill(skill_source=skill_source_dir, output_root=project_root)
    sync_apm_yml(version=version, output_root=project_root)
