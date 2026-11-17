"""
Convert Unified Rules to IDE Formats

Transforms the unified markdown sources into IDE-specific bundles (Cursor,
Windsurf, Copilot, Agent Skills, Antigravity, OpenCode, Codex). This script is
the main entry point for producing distributable rule packs from the sources/
directory.
"""

import re
import shutil
from collections import defaultdict
from pathlib import Path

from artifact_targets import SKILL_COPY_HOSTS
from converter import RuleConverter
from emit_agents import emit_agents
from formats import (
    CursorFormat,
    WindsurfFormat,
    DevinFormat,
    CopilotFormat,
    AgentSkillsFormat,
    AntigravityFormat,
    OpenCodeFormat,
    CodexFormat,
    OpenClawFormat,
    HermesFormat,
    ClaudeFormat,
)
from utils import get_version_from_pyproject
from validate_versions import (
    set_codex_plugin_version,
    set_marketplace_version,
    set_plugin_version,
)

# Project root is always one level up from src/
PROJECT_ROOT = Path(__file__).parent.parent
_CORE_RULES_REL = Path("sources/rules/core")
_RULES_ROOT_REL = Path("sources/rules")
_SKILL_TEMPLATE = PROJECT_ROOT / _CORE_RULES_REL / "codeguard-SKILLS.md.template"


def sync_plugin_metadata(version: str) -> None:
    """
    Sync the project version to the Claude Code and Codex plugin metadata.

    Args:
        version: Version string from pyproject.toml
    """
    set_plugin_version(version, PROJECT_ROOT)
    set_marketplace_version(version, PROJECT_ROOT)
    set_codex_plugin_version(version, PROJECT_ROOT)
    print(f"✅ Synced plugin metadata to {version}")


def matches_tag_filter(rule_tags: list[str], filter_tags: list[str]) -> bool:
    """
    Check if rule has all required tags (AND logic).

    Args:
        rule_tags: List of tags from the rule (already normalized to lowercase)
        filter_tags: List of tags to filter by (already normalized to lowercase)

    Returns:
        True if rule has all filter tags (or no filter), False otherwise
    """
    if not filter_tags:
        return True  # No filter means all pass

    return all(tag in rule_tags for tag in filter_tags)


def _render_skill_template(
    template: str, reference_names: set[str], version: str
) -> str:
    """Keep the authored routes for the references included in this bundle."""
    rendered = re.sub(
        r'codeguard-version:\s*"[^"]*"',
        lambda _match: f'codeguard-version: "{version}"',
        template,
    )
    lines = []
    for line in rendered.splitlines(keepends=True):
        route = re.match(r"- \[.*?\]\(references/([^/)]+\.md)\):", line)
        if route and route[1] not in reference_names:
            continue
        lines.append(line)
    return "".join(lines)


def convert_rules(
    input_path: str,
    output_dir: str = "dist",
    include_agentskills: bool = True,
    version: str = None,
    filter_tags: list[str] = None,
) -> dict[str, list[str]]:
    """
    Convert rule file(s) to all supported IDE formats using RuleConverter.

    Args:
        input_path: Path to a single .md file or folder containing .md files
        output_dir: Output directory (default: 'dist/')
        include_agentskills: Whether to generate Agent Skills format (default: True, only for core rules)
        version: Version string to use (default: read from pyproject.toml)
        filter_tags: Optional list of tags to filter by (AND logic, case-insensitive)

    Returns:
        Dictionary with 'success', 'errors', and 'skipped' lists.

    Example:
        results = convert_rules("sources/rules/core", "dist")
        print(f"Converted {len(results['success'])} rules")
    """
    if version is None:
        version = get_version_from_pyproject()

    # Specify formats to generate
    all_formats = [
        CursorFormat(version),
        WindsurfFormat(version),
        CopilotFormat(version),
        AntigravityFormat(version),
    ]

    # Only include Agent Skills–based formats (skills with SKILL.md) for core rules
    if include_agentskills:
        all_formats.append(AgentSkillsFormat(version))
        all_formats.append(DevinFormat(version))
        all_formats.append(OpenCodeFormat(version))
        all_formats.append(CodexFormat(version))
        all_formats.append(OpenClawFormat(version))
        all_formats.append(HermesFormat(version))
        all_formats.append(ClaudeFormat(version))

    converter = RuleConverter(formats=all_formats)
    path = Path(input_path)

    if not path.exists():
        raise FileNotFoundError(f"{input_path} does not exist")

    # Only ``codeguard-*.md`` are rule files; filter at the glob so SKILL.md /
    # READMEs don't hit RuleConverter.parse_rule and spam frontmatter errors.
    if path.is_file():
        if path.suffix != ".md":
            raise ValueError(f"{input_path} is not a .md file")
        if not path.name.startswith("codeguard-"):
            raise ValueError(
                f"{input_path} is not a rule file (name must start with "
                f"'codeguard-'). To convert a skill or reference doc, add it "
                f"to the appropriate sources/skills/<name>/ bundle instead."
            )
        md_files = [path]
    else:
        md_files = sorted(path.rglob("codeguard-*.md"))
        if not md_files:
            raise ValueError(
                f"No rule files (codeguard-*.md) found in {input_path}. "
                f"--source expects a directory of rules; skills and reference "
                f"docs are not valid sources for IDE format conversion."
            )

    print(f"Converting {len(md_files)} files from: {path}")

    # Setup output directory
    output_base = Path(output_dir)

    results = {"success": [], "errors": [], "skipped": []}
    conversions = []

    # Process each file
    for md_file in md_files:
        try:
            # Convert the file (raises exceptions on error)
            result = converter.convert(md_file)

            conversions.append(result)

        except FileNotFoundError as e:
            error_msg = f"{md_file.name}: File not found - {e}"
            print(f"Error: {error_msg}")
            results["errors"].append(error_msg)

        except ValueError as e:
            error_msg = f"{md_file.name}: Validation error - {e}"
            print(f"Error: {error_msg}")
            results["errors"].append(error_msg)

        except Exception as e:
            error_msg = f"{md_file.name}: Unexpected error - {e}"
            print(f"Error: {error_msg}")
            results["errors"].append(error_msg)

    selected = []
    for result in conversions:
        if filter_tags and not matches_tag_filter(result.tags, filter_tags):
            results["skipped"].append(result.filename)
        else:
            selected.append(result)

    if results["errors"]:
        return results

    if include_agentskills:
        if not _SKILL_TEMPLATE.exists():
            raise FileNotFoundError(f"SKILL.md template not found at {_SKILL_TEMPLATE}")
        template = _SKILL_TEMPLATE.read_text(encoding="utf-8")
        # Check routing before replacing generated output. Tag-filtered builds
        # intentionally include only a subset of the authored routes.
        all_references = {
            result.outputs["agentskills"].filename for result in conversions
        }
        routes = set(re.findall(r"\]\(references/([^/)]+\.md)\)", template))
        missing_routes = all_references - routes
        if len(all_references) != len(conversions):
            raise ValueError("Core rule filenames produce duplicate reference names")
        if missing_routes:
            raise ValueError(
                f"SKILL.md template has no routes for: {sorted(missing_routes)}"
            )
        if not filter_tags and path.is_dir() and routes != all_references:
            raise ValueError(
                "SKILL.md template references missing rules: "
                f"{sorted(routes - all_references)}"
            )

        output_skill_dir = PROJECT_ROOT / "skills" / "codeguard"
        # Remove both layouts so renamed/deleted rules and v1 files cannot
        # linger alongside regenerated references (including an empty filter).
        skill_dirs = [output_skill_dir] + [
            output_base / host / "skills" / "codeguard" for host in SKILL_COPY_HOSTS
        ]
        for skill_dir in skill_dirs:
            for layout in ("rules", "references"):
                generated_dir = skill_dir / layout
                if generated_dir.exists():
                    shutil.rmtree(generated_dir)
            (skill_dir / "SKILL.md").unlink(missing_ok=True)

    excluded_by_format = {
        handler.get_format_name(): {
            item.outputs[handler.get_format_name()].filename
            for item in conversions if item not in selected
        }
        for handler in all_formats
    }
    for result in selected:
        output_files = []
        for format_name, output in result.outputs.items():
            base_dir = PROJECT_ROOT if format_name == "agentskills" else output_base
            output_file = base_dir / output.subpath / output.filename
            # When a tag excludes a linked rule, preserve its label as plain
            # text instead of emitting a link to a file absent from the bundle.
            excluded = excluded_by_format[format_name]
            content = re.sub(
                r"\[([^\]]+)\]\(([^/):#]+)(?:#[^)]*)?\)",
                lambda match: match[1] if match[2] in excluded else match[0],
                output.content,
            )
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(content, encoding="utf-8")
            output_files.append(output_file.name)
        print(f"Success: {result.filename} → {', '.join(output_files)}")
        results["success"].append(result.filename)

    if include_agentskills and selected:
        reference_names = {
            result.outputs["agentskills"].filename for result in selected
        }
        output_skill_path = output_skill_dir / "SKILL.md"
        output_skill_path.write_text(
            _render_skill_template(template, reference_names, version), encoding="utf-8"
        )
        for host_dir in SKILL_COPY_HOSTS:
            dest = output_base / host_dir / "skills" / "codeguard" / "SKILL.md"
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(output_skill_path, dest)
            print(f"Copied SKILL.md to {dest}")

    print(
        f"\nResults: {len(results['success'])} success, "
        f"{len(results['skipped'])} skipped, {len(results['errors'])} errors"
    )

    return results


def _resolve_source_paths(args) -> list[Path]:
    """Resolve ``--source <name>`` arguments to ``sources/rules/<name>`` paths.

    Rejects absolute paths and ``..`` so a CLI invocation can't escape
    ``sources/rules/`` (``Path("sources/rules") / "/etc"`` would otherwise
    collapse to ``/etc``).
    """
    if not args.source:
        return [_CORE_RULES_REL]

    resolved = []
    for src in args.source:
        src_path = Path(src)
        if not src.strip() or src_path.is_absolute() or ".." in src_path.parts:
            raise ValueError(
                f"--source '{src}' must be a non-empty relative name under "
                f"sources/rules/ (no absolute paths, no '..'). "
                f"Examples: 'core', 'owasp', 'my-rules'."
            )
        resolved.append(Path("sources/rules") / src)
    return resolved


def _find_duplicate_rule_filenames(rules_root: Path) -> dict[str, list[Path]]:
    """Return rule filenames that appear more than once under rules_root."""
    filename_to_paths: defaultdict[str, list[Path]] = defaultdict(list)

    for source_dir in sorted(path for path in rules_root.iterdir() if path.is_dir()):
        for rule_file in sorted(source_dir.rglob("codeguard-*.md")):
            filename_to_paths[rule_file.name].append(rule_file)

    return {
        filename: paths
        for filename, paths in filename_to_paths.items()
        if len(paths) > 1
    }


def _print_duplicate_rule_filenames(
    duplicates: dict[str, list[Path]], rules_root: Path
) -> None:
    print(f"❌ Found {len(duplicates)} duplicate rule filename(s) under {rules_root}:")
    for filename, paths in sorted(duplicates.items()):
        relative_paths = [str(path.relative_to(rules_root)) for path in sorted(paths)]
        print(f"   - {filename} in: {', '.join(relative_paths)}")
    print("\nPlease rename or remove duplicate rule files.")


if __name__ == "__main__":
    import sys
    from argparse import ArgumentParser

    parser = ArgumentParser(
        description="Convert unified rule markdown into IDE-specific bundles."
    )
    parser.add_argument(
        "--source",
        nargs="+",
        help="Rule source directories under sources/rules/ to convert (e.g., --source core owasp my-rules). Each must contain codeguard-*.md files. Default: core",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        default="dist",
        help="Output directory for generated bundles (default: dist).",
    )
    parser.add_argument(
        "--tag",
        "--tags",
        dest="tags",
        help="Filter rules by tags (comma-separated, case-insensitive, AND logic). Example: --tag api,web-security",
    )

    cli_args = parser.parse_args()
    try:
        source_paths = _resolve_source_paths(cli_args)
    except ValueError as exc:
        print(f"❌ {exc}")
        sys.exit(1)

    # Validate all source paths exist
    missing = [p for p in source_paths if not p.exists()]
    if missing:
        print(f"❌ Source path(s) not found: {', '.join(str(p) for p in missing)}")
        sys.exit(1)

    duplicates = _find_duplicate_rule_filenames(PROJECT_ROOT / _RULES_ROOT_REL)
    if duplicates:
        _print_duplicate_rule_filenames(duplicates, PROJECT_ROOT / _RULES_ROOT_REL)
        sys.exit(1)

    version = get_version_from_pyproject()

    # Check if core is in the sources for Agent Skills generation
    has_core = _CORE_RULES_REL in source_paths
    if has_core and not _SKILL_TEMPLATE.exists():
        print(f"❌ SKILL.md template not found at {_SKILL_TEMPLATE}")
        print("This file is required for Agent Skills, OpenCode, and Codex generation.")
        sys.exit(1)

    # Clean output directories once before processing
    output_path = Path(cli_args.output_dir)
    if output_path.exists():
        shutil.rmtree(output_path)
        print(f"✅ Cleaned {cli_args.output_dir}/ directory")

    # Print processing summary
    if len(source_paths) > 1:
        sources_list = ", ".join(p.name for p in source_paths)
        print(f"\nConverting {len(source_paths)} sources: {sources_list}")
        if has_core:
            print("(Agent Skills, OpenCode, Codex, OpenClaw, and Hermes will include only core rules)")
        print()

    # Convert all sources
    aggregated = {"success": [], "errors": [], "skipped": []}
    core_has_rules = False
    # Parse comma-separated tags and normalize to lowercase
    filter_tags = None
    if cli_args.tags:
        filter_tags = [
            tag.strip().lower() for tag in cli_args.tags.split(",") if tag.strip()
        ]

    # Print tag filter info if active
    if filter_tags:
        print(
            f"Tag filter active: {', '.join(filter_tags)} (AND logic - rules must have all tags)\n"
        )

    for source_path in source_paths:
        is_core = source_path == _CORE_RULES_REL

        print(f"Processing: {source_path}")
        try:
            results = convert_rules(
                str(source_path),
                cli_args.output_dir,
                include_agentskills=is_core,
                version=version,
                filter_tags=filter_tags,
            )
        except ValueError as exc:
            print(f"❌ {exc}")
            sys.exit(1)

        aggregated["success"].extend(results["success"])
        if is_core:
            core_has_rules = bool(results["success"])
        aggregated["errors"].extend(results["errors"])
        if "skipped" in results:
            aggregated["skipped"].extend(results["skipped"])
        print("")

    if aggregated["errors"]:
        print("❌ Some conversions failed")
        sys.exit(1)

    # Agents read rules from each host's existing rules dir, which only
    # the core build populates for skill-bundle hosts.
    if core_has_rules:
        try:
            emit_agents(
                agents_source_dir=PROJECT_ROOT / "sources" / "agents",
                output_dir=Path(cli_args.output_dir),
            )
        except (ValueError, FileNotFoundError) as exc:
            print(f"❌ Agent emission failed: {exc}")
            sys.exit(1)
    else:
        print("ℹ️  Skipped agent emission (no core rules selected).")

    # Sync metadata last so a failed build doesn't leave plugin.json dirty.
    sync_plugin_metadata(version)

    print("✅ All conversions successful")
