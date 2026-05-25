"""Parse security-rule markdown files with YAML frontmatter.

Reads the unified rule sources from ``sources/rules/core/`` in the
cosai-project-codeguard repository.  The frontmatter schema matches
the converter's ``ProcessedRule``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from codeguard_mcp.config import settings

logger = logging.getLogger(__name__)


@dataclass
class ProcessedRule:
    rule_id: str
    description: str
    languages: list[str] = field(default_factory=list)
    always_apply: bool = False
    content: str = ""
    filename: str = ""
    tags: list[str] = field(default_factory=list)


class RuleProcessor:
    """Load ``*.md`` rule files from the repo's ``sources/rules/core/`` directory."""

    def __init__(self, rules_dir: str | Path | None = None) -> None:
        if rules_dir is None:
            self.rules_dir = Path(settings.RULES_DIR)
        else:
            self.rules_dir = Path(rules_dir)
        self._cache: list[ProcessedRule] | None = None

    @staticmethod
    def _split_frontmatter(text: str) -> tuple[dict | None, str]:
        if not text.startswith("---\n"):
            return None, text

        lines = text.split("\n")
        for idx in range(1, len(lines)):
            if lines[idx].strip() == "---":
                fm_text = "\n".join(lines[1:idx])
                body = "\n".join(lines[idx + 1 :]).strip()
                try:
                    return yaml.safe_load(fm_text), body
                except yaml.YAMLError as exc:
                    logger.warning("Bad YAML frontmatter: %s", exc)
                    return None, text

        return None, text

    def parse_rule(self, filepath: Path) -> ProcessedRule:
        if not filepath.exists():
            raise FileNotFoundError(filepath)

        fm, body = self._split_frontmatter(filepath.read_text(encoding="utf-8"))
        if not fm:
            raise ValueError(f"Missing frontmatter in {filepath.name}")

        description = fm.get("description", "").strip()
        if not description:
            raise ValueError(f"Missing 'description' in {filepath.name}")

        always_apply = fm.get("alwaysApply", False)
        languages: list[str] = []

        if always_apply:
            if fm.get("languages"):
                raise ValueError(
                    f"'languages' must be empty when alwaysApply is true ({filepath.name})"
                )
        else:
            languages = fm.get("languages", [])
            if not isinstance(languages, list) or not languages:
                raise ValueError(
                    f"'languages' required when alwaysApply is false ({filepath.name})"
                )

        tool_desc = description
        if always_apply:
            tool_desc += "\nApplies to all programming languages."
        elif languages:
            tool_desc += (
                f"\nApplicable to the following programming languages: "
                f"{', '.join(languages)}."
            )

        tags_raw = fm.get("tags", [])
        tags = [t.lower().strip() for t in tags_raw] if isinstance(tags_raw, list) else []

        return ProcessedRule(
            rule_id=filepath.stem,
            description=tool_desc,
            languages=[lang.lower() for lang in languages],
            always_apply=always_apply,
            content=body,
            filename=filepath.name,
            tags=tags,
        )

    def get_all_rules(self) -> list[ProcessedRule]:
        """Return all parsed rules, using a cached copy after the first load."""
        if self._cache is not None:
            return self._cache

        if not self.rules_dir.exists():
            logger.error("Rules directory missing: %s", self.rules_dir)
            return []

        rules: list[ProcessedRule] = []
        for md in sorted(self.rules_dir.glob("*.md")):
            if "template" in md.name.lower():
                continue
            try:
                rules.append(self.parse_rule(md))
            except (ValueError, OSError) as exc:
                logger.warning("Skipping malformed rule %s: %s", md.name, exc)

        logger.info("Loaded %d security rules from %s", len(rules), self.rules_dir)
        self._cache = rules
        return rules
