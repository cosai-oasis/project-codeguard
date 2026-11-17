"""Exercise generated skill bundles in an isolated project, without network access."""

import contextlib
import io
from pathlib import Path
import re
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import convert_to_ide_formats as build
from artifact_targets import AGENT_HOSTS, SKILL_COPY_HOSTS, TOML_AGENT_HOSTS
from emit_agents import emit_agents
from utils import parse_frontmatter_and_content
from validate_versions import get_skill_codeguard_version


class SkillGenerationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="codeguard-build-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.core = self.root / "sources/rules/core"
        shutil.copytree(PROJECT_ROOT / "sources/rules/core", self.core)
        self.output = self.root / "dist"
        self.skill = self.root / "skills/codeguard"
        root_patch = patch.object(build, "PROJECT_ROOT", self.root)
        root_patch.start()
        self.addCleanup(root_patch.stop)
        template_patch = patch.object(
            build, "_SKILL_TEMPLATE", self.core / "codeguard-SKILLS.md.template"
        )
        template_patch.start()
        self.addCleanup(template_patch.stop)

    def generate(self, **kwargs):
        source = kwargs.pop("source", self.core)
        with contextlib.redirect_stdout(io.StringIO()):
            result = build.convert_rules(
                str(source), str(self.output), version="2.0.0", **kwargs
            )
        self.assertEqual(result["errors"], [])
        return result

    def skill_bundles(self):
        return [self.skill] + [
            self.output / host / "skills/codeguard" for host in SKILL_COPY_HOSTS
        ]

    def assert_links_exist(self, directory):
        for path in directory.rglob("*"):
            if path.is_file() and path.suffix in {".md", ".mdc"}:
                for target in re.findall(r"\]\(([^)#]+)(?:#[^)]*)?\)", path.read_text()):
                    if ":" not in target:
                        self.assertTrue((path.parent / target).is_file(), (path, target))

    def test_all_hosts_share_complete_skill_with_canonical_ids(self):
        result = self.generate()
        sources = set(result["success"])
        self.assertEqual(len(sources), 24)
        self.assertIn("codeguard-0-firmware-security.md", sources)
        self.assertIn("codeguard-0-cloud-orchestration-kubernetes.md", sources)
        self.assertNotIn("codeguard-0-safe-c-functions.md", sources)
        for bundle in self.skill_bundles():
            self.assertFalse((bundle / "rules").exists())
            self.assertEqual((bundle / "SKILL.md").read_bytes(), (self.skill / "SKILL.md").read_bytes())
            references = list((bundle / "references").glob("*.md"))
            self.assertEqual(len(references), len(sources))
            for ref in references:
                self.assertFalse(ref.name.startswith("codeguard-"))
                metadata, body = parse_frontmatter_and_content(ref.read_text())
                rule_id = body.splitlines()[0].removeprefix("rule_id: ")
                self.assertIn(rule_id + ".md", sources)
                source_metadata, _ = parse_frontmatter_and_content((self.core / (rule_id + ".md")).read_text())
                self.assertEqual(metadata.get("languages", []), source_metadata["languages"])
                self.assertEqual(metadata["alwaysApply"], source_metadata["alwaysApply"])
            routes = set(re.findall(r"\]\(references/([^/)]+)\)", (bundle / "SKILL.md").read_text()))
            self.assertEqual(routes, {ref.name for ref in references})
            self.assert_links_exist(bundle)
        self.assertEqual(get_skill_codeguard_version(self.root), "2.0.0")
        for directory in (".cursor/rules", ".github/instructions", ".windsurf/rules", ".agents/rules"):
            self.assert_links_exist(self.output / directory)

    def test_regeneration_removes_legacy_and_stale_files_and_is_repeatable(self):
        for bundle in self.skill_bundles():
            for layout in ("rules", "references"):
                (bundle / layout).mkdir(parents=True)
                (bundle / layout / "stale.md").write_text("outdated guidance")
        self.generate()
        first = {str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        self.generate()
        second = {str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        self.assertEqual(first, second)
        for bundle in self.skill_bundles():
            self.assertFalse((bundle / "references/stale.md").exists())
            self.assertFalse((bundle / "rules").exists())

    def test_filtered_build_routes_and_links_only_to_included_files(self):
        result = self.generate(filter_tags=["secrets"])
        self.assertGreater(len(result["skipped"]), 0)
        self.assertGreater(len(result["success"]), 0)
        for bundle in self.skill_bundles():
            self.assertEqual(len(list((bundle / "references").glob("*.md"))), len(result["success"]))
            self.assert_links_exist(bundle)
        for directory in (".cursor/rules", ".github/instructions"):
            self.assert_links_exist(self.output / directory)

    def test_single_always_apply_rule_still_gets_an_entrypoint(self):
        result = self.generate(source=self.core / "codeguard-1-crypto-algorithms.md")
        self.assertEqual(len(result["success"]), 1)
        for bundle in self.skill_bundles():
            self.assertTrue((bundle / "SKILL.md").is_file())
            self.assertTrue((bundle / "references/crypto-algorithms.md").is_file())
            self.assert_links_exist(bundle)

    def test_empty_filter_cannot_leave_a_previous_skill_installed(self):
        self.generate()
        result = self.generate(filter_tags=["does-not-exist"])
        self.assertEqual(result["success"], [])
        for bundle in self.skill_bundles():
            self.assertFalse((bundle / "SKILL.md").exists())
            self.assertFalse((bundle / "references").exists())

    def test_unrouted_core_topic_is_rejected_before_overwriting_skill(self):
        self.generate()
        before = (self.skill / "SKILL.md").read_bytes()
        shutil.copyfile(self.core / "codeguard-1-crypto-algorithms.md", self.core / "codeguard-1-new-topic.md")
        with self.assertRaisesRegex(ValueError, "no routes for"):
            self.generate()
        self.assertEqual((self.skill / "SKILL.md").read_bytes(), before)

    def test_reviewers_can_find_their_generated_guidance(self):
        self.generate()
        with contextlib.redirect_stdout(io.StringIO()):
            emit_agents(agents_source_dir=PROJECT_ROOT / "sources/agents", output_dir=self.output)
        for cfg in [*AGENT_HOSTS.values(), *TOML_AGENT_HOSTS.values()]:
            directory = self.output / cfg["rules_dir"]
            self.assertEqual(len(list(directory.glob("*" + cfg["rule_ext"]))), 24)


if __name__ == "__main__":
    unittest.main()
