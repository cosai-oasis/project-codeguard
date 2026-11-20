from __future__ import annotations

import os
from pathlib import Path

import pytest

import codeguard_evals.skill_files as skill_files
from codeguard_evals.skill_files import (
    load_skill_files,
    skill_content_sha256,
    skill_front_matter,
    skill_version,
)

SKILL = (
    b"---\n"
    b"name: codeguard\n"
    b"description: Secure coding guidance.\n"
    b"---\n"
    b"# CodeGuard\n"
)
RULE = b"# Rule\n"


@pytest.fixture(params=["rules/codeguard-test.md", "references/test-guidance.md"])
def guidance_path(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture
def skill_source(tmp_path: Path, guidance_path: str) -> Path:
    source = tmp_path / "software-security"
    guidance = source / guidance_path
    guidance.parent.mkdir(parents=True)
    (source / "SKILL.md").write_bytes(SKILL)
    guidance.write_bytes(RULE)
    return source


def test_skill_freezes_allowlisted_files(
    skill_source: Path,
    guidance_path: str,
) -> None:
    assert load_skill_files(skill_source) == {
        "SKILL.md": SKILL,
        guidance_path: RULE,
    }


def test_frozen_files_do_not_change_with_source(
    skill_source: Path,
    guidance_path: str,
) -> None:
    files = load_skill_files(skill_source)
    (skill_source / "SKILL.md").write_bytes(b"changed")
    (skill_source / guidance_path).unlink()

    assert files == {
        "SKILL.md": SKILL,
        guidance_path: RULE,
    }


def test_skill_content_digest_is_canonical_and_sensitive(
    guidance_path: str,
) -> None:
    snapshot = {
        "SKILL.md": SKILL,
        guidance_path: RULE,
    }
    reversed_snapshot = dict(reversed(snapshot.items()))
    changed_snapshot = {**snapshot, guidance_path: b"# Changed\n"}
    renamed_snapshot = {
        "SKILL.md": SKILL,
        f"{guidance_path.rsplit('/', 1)[0]}/codeguard-renamed.md": RULE,
    }

    digest = skill_content_sha256(snapshot)
    assert len(digest) == 64
    assert skill_content_sha256(reversed_snapshot) == digest
    assert skill_content_sha256(changed_snapshot) != digest
    assert skill_content_sha256(renamed_snapshot) != digest


@pytest.mark.parametrize(
    "snapshot",
    [
        {},
        {"SKILL.md": SKILL, "unexpected.md": RULE},
        {"SKILL.md": SKILL, "rules/codeguard-test.md": b""},
    ],
)
def test_skill_content_digest_rejects_invalid_snapshots(
    snapshot: dict[str, bytes],
) -> None:
    with pytest.raises(ValueError, match="unexpected layout|unexpected path|invalid content"):
        skill_content_sha256(snapshot)


def test_frozen_snapshot_enforces_the_total_size_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = {
        "SKILL.md": SKILL,
        "rules/codeguard-test.md": RULE,
    }
    monkeypatch.setattr(
        skill_files,
        "MAX_SKILL_TOTAL_BYTES",
        len(SKILL) + len(RULE) - 1,
    )

    with pytest.raises(ValueError, match="snapshot exceeds"):
        skill_content_sha256(snapshot)


def test_skill_does_not_infer_a_missing_version(skill_source: Path) -> None:
    frozen = load_skill_files(skill_source)
    original = dict(frozen)

    assert skill_version(skill_front_matter(frozen)) == "unspecified"
    assert frozen == original


@pytest.mark.parametrize("version", ["1.4.0", "9.8.7"])
def test_skill_preserves_the_declared_version(
    skill_source: Path,
    version: str,
) -> None:
    frozen = load_skill_files(skill_source)
    frozen["SKILL.md"] = SKILL.replace(
        b"---\n# CodeGuard\n",
        (
            f'codeguard-version: "{version}"\n'
            "framework: Project CodeGuard\n"
            "purpose: Secure code generation guidance\n"
            "---\n# CodeGuard\n"
        ).encode(),
    )
    original = dict(frozen)

    assert skill_version(skill_front_matter(frozen)) == version
    assert frozen == original


def test_skill_validation_rejects_nonstandard_front_matter(
    skill_source: Path,
) -> None:
    frozen = load_skill_files(skill_source)
    frozen["SKILL.md"] = frozen["SKILL.md"].replace(
        b"name: codeguard\n",
        b"name: codeguard\nunexpected: value\n",
    )

    with pytest.raises(ValueError, match="unexpected front matter"):
        skill_version(skill_front_matter(frozen))


def test_skill_validation_rejects_non_utf8_guidance(
    skill_source: Path,
    guidance_path: str,
) -> None:
    frozen = load_skill_files(skill_source)
    frozen[guidance_path] = b"\xff"

    with pytest.raises(ValueError, match="not valid UTF-8"):
        skill_version(skill_front_matter(frozen))


@pytest.mark.parametrize(
    ("relative_path", "empty", "message"),
    [
        ("SKILL.md", False, "missing SKILL"),
        ("SKILL.md", True, "file is empty"),
        ("guidance", True, "file is empty"),
    ],
)
def test_skill_requires_nonempty_files(
    skill_source: Path,
    guidance_path: str,
    relative_path: str,
    empty: bool,
    message: str,
) -> None:
    path = skill_source / (
        guidance_path if relative_path == "guidance" else relative_path
    )
    if empty:
        path.write_bytes(b"")
    else:
        path.unlink()

    with pytest.raises(ValueError, match=message):
        load_skill_files(skill_source)


def test_skill_rejects_unsafe_names(
    skill_source: Path,
    guidance_path: str,
) -> None:
    rule = skill_source / guidance_path
    rule.rename(rule.with_name("codeguard-bad:name.md"))

    with pytest.raises(ValueError, match="unexpected guidance"):
        load_skill_files(skill_source)


def test_skill_rejects_unexpected_files(skill_source: Path) -> None:
    (skill_source / ".env").write_text("unexpected\n", encoding="utf-8")

    with pytest.raises(ValueError, match="unexpected entries"):
        load_skill_files(skill_source)


def test_skill_rejects_mixed_layouts(
    skill_source: Path,
    guidance_path: str,
) -> None:
    frozen = load_skill_files(skill_source)
    other_dir = "references" if guidance_path.startswith("rules/") else "rules"
    other_path = f"{other_dir}/codeguard-other.md"
    frozen[other_path] = RULE
    with pytest.raises(ValueError, match="mixes guidance layouts"):
        skill_content_sha256(frozen)

    (skill_source / other_dir).mkdir()
    (skill_source / other_path).write_bytes(RULE)
    with pytest.raises(ValueError, match="unexpected entries"):
        load_skill_files(skill_source)


@pytest.mark.parametrize("kind", ["root", "file", "directory", "broken"])
def test_skill_rejects_symlinks(
    tmp_path: Path,
    skill_source: Path,
    guidance_path: str,
    kind: str,
) -> None:
    source = skill_source
    if kind == "root":
        source = tmp_path / "linked-source"
        source.symlink_to(skill_source, target_is_directory=True)
    elif kind == "file":
        skill = source / "SKILL.md"
        skill.unlink()
        skill.symlink_to(source / guidance_path)
    elif kind == "directory":
        guidance = source / guidance_path
        guidance.unlink()
        guidance.parent.rmdir()
        guidance.parent.symlink_to(tmp_path, target_is_directory=True)
    else:
        rule = source / guidance_path
        rule.unlink()
        rule.symlink_to(source / "missing.md")

    with pytest.raises(ValueError, match="directory|safely open"):
        load_skill_files(source)


def test_skill_rejects_special_files(
    skill_source: Path,
    guidance_path: str,
) -> None:
    rule = skill_source / guidance_path
    rule.unlink()
    os.mkfifo(rule)

    with pytest.raises(ValueError, match="not a regular file"):
        load_skill_files(skill_source)


@pytest.mark.parametrize(
    ("limit_name", "exact_limit"),
    [
        ("MAX_SKILL_FILES", 2),
        ("MAX_SKILL_FILE_BYTES", len(SKILL)),
        ("MAX_SKILL_TOTAL_BYTES", len(SKILL) + len(RULE)),
    ],
)
def test_skill_limits_accept_boundary_and_reject_one_less(
    monkeypatch: pytest.MonkeyPatch,
    skill_source: Path,
    limit_name: str,
    exact_limit: int,
) -> None:
    monkeypatch.setattr(skill_files, limit_name, exact_limit)
    load_skill_files(skill_source)

    monkeypatch.setattr(skill_files, limit_name, exact_limit - 1)
    with pytest.raises(ValueError, match="exceeds"):
        load_skill_files(skill_source)


@pytest.mark.parametrize("guidance", [False, True], ids=["standalone", "references"])
def test_catalog_loads_exact_skill_bytes(catalog_skill, guidance):
    from codeguard_evals.skill_catalog import load_skill_variant
    path, expected = catalog_skill("selected", guidance=guidance)
    snapshot, identity = load_skill_variant("selected")
    assert snapshot == expected
    assert identity.name == "example-security" and identity.version is None
    assert identity.content_sha256 == skill_content_sha256(expected)
    (path / "SKILL.md").write_text("changed")
    assert snapshot == expected


@pytest.mark.parametrize("filename", ["SKILL.md", "references/REFERENCE.md"])
def test_catalog_detects_changes_to_any_selected_file(catalog_skill, filename):
    from codeguard_evals.skill_catalog import load_skill_variant
    path, _ = catalog_skill("selected", guidance=True)
    (path / filename).write_text("Changed instructions.\n")
    with pytest.raises(ValueError, match="pinned fingerprint"):
        load_skill_variant("selected")


@pytest.mark.parametrize("problem", ["traversal", "absolute", "ancestor_link", "file_link", "script"])
def test_catalog_rejects_unsafe_inputs(catalog_skill, problem, tmp_path):
    import json
    from codeguard_evals import skill_catalog
    path, _ = catalog_skill("selected")
    # The entry loads until the one unsafe change below.
    skill_catalog.load_skill_variant("selected")
    if problem in ("traversal", "absolute"):
        entries = json.loads(skill_catalog.CATALOG_PATH.read_text())
        entries["selected"]["path"] = "../outside" if problem == "traversal" else str(path)
        skill_catalog.CATALOG_PATH.write_text(json.dumps(entries))
    elif problem == "ancestor_link":
        ancestor = path.parent
        moved = ancestor.with_name("moved")
        ancestor.rename(moved)
        ancestor.symlink_to(moved, target_is_directory=True)
    elif problem == "file_link":
        source = path / "SKILL.md"
        moved = tmp_path / "linked.md"
        moved.write_bytes(source.read_bytes())
        source.unlink()
        source.symlink_to(moved)
    else:
        (path / "run.sh").write_text("exit 0\n")
    with pytest.raises((OSError, ValueError)):
        skill_catalog.load_skill_variant("selected")


def test_catalog_rejects_duplicate_ids_and_unknown_selections(catalog_skill):
    import json
    from codeguard_evals import skill_catalog
    catalog_skill("selected")
    with pytest.raises(ValueError, match="Select a skill variant"):
        skill_catalog.load_skill_variant("unknown")
    entry = json.loads(skill_catalog.CATALOG_PATH.read_text())["selected"]
    record = json.dumps(entry)
    skill_catalog.CATALOG_PATH.write_text('{"selected":' + record + ',"selected":' + record + '}')
    with pytest.raises(ValueError, match="catalog is missing or invalid"):
        skill_catalog.load_skill_variant("selected")


@pytest.mark.parametrize("line_ending", [b"\n", b"\r\n"], ids=["LF", "CRLF"])
@pytest.mark.parametrize(
    ("version_key", "version"),
    [("version", "candidate-1"), ("codeguard-version", "2.0.0")],
)
def test_standard_skill_metadata_is_preserved(catalog_skill, line_ending, version_key, version):
    import json
    from codeguard_evals import skill_catalog
    from codeguard_evals.skill_files import skill_front_matter
    path, snapshot = catalog_skill("selected")
    snapshot["SKILL.md"] = snapshot["SKILL.md"].replace(b"description:", (
        "license: Apache-2.0\ncompatibility: Offline coding agent.\n"
        f"allowed-tools: Read\nmetadata:\n  {version_key}: {version}\ndescription:"
    ).encode())
    snapshot["SKILL.md"] = snapshot["SKILL.md"].replace(b"\n", line_ending)
    original = dict(snapshot)
    fields = skill_front_matter(snapshot)
    assert fields["metadata"] == {version_key: version}
    assert fields["allowed-tools"] == "Read"
    assert snapshot == original

    (path / "SKILL.md").write_bytes(snapshot["SKILL.md"])
    entries = json.loads(skill_catalog.CATALOG_PATH.read_text())
    entries["selected"]["content_sha256"] = skill_content_sha256(snapshot)
    skill_catalog.CATALOG_PATH.write_text(json.dumps(entries))
    loaded, identity = skill_catalog.load_skill_variant("selected")
    assert loaded == original
    assert identity.name == "example-security"
    assert identity.version == version


def test_repository_catalog_pins_are_valid(tmp_path, monkeypatch):
    import json
    import shutil
    from codeguard_evals import skill_catalog

    entries = json.loads(skill_catalog.CATALOG_PATH.read_text())
    expected = {variant: skill_catalog.load_skill_variant(variant) for variant in entries}
    snapshot_root = skill_catalog.CATALOG_PATH.parent
    shutil.copytree(
        snapshot_root, tmp_path / snapshot_root.relative_to(skill_catalog.PROJECT_ROOT),
    )
    # A checkout with a different live skill must still load every frozen variant.
    live = tmp_path / "skills/codeguard"
    live.mkdir(parents=True)
    (live / "SKILL.md").write_text("Changed repository skill.\n")
    monkeypatch.setattr(skill_catalog, "PROJECT_ROOT", tmp_path)
    for variant, (original, provenance) in expected.items():
        snapshot, identity = skill_catalog.load_skill_variant(variant)
        assert snapshot == original
        assert identity == provenance
        assert identity.id == variant and snapshot["SKILL.md"]
    # The benchmark packages' CodeGuard tasks install a released CodeGuard bundle.
    codeguard = expected[skill_catalog.CODEGUARD_VARIANT][1]
    assert (codeguard.name, codeguard.version) == ("codeguard", "1.5.0")
