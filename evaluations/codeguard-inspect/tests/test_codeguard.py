from __future__ import annotations

import os
from pathlib import Path

import pytest

import codeguard_evals.codeguard as codeguard
from codeguard_evals.codeguard import (
    CODEGUARD_SOURCE,
    codeguard_content_sha256,
    codeguard_version,
    load_codeguard,
)

SKILL = b"# CodeGuard\n"
RULE = b"# Rule\n"


@pytest.fixture
def codeguard_source(tmp_path: Path) -> Path:
    source = tmp_path / "software-security"
    rules = source / "rules"
    rules.mkdir(parents=True)
    (source / "SKILL.md").write_bytes(SKILL)
    (rules / "codeguard-test.md").write_bytes(RULE)
    return source


def test_codeguard_freezes_allowlisted_files(codeguard_source: Path) -> None:
    assert load_codeguard(codeguard_source) == {
        "SKILL.md": SKILL,
        "rules/codeguard-test.md": RULE,
    }


def test_frozen_files_do_not_change_with_source(
    codeguard_source: Path,
) -> None:
    files = load_codeguard(codeguard_source)
    (codeguard_source / "SKILL.md").write_bytes(b"changed")
    (codeguard_source / "rules/codeguard-test.md").unlink()

    assert files == {
        "SKILL.md": SKILL,
        "rules/codeguard-test.md": RULE,
    }


def test_codeguard_content_digest_is_canonical_and_sensitive() -> None:
    snapshot = {
        "SKILL.md": SKILL,
        "rules/codeguard-test.md": RULE,
    }
    reversed_snapshot = dict(reversed(snapshot.items()))
    changed_snapshot = {**snapshot, "rules/codeguard-test.md": b"# Changed\n"}

    digest = codeguard_content_sha256(snapshot)
    assert len(digest) == 64
    assert codeguard_content_sha256(reversed_snapshot) == digest
    assert codeguard_content_sha256(changed_snapshot) != digest


@pytest.mark.parametrize(
    "snapshot",
    [
        {"SKILL.md": SKILL},
        {"SKILL.md": SKILL, "unexpected.md": RULE},
        {"SKILL.md": SKILL, "rules/codeguard-test.md": b""},
    ],
)
def test_codeguard_content_digest_rejects_invalid_snapshots(
    snapshot: dict[str, bytes],
) -> None:
    with pytest.raises(ValueError, match="no rules|unexpected path|invalid content"):
        codeguard_content_sha256(snapshot)


def test_frozen_snapshot_enforces_the_total_size_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = {
        "SKILL.md": SKILL,
        "rules/codeguard-test.md": RULE,
    }
    monkeypatch.setattr(
        codeguard,
        "MAX_CODEGUARD_TOTAL_BYTES",
        len(SKILL) + len(RULE) - 1,
    )

    with pytest.raises(ValueError, match="snapshot exceeds"):
        codeguard_content_sha256(snapshot)


def test_repository_codeguard_folder_is_loadable() -> None:
    files = load_codeguard()

    assert files["SKILL.md"] == (CODEGUARD_SOURCE / "SKILL.md").read_bytes()
    assert any(path.startswith("rules/codeguard-") for path in files)


def test_repository_codeguard_is_validated_without_rewriting() -> None:
    frozen = load_codeguard()
    original = dict(frozen)

    assert codeguard_version(frozen) == "1.4.0"
    assert frozen == original
    assert b"`rules/`" in frozen["SKILL.md"]


def test_codeguard_validation_rejects_nonstandard_front_matter() -> None:
    frozen = load_codeguard()
    frozen["SKILL.md"] = frozen["SKILL.md"].replace(
        b"framework:",
        b"unexpected: value\nframework:",
    )

    with pytest.raises(ValueError, match="unexpected front matter"):
        codeguard_version(frozen)


def test_codeguard_validation_rejects_non_utf8_rule() -> None:
    frozen = load_codeguard()
    rule_path = next(path for path in frozen if path.startswith("rules/"))
    frozen[rule_path] = b"\xff"

    with pytest.raises(ValueError, match="not valid UTF-8"):
        codeguard_version(frozen)


@pytest.mark.parametrize(
    ("relative_path", "empty", "message"),
    [
        ("SKILL.md", False, "missing SKILL"),
        ("SKILL.md", True, "file is empty"),
        ("rules/codeguard-test.md", False, "no rules"),
        ("rules/codeguard-test.md", True, "file is empty"),
    ],
)
def test_codeguard_requires_nonempty_skill_and_rule(
    codeguard_source: Path,
    relative_path: str,
    empty: bool,
    message: str,
) -> None:
    path = codeguard_source / relative_path
    if empty:
        path.write_bytes(b"")
    else:
        path.unlink()

    with pytest.raises(ValueError, match=message):
        load_codeguard(codeguard_source)


def test_codeguard_rejects_unsafe_names(codeguard_source: Path) -> None:
    rule = codeguard_source / "rules/codeguard-test.md"
    rule.rename(codeguard_source / "rules/codeguard-bad:name.md")

    with pytest.raises(ValueError, match="unexpected rule"):
        load_codeguard(codeguard_source)


def test_codeguard_rejects_unexpected_files(codeguard_source: Path) -> None:
    (codeguard_source / ".env").write_text("unexpected\n", encoding="utf-8")

    with pytest.raises(ValueError, match="unexpected entries"):
        load_codeguard(codeguard_source)


@pytest.mark.parametrize("kind", ["root", "file", "directory", "broken"])
def test_codeguard_rejects_symlinks(
    tmp_path: Path,
    codeguard_source: Path,
    kind: str,
) -> None:
    source = codeguard_source
    if kind == "root":
        source = tmp_path / "linked-source"
        source.symlink_to(codeguard_source, target_is_directory=True)
    elif kind == "file":
        skill = source / "SKILL.md"
        skill.unlink()
        skill.symlink_to(source / "rules/codeguard-test.md")
    elif kind == "directory":
        rules = source / "rules"
        (rules / "codeguard-test.md").unlink()
        rules.rmdir()
        rules.symlink_to(tmp_path, target_is_directory=True)
    else:
        rule = source / "rules/codeguard-test.md"
        rule.unlink()
        rule.symlink_to(source / "missing.md")

    with pytest.raises(ValueError, match="directory|safely open"):
        load_codeguard(source)


def test_codeguard_rejects_special_files(codeguard_source: Path) -> None:
    rule = codeguard_source / "rules/codeguard-test.md"
    rule.unlink()
    os.mkfifo(rule)

    with pytest.raises(ValueError, match="not a regular file"):
        load_codeguard(codeguard_source)


@pytest.mark.parametrize(
    ("limit_name", "exact_limit"),
    [
        ("MAX_CODEGUARD_FILES", 2),
        ("MAX_CODEGUARD_FILE_BYTES", len(SKILL)),
        ("MAX_CODEGUARD_TOTAL_BYTES", len(SKILL) + len(RULE)),
    ],
)
def test_codeguard_limits_accept_boundary_and_reject_one_less(
    monkeypatch: pytest.MonkeyPatch,
    codeguard_source: Path,
    limit_name: str,
    exact_limit: int,
) -> None:
    monkeypatch.setattr(codeguard, limit_name, exact_limit)
    load_codeguard(codeguard_source)

    monkeypatch.setattr(codeguard, limit_name, exact_limit - 1)
    with pytest.raises(ValueError, match="exceeds"):
        load_codeguard(codeguard_source)
