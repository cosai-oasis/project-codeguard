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
def codeguard_source(tmp_path: Path, guidance_path: str) -> Path:
    source = tmp_path / "software-security"
    guidance = source / guidance_path
    guidance.parent.mkdir(parents=True)
    (source / "SKILL.md").write_bytes(SKILL)
    guidance.write_bytes(RULE)
    return source


def test_codeguard_freezes_allowlisted_files(
    codeguard_source: Path,
    guidance_path: str,
) -> None:
    assert load_codeguard(codeguard_source) == {
        "SKILL.md": SKILL,
        guidance_path: RULE,
    }


def test_frozen_files_do_not_change_with_source(
    codeguard_source: Path,
    guidance_path: str,
) -> None:
    files = load_codeguard(codeguard_source)
    (codeguard_source / "SKILL.md").write_bytes(b"changed")
    (codeguard_source / guidance_path).unlink()

    assert files == {
        "SKILL.md": SKILL,
        guidance_path: RULE,
    }


def test_codeguard_content_digest_is_canonical_and_sensitive(
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

    digest = codeguard_content_sha256(snapshot)
    assert len(digest) == 64
    assert codeguard_content_sha256(reversed_snapshot) == digest
    assert codeguard_content_sha256(changed_snapshot) != digest
    assert codeguard_content_sha256(renamed_snapshot) != digest


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
    with pytest.raises(ValueError, match="no guidance|unexpected path|invalid content"):
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


def test_repository_codeguard_is_validated_without_rewriting() -> None:
    frozen = load_codeguard()
    original = dict(frozen)

    assert len(frozen) > 1
    assert codeguard_version(frozen)
    assert all(
        content == (CODEGUARD_SOURCE / path).read_bytes()
        for path, content in frozen.items()
    )
    assert frozen == original


def test_codeguard_does_not_infer_a_missing_version(codeguard_source: Path) -> None:
    frozen = load_codeguard(codeguard_source)
    original = dict(frozen)

    assert codeguard_version(frozen) == "unspecified"
    assert frozen == original


@pytest.mark.parametrize("version", ["1.4.0", "9.8.7"])
def test_codeguard_preserves_the_declared_version(
    codeguard_source: Path,
    version: str,
) -> None:
    frozen = load_codeguard(codeguard_source)
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

    assert codeguard_version(frozen) == version
    assert frozen == original


def test_codeguard_validation_rejects_nonstandard_front_matter(
    codeguard_source: Path,
) -> None:
    frozen = load_codeguard(codeguard_source)
    frozen["SKILL.md"] = frozen["SKILL.md"].replace(
        b"name: codeguard\n",
        b"name: codeguard\nunexpected: value\n",
    )

    with pytest.raises(ValueError, match="unexpected front matter"):
        codeguard_version(frozen)


def test_codeguard_validation_rejects_non_utf8_guidance(
    codeguard_source: Path,
    guidance_path: str,
) -> None:
    frozen = load_codeguard(codeguard_source)
    frozen[guidance_path] = b"\xff"

    with pytest.raises(ValueError, match="not valid UTF-8"):
        codeguard_version(frozen)


@pytest.mark.parametrize(
    ("relative_path", "empty", "message"),
    [
        ("SKILL.md", False, "missing SKILL"),
        ("SKILL.md", True, "file is empty"),
        ("guidance", False, "no guidance"),
        ("guidance", True, "file is empty"),
    ],
)
def test_codeguard_requires_nonempty_skill_and_guidance(
    codeguard_source: Path,
    guidance_path: str,
    relative_path: str,
    empty: bool,
    message: str,
) -> None:
    path = codeguard_source / (
        guidance_path if relative_path == "guidance" else relative_path
    )
    if empty:
        path.write_bytes(b"")
    else:
        path.unlink()

    with pytest.raises(ValueError, match=message):
        load_codeguard(codeguard_source)


def test_codeguard_rejects_unsafe_names(
    codeguard_source: Path,
    guidance_path: str,
) -> None:
    rule = codeguard_source / guidance_path
    rule.rename(rule.with_name("codeguard-bad:name.md"))

    with pytest.raises(ValueError, match="unexpected guidance"):
        load_codeguard(codeguard_source)


def test_codeguard_rejects_unexpected_files(codeguard_source: Path) -> None:
    (codeguard_source / ".env").write_text("unexpected\n", encoding="utf-8")

    with pytest.raises(ValueError, match="unexpected entries"):
        load_codeguard(codeguard_source)


def test_codeguard_rejects_mixed_layouts(
    codeguard_source: Path,
    guidance_path: str,
) -> None:
    frozen = load_codeguard(codeguard_source)
    other_dir = "references" if guidance_path.startswith("rules/") else "rules"
    other_path = f"{other_dir}/codeguard-other.md"
    frozen[other_path] = RULE
    with pytest.raises(ValueError, match="mixes guidance layouts"):
        codeguard_content_sha256(frozen)

    (codeguard_source / other_dir).mkdir()
    (codeguard_source / other_path).write_bytes(RULE)
    with pytest.raises(ValueError, match="unexpected entries"):
        load_codeguard(codeguard_source)


@pytest.mark.parametrize("kind", ["root", "file", "directory", "broken"])
def test_codeguard_rejects_symlinks(
    tmp_path: Path,
    codeguard_source: Path,
    guidance_path: str,
    kind: str,
) -> None:
    source = codeguard_source
    if kind == "root":
        source = tmp_path / "linked-source"
        source.symlink_to(codeguard_source, target_is_directory=True)
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
        load_codeguard(source)


def test_codeguard_rejects_special_files(
    codeguard_source: Path,
    guidance_path: str,
) -> None:
    rule = codeguard_source / guidance_path
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
