from __future__ import annotations

import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from codeguard_evals.artifact_locks import MAX_FILES_LOCK_BYTES
from codeguard_evals.artifacts import MAX_FILE_BYTES, MAX_TREE_BYTES, tree_sha256
from codeguard_evals.graders.scanner_worker import SEMGREP_VERSION
from codeguard_evals.graders.semgrep_artifacts import (
    ALL_SEMGREP_SUBCATEGORIES,
    MEASURED_SEVERITIES,
    MAX_SEMGREP_LOCK_BYTES,
    SEMGREP_IMAGE_REFERENCE,
    SEMGREP_LOCK,
    SEMGREP_RULES_CACHE_ROOT,
    SemgrepLock,
    load_locked_rules_directory,
    load_semgrep_lock,
    semgrep_provenance,
    semgrep_rules_checkout_path,
)
from tests.conftest import semgrep_lock_for_files


def _cached_checkout(
    root: Path,
    *,
    lock: SemgrepLock = SEMGREP_LOCK,
    files: dict[str, bytes] | None = None,
) -> tuple[Path, Path]:
    root.mkdir(mode=0o700, exist_ok=True)
    root.chmod(0o700)
    checkout = semgrep_rules_checkout_path(lock, cache_root=root)
    checkout.mkdir()
    rules = checkout / lock.rules.subdirectory
    rules.mkdir()
    for relative, content in (files or {}).items():
        target = checkout / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    return checkout, rules


def test_rules_tree_sha256_is_rule_relative_ordered_and_framed(
    tmp_path: Path,
) -> None:
    files = {"z.yaml": b"z", "nested/a.py": b"a", "README.md": b"docs"}
    first = tmp_path / "first"
    second = tmp_path / "second"
    for root, entries in ((first, files.items()), (second, reversed(files.items()))):
        for relative, content in entries:
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)

    expected = "9fa6003728b952cb196027ac3e5c62c994612a471f6c937d09185a9e266a085e"
    assert tree_sha256(first) == expected
    assert tree_sha256(second) == expected


def test_tracked_lock_pins_image_and_only_python_rule_definitions() -> None:
    assert SEMGREP_LOCK.schema_version == 4
    assert SEMGREP_LOCK.image.version == "1.173.0"
    assert SEMGREP_VERSION == SEMGREP_LOCK.image.version
    assert SEMGREP_LOCK.image.tag == "1.173.0-nonroot"
    assert SEMGREP_IMAGE_REFERENCE.endswith(
        "@sha256:ae85c429145ef6b29c7a47b4cdec78304f9b325f75ce0ee4a797e841206e3e68"
    )
    assert SEMGREP_LOCK.rules.repository == "https://github.com/semgrep/semgrep-rules"
    assert SEMGREP_LOCK.rules.commit == "40b8c63f75dc7c22c8a77482d73bfb864b146f7e"
    assert SEMGREP_LOCK.rules.subdirectory == "python"
    assert SEMGREP_LOCK.rules.tree_sha256 == (
        "412d075726808b10d1a78f194006dbe03ceb62b1a4fa734640a82c70b8f7b4b8"
    )
    assert SEMGREP_RULES_CACHE_ROOT.name == "semgrep-rules-only"
    assert len(SEMGREP_LOCK.rules.files) == 338
    assert "LICENSE" in SEMGREP_LOCK.rules.files
    assert all(
        name == "LICENSE" or name.startswith("python/") and name.endswith(".yaml")
        for name in SEMGREP_LOCK.rules.files
    )


def test_lock_can_load_the_maximum_file_count(tmp_path: Path) -> None:
    files = {
        f"python/security/audit/fixture_rule_{index:03d}.yaml": b"rules: []\n"
        for index in range(511)
    }
    files["LICENSE"] = b"fixture license\n"
    lock = semgrep_lock_for_files(files)
    raw = json.dumps(lock.model_dump(mode="json"), indent=2).encode()
    assert MAX_FILES_LOCK_BYTES < len(raw) < MAX_SEMGREP_LOCK_BYTES
    path = tmp_path / "semgrep.lock.json"
    path.write_bytes(raw)
    assert load_semgrep_lock(path) == lock


def test_lock_enforces_its_byte_limit(tmp_path: Path) -> None:
    raw = json.dumps(SEMGREP_LOCK.model_dump(mode="json")).encode()
    path = tmp_path / "semgrep.lock.json"
    path.write_bytes(raw.ljust(MAX_SEMGREP_LOCK_BYTES, b" "))
    assert load_semgrep_lock(path) == SEMGREP_LOCK
    path.write_bytes(raw.ljust(MAX_SEMGREP_LOCK_BYTES + 1, b" "))
    with pytest.raises(RuntimeError, match="lock is invalid"):
        load_semgrep_lock(path)


def test_provenance_records_scanner_and_rules_identity() -> None:
    assert semgrep_provenance() == {
        "version": "1.173.0",
        "engine": "OSS",
        "execution": "inspect-sandbox:semgrep",
        "image": "docker.io/semgrep/semgrep:1.173.0-nonroot",
        "image_digest": SEMGREP_LOCK.image.index_digest,
        "rules_repository": SEMGREP_LOCK.rules.repository,
        "rules_commit": SEMGREP_LOCK.rules.commit,
        "rules_subdirectory": "python",
        "rules_tree_sha256": SEMGREP_LOCK.rules.tree_sha256,
        "finding_category": "security",
        "measured_subcategories": sorted(ALL_SEMGREP_SUBCATEGORIES),
        "measured_severities": sorted(MEASURED_SEVERITIES),
        "rule_id_rewriting": True,
    }


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(schema_version=3),
        lambda value: value.update(unexpected=True),
        lambda value: value["image"].update(version="latest"),
        lambda value: value["image"].update(index_digest="sha256:bad"),
        lambda value: value["rules"].update(commit="main"),
        lambda value: value["rules"].update(tree_sha256="bad"),
        lambda value: value["rules"].update(subdirectory="javascript"),
        lambda value: value["rules"]["files"].pop("LICENSE"),
        lambda value: value["rules"].update(
            files={"LICENSE": value["rules"]["files"]["LICENSE"]}
        ),
    ],
)
def test_lock_rejects_malformed_contracts(
    mutation: Callable[[dict[str, Any]], object],
    tmp_path: Path,
) -> None:
    value = SEMGREP_LOCK.model_dump(mode="json")
    mutation(value)
    path = tmp_path / "semgrep.lock.json"
    path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(RuntimeError, match="lock is invalid"):
        load_semgrep_lock(path)


@pytest.fixture
def locked_rules(tmp_path: Path) -> tuple[SemgrepLock, Path]:
    files = {
        "LICENSE": b"fixture license\n",
        "python/one.yaml": b"rules: []\n",
        "python/nested/two.yml": b"rules: []\r\n",
    }
    lock = semgrep_lock_for_files(files)
    _, rules = _cached_checkout(tmp_path, lock=lock, files=files)
    return lock, rules


def test_locked_rules_directory_accepts_exact_private_checkout(
    tmp_path: Path, locked_rules: tuple[SemgrepLock, Path]
) -> None:
    lock, rules = locked_rules
    assert load_locked_rules_directory(lock, cache_root=tmp_path) == rules


@pytest.mark.parametrize("mutation", ["content", "path", "add", "delete"])
def test_locked_rules_directory_rejects_tree_identity_changes(
    mutation: str,
    tmp_path: Path,
    locked_rules: tuple[SemgrepLock, Path],
) -> None:
    lock, rules = locked_rules
    if mutation == "content":
        (rules / "nested/two.yml").write_bytes(b"changed\n")
    elif mutation == "path":
        (rules / "one.yaml").rename(rules / "renamed.yaml")
    elif mutation == "add":
        (rules / "added.md").write_bytes(b"added\n")
    else:
        (rules / "one.yaml").unlink()

    with pytest.raises(RuntimeError, match="rules are invalid"):
        load_locked_rules_directory(lock, cache_root=tmp_path)


@pytest.mark.parametrize("kind", ["file", "directory"])
def test_locked_rules_directory_rejects_every_symlink(
    kind: str,
    tmp_path: Path,
    locked_rules: tuple[SemgrepLock, Path],
) -> None:
    lock, rules = locked_rules
    if kind == "file":
        external = tmp_path / "external.txt"
        external.write_text("external\n")
        (rules / "linked.txt").symlink_to(external)
    else:
        external = tmp_path / "external"
        external.mkdir()
        (rules / "linked").symlink_to(external, target_is_directory=True)

    with pytest.raises(RuntimeError, match="rules are invalid"):
        load_locked_rules_directory(lock, cache_root=tmp_path)


@pytest.mark.parametrize(
    "relative",
    ["rule.yml", "rule.test.yaml", "rule.fixed.yml", "fixture.py", "README.md"],
)
def test_locked_rules_directory_rejects_unlisted_file_types(
    relative: str,
    tmp_path: Path,
    locked_rules: tuple[SemgrepLock, Path],
) -> None:
    lock, rules = locked_rules
    (rules / relative).write_bytes(b"new file\n")

    with pytest.raises(RuntimeError, match="rules are invalid"):
        load_locked_rules_directory(lock, cache_root=tmp_path)


def test_locked_rules_directory_rejects_special_file(
    tmp_path: Path,
    locked_rules: tuple[SemgrepLock, Path],
) -> None:
    lock, rules = locked_rules
    os.mkfifo(rules / "special")

    with pytest.raises(RuntimeError, match="rules are invalid"):
        load_locked_rules_directory(lock, cache_root=tmp_path)


@pytest.mark.parametrize("size_kind", ["file", "total"])
def test_manifest_rejects_oversized_rules_before_download(
    size_kind: str,
) -> None:
    if size_kind == "file":
        files = {"python/large.yaml": b"x" * (MAX_FILE_BYTES + 1)}
    else:
        file_count = MAX_TREE_BYTES // MAX_FILE_BYTES + 1
        content = b"x" * MAX_FILE_BYTES
        files = {f"python/files/{index:02d}.yaml": content for index in range(file_count)}
    files["LICENSE"] = b"license\n"

    with pytest.raises(ValidationError):
        semgrep_lock_for_files(files)


@pytest.mark.parametrize(
    "name",
    [
        "python/security/rule.py", "setup.py", "python/rule.test.yaml",
        "python/rule.fixed.yml", "javascript/rule.yaml", "python/README.md",
        "python/.hidden.yaml", "python/../rule.yaml", "python/rule.yaml.py",
    ],
)
def test_semgrep_manifest_rejects_nonrules_before_any_download(name: str) -> None:
    with pytest.raises(ValidationError):
        semgrep_lock_for_files({"LICENSE": b"license\n", name: b"inert fixture\n"})


def test_license_is_verified_with_the_rules(
    tmp_path: Path, locked_rules: tuple[SemgrepLock, Path]
) -> None:
    lock, rules = locked_rules
    (rules.parent / "LICENSE").write_bytes(b"changed\n")
    with pytest.raises(RuntimeError, match="rules are invalid"):
        load_locked_rules_directory(lock, cache_root=tmp_path)


def test_unlisted_fixture_is_rejected_without_reading_it(
    tmp_path: Path, locked_rules: tuple[SemgrepLock, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    from codeguard_evals import artifacts

    lock, rules = locked_rules
    (rules / "unlisted.py").write_bytes(b"inert fixture\n")
    monkeypatch.setattr(
        artifacts, "read_bounded", lambda *a, **kw: pytest.fail("unexpected file read")
    )
    with pytest.raises(RuntimeError, match="rules are invalid"):
        load_locked_rules_directory(lock, cache_root=tmp_path)


def test_missing_rules_names_the_benchmark_preparation_command(
    tmp_path: Path,
) -> None:
    with pytest.raises(FileNotFoundError) as error:
        load_locked_rules_directory(cache_root=tmp_path)

    assert "codeguard_evals.prefetch --benchmark securityeval --stage scan" in str(error.value)


def test_cache_root_rejects_symlinks_and_nonprivate_permissions(
    tmp_path: Path,
) -> None:
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)

    with pytest.raises(RuntimeError, match="rules are invalid"):
        load_locked_rules_directory(cache_root=linked)

    real.chmod(0o755)
    with pytest.raises(RuntimeError, match="permissions"):
        load_locked_rules_directory(cache_root=real)


@pytest.mark.parametrize(
    "mutation",
    ["checkout-symlink", "rules-file", "rules-symlink"],
)
def test_rejects_symlinked_checkout_or_invalid_rules_root(
    mutation: str,
    tmp_path: Path,
) -> None:
    checkout, rules = _cached_checkout(tmp_path)
    if mutation == "checkout-symlink":
        rules.rmdir()
        checkout.rmdir()
        external = tmp_path / "external"
        (external / SEMGREP_LOCK.rules.subdirectory).mkdir(parents=True)
        checkout.symlink_to(external, target_is_directory=True)
    else:
        rules.rmdir()
        if mutation == "rules-file":
            rules.write_text("not a directory\n")
        else:
            rules.symlink_to(tmp_path, target_is_directory=True)

    with pytest.raises(RuntimeError, match="rules are invalid"):
        load_locked_rules_directory(cache_root=tmp_path)
