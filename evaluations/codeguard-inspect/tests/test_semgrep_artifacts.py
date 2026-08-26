from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from codeguard_evals.semgrep_artifacts import (
    COUNTED_SEVERITIES,
    MAX_RULE_FILE_BYTES,
    MAX_RULE_TREE_BYTES,
    SEMGREP_COUNTED_SUBCATEGORIES,
    SEMGREP_IMAGE_REFERENCE,
    SEMGREP_LOCK,
    SemgrepFinding,
    SemgrepLock,
    _rules_tree_sha256 as calculate_rules_tree_sha256,
    is_counted_finding,
    load_locked_rules_directory,
    load_semgrep_lock,
    semgrep_provenance,
    semgrep_rules_checkout_path,
)


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
        target = rules / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    return checkout, rules


def _expected_rules_tree_sha256(
    files: dict[str, bytes],
) -> str:
    digest = hashlib.sha256()
    framed: list[tuple[bytes, bytes]] = []
    for relative, content in files.items():
        framed.append((relative.encode("utf-8"), content))
    for relative_raw, content in sorted(framed):
        digest.update(len(relative_raw).to_bytes(8, "big"))
        digest.update(relative_raw)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _lock_for_files(files: dict[str, bytes]) -> SemgrepLock:
    value = SEMGREP_LOCK.model_dump(mode="json")
    value["rules"]["tree_sha256"] = _expected_rules_tree_sha256(files)
    return SemgrepLock.model_validate(value)


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
    assert calculate_rules_tree_sha256(first) == expected
    assert calculate_rules_tree_sha256(second) == expected


def test_tracked_lock_pins_image_and_complete_python_rules_tree() -> None:
    assert SEMGREP_LOCK.schema_version == 3
    assert SEMGREP_LOCK.image.version == "1.173.0"
    assert SEMGREP_LOCK.image.tag == "1.173.0-nonroot"
    assert SEMGREP_IMAGE_REFERENCE.endswith(
        "@sha256:ae85c429145ef6b29c7a47b4cdec78304f9b325f75ce0ee4a797e841206e3e68"
    )
    assert (
        SEMGREP_LOCK.rules.repository
        == "https://github.com/semgrep/semgrep-rules"
    )
    assert (
        SEMGREP_LOCK.rules.commit
        == "40b8c63f75dc7c22c8a77482d73bfb864b146f7e"
    )
    assert SEMGREP_LOCK.rules.subdirectory == "python"
    assert SEMGREP_LOCK.rules.tree_sha256 == (
        "defc43c66fd02d51057745f530f2c181"
        "a796f69f4c29bb887c28abcb984e13c6"
    )


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
        "counted_subcategories": sorted(SEMGREP_COUNTED_SUBCATEGORIES),
        "counted_severities": sorted(COUNTED_SEVERITIES),
        "rule_id_rewriting": True,
    }


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(schema_version=2),
        lambda value: value.update(unexpected=True),
        lambda value: value["image"].update(version="latest"),
        lambda value: value["image"].update(index_digest="sha256:bad"),
        lambda value: value["rules"].update(commit="main"),
        lambda value: value["rules"].update(tree_sha256="bad"),
        lambda value: value["rules"].update(subdirectory="javascript"),
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


def test_checkout_path_is_derived_only_from_the_locked_commit(
    tmp_path: Path,
) -> None:
    assert semgrep_rules_checkout_path(cache_root=tmp_path) == (
        tmp_path / SEMGREP_LOCK.rules.commit
    )


def test_locked_rules_directory_accepts_exact_private_checkout(
    tmp_path: Path,
) -> None:
    files = {
        "z-last.yaml": b"rules: []\n",
        "nested/a-first.py": b"print('fixture')\n",
        "fixtures/rule.test.yaml": b"fixture\n",
        "README.md": b"rules documentation\n",
    }
    lock = _lock_for_files(files)
    _checkout, rules = _cached_checkout(tmp_path, lock=lock, files=files)

    assert (
        load_locked_rules_directory(lock, cache_root=tmp_path) == rules
    )


@pytest.mark.parametrize("mutation", ["content", "path", "add", "delete"])
def test_locked_rules_directory_rejects_tree_identity_changes(
    mutation: str,
    tmp_path: Path,
) -> None:
    files = {
        "one.yaml": b"rules: []\n",
        "nested/two.py": b"print('fixture')\n",
    }
    lock = _lock_for_files(files)
    _checkout, rules = _cached_checkout(tmp_path, lock=lock, files=files)
    if mutation == "content":
        (rules / "nested/two.py").write_bytes(b"print('changed')\n")
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
) -> None:
    files = {"rule.yaml": b"rules: []\n"}
    lock = _lock_for_files(files)
    _checkout, rules = _cached_checkout(tmp_path, lock=lock, files=files)
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
def test_every_regular_file_type_participates_in_the_digest(
    relative: str,
    tmp_path: Path,
) -> None:
    files = {"rule.yaml": b"rules: []\n"}
    lock = _lock_for_files(files)
    _checkout, rules = _cached_checkout(tmp_path, lock=lock, files=files)
    (rules / relative).write_bytes(b"new file\n")

    with pytest.raises(RuntimeError, match="rules are invalid"):
        load_locked_rules_directory(lock, cache_root=tmp_path)


def test_locked_rules_directory_rejects_special_file(
    tmp_path: Path,
) -> None:
    files = {"rule.yaml": b"rules: []\n"}
    lock = _lock_for_files(files)
    _checkout, rules = _cached_checkout(tmp_path, lock=lock, files=files)
    os.mkfifo(rules / "special")

    with pytest.raises(RuntimeError, match="rules are invalid"):
        load_locked_rules_directory(lock, cache_root=tmp_path)


@pytest.mark.parametrize("size_kind", ["file", "total"])
def test_locked_rules_directory_enforces_tree_size_limits(
    size_kind: str,
    tmp_path: Path,
) -> None:
    if size_kind == "file":
        files = {"large.bin": b"x" * (MAX_RULE_FILE_BYTES + 1)}
    else:
        file_count = MAX_RULE_TREE_BYTES // MAX_RULE_FILE_BYTES + 1
        content = b"x" * MAX_RULE_FILE_BYTES
        files = {
            f"files/{index:02d}.bin": content
            for index in range(file_count)
        }
    lock = _lock_for_files(files)
    _cached_checkout(tmp_path, lock=lock, files=files)

    with pytest.raises(RuntimeError, match="rules are invalid"):
        load_locked_rules_directory(lock, cache_root=tmp_path)


def test_missing_rules_names_the_operator_managed_checkout(
    tmp_path: Path,
) -> None:
    with pytest.raises(FileNotFoundError) as error:
        load_locked_rules_directory(cache_root=tmp_path)

    assert "operator-provided" in str(error.value)
    assert "README.md" in str(error.value)


def test_cache_root_rejects_symlinks_and_nonprivate_permissions(
    tmp_path: Path,
) -> None:
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)

    with pytest.raises(RuntimeError, match="cache is invalid"):
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


@pytest.mark.parametrize(
    ("finding", "expected"),
    [
        (
            SemgrepFinding(
                rule_id="a", severity="ERROR", line=1, subcategory="vuln"
            ),
            True,
        ),
        (
            SemgrepFinding(
                rule_id="b",
                severity="INFO",
                line=1,
                subcategory="secure default",
            ),
            True,
        ),
        (
            SemgrepFinding(
                rule_id="c", severity="HIGH", line=1, subcategory="audit"
            ),
            False,
        ),
        (
            SemgrepFinding(
                rule_id="d",
                severity="EXPERIMENT",
                line=1,
                subcategory="vuln",
            ),
            False,
        ),
        (
            SemgrepFinding(
                rule_id="e",
                severity="INVENTORY",
                line=1,
                subcategory="vuln",
            ),
            False,
        ),
    ],
)
def test_counted_finding_filter_is_explicit(
    finding: SemgrepFinding,
    expected: bool,
) -> None:
    assert is_counted_finding(finding) is expected
