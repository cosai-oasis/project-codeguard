from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from codeguard_evals.semgrep_artifacts import (
    COUNTED_SEVERITIES,
    SEMGREP_COUNTED_SUBCATEGORIES,
    SEMGREP_IMAGE_REFERENCE,
    SEMGREP_LOCK,
    SEMGREP_RULES_SOURCE,
    SemgrepFinding,
    SemgrepLock,
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
    head: str | None = None,
    checkout_mode: int = 0o700,
) -> tuple[Path, Path]:
    root.mkdir(mode=0o700, exist_ok=True)
    root.chmod(0o700)
    checkout = semgrep_rules_checkout_path(lock, cache_root=root)
    checkout.mkdir(mode=checkout_mode)
    checkout.chmod(checkout_mode)
    git = checkout / ".git"
    git.mkdir()
    (git / "HEAD").write_text(
        f"{lock.rules.commit if head is None else head}\n",
        encoding="ascii",
    )
    rules = checkout / lock.rules.subdirectory
    rules.mkdir()
    return checkout, rules


def test_tracked_lock_pins_image_and_complete_python_rules_checkout() -> None:
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
    assert SEMGREP_LOCK.rules.selection == (
        "load=python/**/*.yaml;retain=metadata.category:security"
    )
    assert SEMGREP_LOCK.rules.source_yaml_file_count == 337
    assert SEMGREP_LOCK.rules.loaded_rule_count == 378
    assert SEMGREP_LOCK.rules.retained_rule_count == 269
    assert SEMGREP_LOCK.rules.subcategory_counts.model_dump() == {
        "audit": 135,
        "secure_default": 1,
        "vuln": 133,
    }


def test_provenance_records_loaded_and_retained_rule_contract() -> None:
    assert semgrep_provenance() == {
        "version": "1.173.0",
        "engine": "OSS",
        "execution": "inspect-sandbox:semgrep",
        "image": "docker.io/semgrep/semgrep:1.173.0-nonroot",
        "image_digest": SEMGREP_LOCK.image.index_digest,
        "rules_source": SEMGREP_RULES_SOURCE,
        "rules_repository": SEMGREP_LOCK.rules.repository,
        "rules_commit": SEMGREP_LOCK.rules.commit,
        "rules_subdirectory": "python",
        "rules_selection": (
            "load=python/**/*.yaml;retain=metadata.category:security"
        ),
        "rules_source_yaml_file_count": 337,
        "rules_loaded_rule_count": 378,
        "rules_retained_rule_count": 269,
        "rules_subcategory_counts": {
            "audit": 135,
            "secure default": 1,
            "vuln": 133,
        },
        "finding_category": "security",
        "rules_worktree_validation": "operator-trusted",
        "counted_subcategories": sorted(SEMGREP_COUNTED_SUBCATEGORIES),
        "counted_severities": sorted(COUNTED_SEVERITIES),
        "rule_id_rewriting": True,
        "rules_mutable": False,
    }


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(schema_version=2),
        lambda value: value.update(unexpected=True),
        lambda value: value["image"].update(tag="latest"),
        lambda value: value["image"].update(index_digest="sha256:bad"),
        lambda value: value["rules"].update(commit="main"),
        lambda value: value["rules"].update(subdirectory="javascript"),
        lambda value: value["rules"].update(selection="all"),
        lambda value: value["rules"].update(loaded_rule_count=1),
        lambda value: value["rules"]["subcategory_counts"].update(vuln=132),
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
    _checkout, rules = _cached_checkout(tmp_path)

    assert load_locked_rules_directory(cache_root=tmp_path) == rules


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
    ("mutation", "message"),
    [
        ("checkout-mode", "rules are invalid"),
        ("head", "rules are invalid"),
        ("git-file", "rules are invalid"),
        ("rules-symlink", "rules are invalid"),
    ],
)
def test_checkout_rejects_invalid_boundaries(
    mutation: str,
    message: str,
    tmp_path: Path,
) -> None:
    checkout, rules = _cached_checkout(tmp_path)
    if mutation == "checkout-mode":
        checkout.chmod(0o755)
    elif mutation == "head":
        (checkout / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    elif mutation == "git-file":
        git = checkout / ".git"
        (git / "HEAD").unlink()
        git.rmdir()
        git.write_text("gitdir: elsewhere\n")
    else:
        rules.rmdir()
        rules.symlink_to(tmp_path, target_is_directory=True)

    with pytest.raises(RuntimeError, match=message):
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
