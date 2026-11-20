"""SecurityEval downloads an exact rules manifest; fixtures never reach disk."""

from __future__ import annotations

import errno
import os
import subprocess
from pathlib import Path

import pytest

from codeguard_evals import artifacts, prefetch
from codeguard_evals.artifacts import tree_sha256
from codeguard_evals.graders.semgrep_artifacts import (
    SemgrepLock,
    load_locked_rules_directory,
)
from tests.conftest import semgrep_lock_for_files


Upstream = tuple[SemgrepLock, dict[str, bytes], dict[str, bytes], Path, list[str]]


@pytest.fixture
def upstream(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Upstream:
    files = {
        "LICENSE": b"fixture license\n",
        "python/security/rule.yaml": b"rules: []\r\n",
        "python/security/other.yml": b"rules: []\n",
    }
    lock = semgrep_lock_for_files(files)
    # Extra server files are harmless data and are never requested or written.
    available = {
        **files,
        "python/security/rule.py": b"inert fixture\n",
        "python/security/rule.test.yaml": b"inert fixture\n",
        "setup.py": b"inert fixture\n",
        ".gitattributes": b"inert fixture\n",
    }
    calls: list[str] = []
    prefix = f"https://raw.githubusercontent.com/semgrep/semgrep-rules/{lock.rules.commit}/"

    def download(url: str, maximum: int) -> bytes:
        assert url.startswith(prefix)
        name = url.removeprefix(prefix)
        assert name in files, f"Unallowlisted download: {name}"
        assert maximum == lock.rules.files[name].size
        calls.append(name)
        return available[name]

    monkeypatch.setattr(artifacts, "download_bytes", download)
    monkeypatch.setattr(
        subprocess, "run",
        lambda *a, **kw: pytest.fail("Prefetch must not launch Git or upstream code"),
    )
    return lock, files, available, tmp_path / "cache", calls


def test_prefetch_writes_only_verified_rules_and_license(
    upstream: Upstream, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock, files, _, cache, calls = upstream
    written: list[str] = []
    original_open = Path.open

    def track_write(path, mode="r", *args, **kwargs):
        if "x" in mode or "w" in mode or "a" in mode:
            # Include temporary files: downloading everything then deleting fixtures
            # would still trigger endpoint protection.
            relative = path.relative_to(cache)
            assert relative.parts[0].startswith(".fetch-")
            name = Path(*relative.parts[1:]).as_posix()
            assert name in files
            written.append(name)
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", track_write)
    previous_umask = os.umask(0o077)
    try:
        rules = prefetch.prefetch_securityeval_rules(lock, cache_root=cache)
    finally:
        os.umask(previous_umask)
    assert calls == written == sorted(files)
    assert tree_sha256(rules.parent) == lock.rules.tree_sha256
    assert {
        path.relative_to(rules.parent).as_posix(): path.read_bytes()
        for path in rules.parent.rglob("*") if path.is_file()
    } == files
    assert cache.stat().st_mode & 0o777 == 0o700
    assert rules.stat().st_mode & 0o777 == 0o755
    assert (rules / "security/rule.yaml").stat().st_mode & 0o777 == 0o444
    assert (rules.parent / "LICENSE").stat().st_mode & 0o777 == 0o444
    calls.clear()
    assert prefetch.prefetch_securityeval_rules(lock, cache_root=cache) == rules
    assert load_locked_rules_directory(lock, cache_root=cache) == rules
    assert calls == []


@pytest.mark.parametrize(
    "damage", ["bytes", "missing", "symlink", "extra", "license", "empty-dir"]
)
def test_invalid_existing_cache_is_not_downloaded_or_repaired(
    upstream: Upstream, damage: str
) -> None:
    lock, _, _, cache, calls = upstream
    rules = prefetch.prefetch_securityeval_rules(lock, cache_root=cache)
    path = rules / "security/rule.yaml"
    path.chmod(0o644)
    if damage == "bytes":
        path.write_bytes(b"changed")
    elif damage == "extra":
        (rules / "unused.py").write_bytes(b"inert fixture")
    elif damage == "license":
        (rules.parent / "LICENSE").chmod(0o644)
        (rules.parent / "LICENSE").write_bytes(b"changed")
    elif damage == "empty-dir":
        (rules / "unlisted").mkdir()
    else:
        path.unlink()
        if damage == "symlink":
            path.symlink_to(rules.parent / "LICENSE")
    calls.clear()
    with pytest.raises(RuntimeError, match="rules are invalid"):
        prefetch.prefetch_securityeval_rules(lock, cache_root=cache)
    assert calls == []


@pytest.mark.parametrize("damage", ["hash", "network"])
def test_failed_preparation_does_not_publish_partial_rules(
    upstream: Upstream, monkeypatch: pytest.MonkeyPatch, damage: str
) -> None:
    lock, _, _, cache, _ = upstream
    if damage == "hash":
        lock = lock.model_copy(
            update={"rules": lock.rules.model_copy(update={"tree_sha256": "0" * 64})}
        )
    else:
        def unavailable(*args, **kwargs):
            raise OSError("network unavailable")

        monkeypatch.setattr(artifacts, "download_bytes", unavailable)
    with pytest.raises((ValueError, OSError)):
        prefetch.prefetch_securityeval_rules(lock, cache_root=cache)
    assert list(cache.iterdir()) == []


def test_wrong_bytes_are_rejected_before_the_file_is_written(
    upstream: Upstream, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock, _, available, cache, _ = upstream
    available["python/security/rule.yaml"] = b"changed"
    original_open = Path.open

    def reject_write(path, mode="r", *args, **kwargs):
        if path.name == "rule.yaml" and "x" in mode:
            pytest.fail("Unverified bytes must not reach disk")
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", reject_write)
    with pytest.raises(ValueError, match="size/SHA-256 pin"):
        prefetch.prefetch_securityeval_rules(lock, cache_root=cache)
    assert list(cache.iterdir()) == []


@pytest.mark.parametrize("cached", [False, True])
def test_blocked_read_fails_closed_with_actionable_error(
    upstream: Upstream, monkeypatch: pytest.MonkeyPatch, cached: bool
) -> None:
    lock, _, _, cache, calls = upstream
    if cached:
        prefetch.prefetch_securityeval_rules(lock, cache_root=cache)
        calls.clear()
    read = artifacts.read_bounded

    def blocked(path, *args, **kwargs):
        if path.name == "rule.yaml":
            raise PermissionError(errno.EPERM, "Operation not permitted", str(path))
        return read(path, *args, **kwargs)

    monkeypatch.setattr(artifacts, "read_bounded", blocked)
    with pytest.raises(RuntimeError, match="endpoint-protection history") as error:
        prefetch.prefetch_securityeval_rules(lock, cache_root=cache)
    assert isinstance(error.value.__cause__, PermissionError)
    if cached:
        assert calls == []
    else:
        assert list(cache.iterdir()) == []


@pytest.mark.parametrize("matching", [True, False])
def test_concurrent_preparation_verifies_the_complete_bundle(
    upstream: Upstream, monkeypatch: pytest.MonkeyPatch, matching: bool
) -> None:
    lock, files, _, cache, _ = upstream
    rename = Path.rename

    def publish_other(staging, destination):
        for name, raw in files.items():
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw if matching or name != "LICENSE" else b"changed")
        return rename(staging, destination)

    monkeypatch.setattr(Path, "rename", publish_other)
    if matching:
        assert (
            prefetch.prefetch_securityeval_rules(lock, cache_root=cache)
            == cache / lock.rules.commit / "python"
        )
    else:
        with pytest.raises(ValueError, match="pin"):
            prefetch.prefetch_securityeval_rules(lock, cache_root=cache)
    assert list(cache.iterdir()) == [cache / lock.rules.commit]
