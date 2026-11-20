"""Supply-chain boundaries using inert fixtures, without upstream code execution."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
from email.message import Message
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import HTTPSHandler, build_opener
from urllib.response import addinfourl

import pytest
from pydantic import ValidationError

from codeguard_evals import artifacts
from codeguard_evals.artifact_locks import (
    GitFilesLock,
    load_files_lock,
)
from codeguard_evals.artifacts import (
    prefetch_files,
    verify_files,
)


def locked_files() -> tuple[GitFilesLock, dict[str, bytes]]:
    files = {"LICENSE": b"test license\n", "runtime/rules.yaml": b"rules: []\n"}
    digest = hashlib.sha256()
    pins = {}
    for name, raw in sorted(files.items()):
        encoded = name.encode()
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
        pins[name] = {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}
    lock = GitFilesLock.model_validate(
        {
            "schema_version": 1,
            "repository": "https://github.com/example/detector",
            "commit": "a" * 40,
            "tree_sha256": digest.hexdigest(),
            "files": pins,
        }
    )
    return lock, files


def fake_downloads(monkeypatch, lock, files):
    requested = []
    prefix = f"https://raw.githubusercontent.com/example/detector/{lock.commit}/"

    class Opener:
        def open(self, url, timeout):
            assert url.startswith(prefix) and timeout == 30
            name = url.removeprefix(prefix)
            requested.append(name)
            return io.BytesIO(files[name])

    monkeypatch.setattr(artifacts, "build_opener", lambda *args: Opener())
    return requested


def cached_files(tmp_path):
    lock, files = locked_files()
    cache = tmp_path / "cache"
    cache.mkdir(mode=0o700)
    root = cache / lock.commit
    for name, raw in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    return lock, cache, root


def test_prefetch_downloads_only_pinned_paths_and_verifies_cache_offline(
    tmp_path, monkeypatch
):
    lock, files = locked_files()
    requested = fake_downloads(monkeypatch, lock, files)
    cache = tmp_path / "cache"
    previous_umask = os.umask(0o077)
    try:
        root = prefetch_files(lock, cache)
    finally:
        os.umask(previous_umask)
    assert requested == sorted(files)
    assert root == cache / lock.commit
    assert {
        p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()
    } == set(files)
    assert cache.stat().st_mode & 0o777 == 0o700
    assert (root / "runtime").stat().st_mode & 0o777 == 0o755
    assert (root / "runtime/rules.yaml").stat().st_mode & 0o777 == 0o444

    def reject_network(*args):
        pytest.fail("Cached/runtime verification must not use the network")

    monkeypatch.setattr(artifacts, "build_opener", reject_network)
    assert prefetch_files(lock, cache) == verify_files(lock, cache) == root


@pytest.mark.parametrize(
    "damage", ["wrong-bytes", "truncated", "oversized", "network", "wrong-tree"]
)
def test_failed_preparation_never_publishes_or_leaves_partial_files(
    tmp_path, monkeypatch, damage
):
    lock, files = locked_files()
    name = "runtime/rules.yaml"  # Fail after the first file has been downloaded.
    if damage == "wrong-bytes":
        files[name] = b"x" * len(files[name])
    elif damage == "truncated":
        files[name] = files[name][:-1]
    elif damage == "oversized":
        files[name] += b"x" * 1024
    elif damage == "wrong-tree":
        lock = lock.model_copy(update={"tree_sha256": "0" * 64})
    fake_downloads(monkeypatch, lock, files)
    if damage == "network":

        class FailingOpener:
            def open(self, url, timeout):
                if url.endswith("LICENSE"):
                    return io.BytesIO(files["LICENSE"])
                raise HTTPError(url, 503, "unavailable", {}, None)

        monkeypatch.setattr(artifacts, "build_opener", lambda *args: FailingOpener())
    cache = tmp_path / "cache"
    with pytest.raises((ValueError, OSError)):
        prefetch_files(lock, cache)
    assert list(cache.iterdir()) == []


@pytest.mark.parametrize(
    "mutation",
    [
        "changed",
        "missing",
        "extra",
        "empty-dir",
        "symlink",
        "dir-symlink",
        "fifo",
        "commit-symlink",
        "cache-symlink",
        "permissions",
        "wrong-commit",
    ],
)
def test_cache_rejects_mutation_without_downloading_or_repairing(
    tmp_path, monkeypatch, mutation
):
    lock, cache, root = cached_files(tmp_path)
    target = root / "runtime/rules.yaml"
    if mutation == "changed":
        target.write_bytes(b"changed\n")
    elif mutation == "missing":
        target.unlink()
    elif mutation == "extra":
        (root / "example.php").write_bytes(b"unused example")
    elif mutation == "empty-dir":
        (root / "unlisted").mkdir()
    elif mutation == "symlink":
        target.unlink()
        target.symlink_to(root / "LICENSE")
    elif mutation == "dir-symlink":
        (root / "runtime").rename(root / "moved")
        (root / "runtime").symlink_to(root / "moved", target_is_directory=True)
    elif mutation == "fifo":
        target.unlink()
        os.mkfifo(target)
    elif mutation in ("commit-symlink", "cache-symlink"):
        original = root if mutation == "commit-symlink" else cache
        moved = tmp_path / "moved"
        original.rename(moved)
        original.symlink_to(moved, target_is_directory=True)
    elif mutation == "permissions":
        cache.chmod(0o755)
    else:
        root.rename(cache / ("b" * 40))

    def reject_network(*args):
        pytest.fail("An invalid existing cache must not be silently replaced")

    monkeypatch.setattr(artifacts, "build_opener", reject_network)
    with pytest.raises((ValueError, FileNotFoundError)):
        verify_files(lock, cache)
    if mutation != "wrong-commit":
        with pytest.raises(ValueError):
            prefetch_files(lock, cache)


@pytest.mark.parametrize(
    "name",
    [
        "../escape",
        "/absolute",
        "a/../b",
        "a/./b",
        "a//b",
        "a\\b",
        "a?token=x",
        "a%2fb",
        ".git/config",
    ],
)
def test_manifest_rejects_unsafe_paths(name):
    lock, _ = locked_files()
    value = lock.model_dump()
    value["files"][name] = value["files"].pop("LICENSE")
    with pytest.raises(ValidationError):
        GitFilesLock.model_validate(value)


@pytest.mark.parametrize(
    "mutation", ["branch", "url", "overlap", "case", "size", "hash", "field", "schema"]
)
def test_manifest_rejects_invalid_source_and_file_contracts(mutation):
    lock, _ = locked_files()
    value = lock.model_dump()
    if mutation == "branch":
        value["commit"] = "main"
    elif mutation == "url":
        value["repository"] = "https://attacker.invalid/example/detector"
    elif mutation == "overlap":
        value["files"]["runtime"] = copy.deepcopy(value["files"]["LICENSE"])
    elif mutation == "case":
        value["files"]["license"] = copy.deepcopy(value["files"]["LICENSE"])
    elif mutation == "size":
        value["files"]["LICENSE"]["size"] = artifacts.MAX_FILE_BYTES + 1
    elif mutation == "hash":
        value["files"]["LICENSE"]["sha256"] = "invalid"
    elif mutation == "field":
        value["run"] = "untrusted setup command"
    else:
        value["schema_version"] = 2
    with pytest.raises(ValidationError):
        GitFilesLock.model_validate(value)


def test_tracked_manifest_rejects_duplicate_keys_and_links(tmp_path):
    lock, _ = locked_files()
    path = tmp_path / "lock.json"
    path.write_text(json.dumps(lock.model_dump()))
    assert load_files_lock(path) == lock
    path.write_text('{"commit":"' + lock.commit + '",' + path.read_text()[1:])
    with pytest.raises(ValueError, match="duplicate"):
        load_files_lock(path)
    link = tmp_path / "linked.json"
    link.symlink_to(path)
    with pytest.raises(OSError):
        load_files_lock(link)


@pytest.mark.parametrize("kind", ["detector", "dataset"])
def test_downloads_reject_redirects_before_contacting_a_different_url(
    tmp_path, monkeypatch, kind
):
    lock, _ = locked_files()
    requested = []

    class RedirectingHTTPS(HTTPSHandler):
        def https_open(self, request):
            requested.append(request.full_url)
            headers = Message()
            headers["Location"] = "https://attacker.invalid/redirected"
            response = addinfourl(io.BytesIO(b""), headers, request.full_url, 302)
            response.msg = "Found"
            return response

    monkeypatch.setattr(
        artifacts,
        "build_opener",
        lambda policy: build_opener(policy, RedirectingHTTPS()),
    )
    cache = tmp_path / "cache"
    if kind == "detector":

        def prepare():
            return prefetch_files(lock, cache)

        expected_url = (
            f"https://raw.githubusercontent.com/example/detector/{lock.commit}/LICENSE"
        )
    else:
        from codeguard_evals.cyberseceval import dataset

        def prepare():
            return dataset.prefetch_dataset(cache)

        expected_url = f"https://raw.githubusercontent.com/{dataset.REPOSITORY}/{dataset.REVISION}/{dataset.DATASET_FILE}"
    with pytest.raises(ValueError, match="redirect"):
        prepare()
    assert requested == [expected_url]
    assert list(cache.iterdir()) == []


@pytest.mark.parametrize("matching", [True, False])
def test_concurrent_publication_is_verified_without_replacing_existing_files(
    tmp_path, monkeypatch, matching
):
    lock, files = locked_files()
    fake_downloads(monkeypatch, lock, files)
    cache = tmp_path / "cache"
    rename = Path.rename

    def publish_other_copy(staging, destination):
        for name, raw in files.items():
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw if matching else b"changed")
        return rename(staging, destination)

    monkeypatch.setattr(Path, "rename", publish_other_copy)
    if matching:
        assert prefetch_files(lock, cache) == cache / lock.commit
    else:
        with pytest.raises(ValueError, match="pin"):
            prefetch_files(lock, cache)
        assert (cache / lock.commit / "LICENSE").read_bytes() == b"changed"
    assert list(cache.iterdir()) == [cache / lock.commit]
