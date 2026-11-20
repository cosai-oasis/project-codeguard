"""Pinned Git artifacts: bounded, offline verification and explicit preparation.

Runtime callers only verify local files. Explicit preparation downloads
hash-locked files without running Git or upstream code.
"""

from __future__ import annotations

import errno
import hashlib
import os
import re
import stat
import tempfile
from collections.abc import Iterable, Mapping
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING
from urllib.request import HTTPRedirectHandler, build_opener

from codeguard_evals.safe_io import read_bounded

if TYPE_CHECKING:
    from codeguard_evals.artifact_locks import FilePin, GitFilesLock

MAX_FILE_BYTES = 256 * 1024
MAX_TREE_BYTES = 8 * 1024 * 1024
MAX_TREE_ENTRIES = 8192


def validate_artifact_path(value: str) -> str:
    if not re.fullmatch(
        r"[A-Za-z0-9_-][A-Za-z0-9_.-]*(/[A-Za-z0-9_-][A-Za-z0-9_.-]*)*", value
    ):
        raise ValueError("Artifact paths must be canonical relative file names")
    return value


def files_sha256(root: Path, names: Iterable[str]) -> str:
    """Fingerprint an explicit, ordered set of local implementation files."""
    digest = hashlib.sha256()
    for name in names:
        path = name.encode("utf-8")
        raw = read_bounded(root / name, MAX_FILE_BYTES, label="Implementation file")
        digest.update(len(path).to_bytes(8, "big"))
        digest.update(path)
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return digest.hexdigest()


def require_directory(path: Path, *, private: bool = False) -> None:
    details = path.lstat()
    if not stat.S_ISDIR(details.st_mode):
        raise ValueError(
            f"Artifact directory must be a real directory, not a link: {path}"
        )
    if private and stat.S_IMODE(details.st_mode) != 0o700:
        raise ValueError(f"Artifact cache permissions must be 0700: {path}")


def cached_directory(cache_root: Path, relative: str) -> Path:
    """Check each directory below a private cache without following links."""
    require_directory(cache_root, private=True)
    path = cache_root
    for part in PurePosixPath(validate_artifact_path(relative)).parts:
        path /= part
        require_directory(path)
    return path


def tree_sha256(root: Path, *, files: Mapping[str, FilePin] | None = None) -> str:
    """Hash framed relative paths and bytes; optionally enforce an exact manifest."""
    require_directory(root)
    allowed_dirs = (
        {parent.as_posix() for name in files for parent in PurePosixPath(name).parents}
        if files is not None
        else None
    )
    paths: dict[str, Path] = {}

    def walk_error(error: OSError) -> None:
        raise error

    entries = 0
    # os.walk also supports the scanner's Python 3.12 and surfaces read errors.
    for directory, directories, names in os.walk(
        root, followlinks=False, onerror=walk_error
    ):
        for name in directories + names:
            entries += 1
            if entries > MAX_TREE_ENTRIES:
                raise ValueError("Artifact exceeds the entry limit")
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            mode = path.lstat().st_mode
            if stat.S_ISDIR(mode):
                if allowed_dirs is not None and relative not in allowed_dirs:
                    raise ValueError(f"Unexpected artifact directory: {relative}")
            elif stat.S_ISREG(mode):
                paths[relative] = path
            else:
                raise ValueError(
                    f"Artifact contains a link or special file: {relative}"
                )
    if files is not None and paths.keys() != files.keys():
        raise ValueError("Artifact has missing or unexpected files")

    digest = hashlib.sha256()
    total = 0
    for name in sorted(paths, key=lambda value: value.encode("utf-8")):
        raw = read_bounded(paths[name], MAX_FILE_BYTES, label="Artifact file")
        total += len(raw)
        if total > MAX_TREE_BYTES:
            raise ValueError("Artifact exceeds the total size limit")
        if files is not None:
            files[name].verify(raw, name)
        encoded = name.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return digest.hexdigest()


def verify_tree(
    root: Path, expected: str, *, files: Mapping[str, FilePin] | None = None
) -> Path:
    if tree_sha256(root, files=files) != expected:
        raise ValueError("Artifact tree does not match its SHA-256 pin")
    return root


def verify_files(lock: GitFilesLock, cache_root: Path) -> Path:
    """Offline-only verification; never download or repair an invalid cache."""
    root = cached_directory(cache_root, lock.commit)
    return verify_tree(root, lock.tree_sha256, files=lock.files)


def publish_verified_tree(
    staging: Path,
    destination: Path,
    expected: str,
    *,
    files: Mapping[str, FilePin] | None = None,
) -> Path:
    """Publish a complete cache tree, accepting only a verified concurrent winner.

    Callers create the staging directory inside the private destination cache.
    Normalize access for the scanner's UID; the containing host cache remains private.
    """

    verify_tree(staging, expected, files=files)
    for path in staging.rglob("*"):
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            path.chmod(0o755)
        elif stat.S_ISREG(mode):
            path.chmod(0o444)
        else:
            raise ValueError(f"Artifact contains a link or special file: {path}")
    staging.chmod(0o755)
    try:
        staging.rename(destination)
    except OSError as error:
        if error.errno not in (errno.EEXIST, errno.ENOTEMPTY):
            raise
        verify_tree(destination, expected, files=files)
    return destination


class _NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Artifact downloads must not redirect")


def download_bytes(url: str, maximum: int, *, timeout: int = 30) -> bytes:
    """Read a bounded GitHub artifact over verified HTTPS, without redirects."""
    if not url.startswith("https://raw.githubusercontent.com/") or maximum < 0:
        raise ValueError("Invalid artifact download request")
    with build_opener(_NoRedirects()).open(url, timeout=timeout) as response:
        raw = response.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("Artifact download exceeds its size limit")
    return raw


def prefetch_files(lock: GitFilesLock, cache_root: Path) -> Path:
    """Download only allowlisted files at a full commit, then publish atomically.

    HTTPS certificate checks stay enabled. Each response must match its pinned
    length and hash before it is saved. Existing caches are verified, not replaced.
    """
    cache_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    require_directory(cache_root, private=True)
    destination = cache_root / lock.commit
    if destination.exists() or destination.is_symlink():
        return verify_files(lock, cache_root)

    repository = lock.repository.removeprefix("https://github.com/")
    with tempfile.TemporaryDirectory(prefix=".fetch-", dir=cache_root) as temporary:
        staging = Path(temporary)
        for name, pin in sorted(lock.files.items()):
            url = f"https://raw.githubusercontent.com/{repository}/{lock.commit}/{name}"
            raw = download_bytes(url, pin.size)
            pin.verify(raw, name)
            target = staging / name
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            with target.open("xb") as output:
                output.write(raw)
        return publish_verified_tree(
            staging, destination, lock.tree_sha256, files=lock.files
        )
