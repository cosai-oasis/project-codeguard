"""Host-side schemas for reviewed artifact pins; not imported by scanner workers."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Annotated, Final, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

from codeguard_evals.artifacts import (
    MAX_FILE_BYTES,
    MAX_TREE_BYTES,
    validate_artifact_path,
)
from codeguard_evals.safe_io import load_strict_json, read_bounded

MAX_FILES_LOCK_BYTES: Final = 64 * 1024

SHA256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$", min_length=64, max_length=64)]
GitCommit = Annotated[
    str, Field(pattern=r"^[0-9a-f]{40}$", min_length=40, max_length=40)
]


RelativePath = Annotated[
    str, Field(max_length=256), AfterValidator(validate_artifact_path)
]


class GitTreeLock(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    repository: Annotated[
        str,
        Field(
            pattern=r"^https://github\.com/[A-Za-z0-9_-][A-Za-z0-9_.-]*/[A-Za-z0-9_-][A-Za-z0-9_.-]*$"
        ),
    ]
    commit: GitCommit
    tree_sha256: SHA256


class FilePin(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    sha256: SHA256
    size: Annotated[int, Field(ge=0, le=MAX_FILE_BYTES)]

    def verify(self, raw: bytes, name: str) -> None:
        if len(raw) != self.size or hashlib.sha256(raw).hexdigest() != self.sha256:
            raise ValueError(
                f"Artifact file does not match its size/SHA-256 pin: {name}"
            )


class GitFilesLock(GitTreeLock):
    schema_version: Literal[1]
    files: Annotated[dict[RelativePath, FilePin], Field(min_length=1, max_length=256)]

    @model_validator(mode="after")
    def consistent_paths_and_size(self) -> GitFilesLock:
        # Reject aliases on case-insensitive filesystems and file/directory clashes.
        paths = {name.casefold() for name in self.files}
        if len(paths) != len(self.files) or any(
            parent.as_posix().casefold() in paths
            for name in self.files
            for parent in PurePosixPath(name).parents
        ):
            raise ValueError("Artifact paths overlap")
        if sum(pin.size for pin in self.files.values()) > MAX_TREE_BYTES:
            raise ValueError("Artifact exceeds the total size limit")
        return self


def load_files_lock(path: Path) -> GitFilesLock:
    """Read a tracked manifest, never a manifest supplied by the download server."""
    return GitFilesLock.model_validate(
        load_strict_json(
            read_bounded(path, MAX_FILES_LOCK_BYTES, label="Artifact manifest")
        )
    )


def manifest_sha256(lock: GitFilesLock) -> str:
    """Bind the complete manifest independently of JSON whitespace or key order."""
    raw = json.dumps(lock.model_dump(), sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()
