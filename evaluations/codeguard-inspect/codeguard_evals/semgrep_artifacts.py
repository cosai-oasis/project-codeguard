"""Load the exact Semgrep image and rules-checkout contract."""

from __future__ import annotations

import hashlib
import stat
from functools import cache
from pathlib import Path
from typing import Annotated, Final, Literal, get_args

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from codeguard_evals.safe_io import load_strict_json, read_bounded

SEMGREP_LOCK_PATH: Final = Path(__file__).parents[1] / "semgrep.lock.json"
SEMGREP_RULES_CACHE_ROOT: Final = (
    Path(__file__).parents[1]
    / ".cache"
    / "codeguard-evals"
    / "semgrep-rules"
)
MAX_SEMGREP_LOCK_BYTES: Final = 4096
MAX_RULE_FILE_BYTES: Final = 256 * 1024
MAX_RULE_TREE_BYTES: Final = 8 * 1024 * 1024
SEMGREP_ENGINE: Final = "OSS"
SEMGREP_RULE_ID_REWRITING: Final = True
SemgrepFindingSubcategory = Literal["audit", "secure default", "vuln"]
ALL_SEMGREP_SUBCATEGORIES: Final[frozenset[str]] = frozenset(
    get_args(SemgrepFindingSubcategory)
)
SemgrepConfidence = Literal["HIGH", "MEDIUM", "LOW"]
ALL_SEMGREP_CONFIDENCES: Final[frozenset[str]] = frozenset(
    get_args(SemgrepConfidence)
)
SemgrepSeverity = Literal[
    "ERROR",
    "WARNING",
    "EXPERIMENT",
    "INVENTORY",
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFO",
]
ALL_SEVERITIES: Final[frozenset[str]] = frozenset(get_args(SemgrepSeverity))
EXCLUDED_SEVERITIES: Final[frozenset[str]] = frozenset(
    {"EXPERIMENT", "INVENTORY"}
)
MEASURED_SEVERITIES: Final[frozenset[str]] = ALL_SEVERITIES - EXCLUDED_SEVERITIES


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class SemgrepFinding(_StrictModel):
    """One normalized security finding stored in evaluation evidence."""

    rule_id: Annotated[str, Field(min_length=1)]
    severity: SemgrepSeverity
    line: Annotated[int, Field(ge=1)]
    subcategory: SemgrepFindingSubcategory
    confidence: SemgrepConfidence

    def record(self) -> dict[str, object]:
        return self.model_dump(mode="json")


class SemgrepImageLock(_StrictModel):
    repository: Literal["docker.io/semgrep/semgrep"]
    version: Annotated[
        str,
        Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$"),
    ]
    index_digest: Annotated[
        str,
        Field(min_length=71, max_length=71, pattern=r"^sha256:[0-9a-f]{64}$"),
    ]

    @property
    def tag(self) -> str:
        return f"{self.version}-nonroot"

    @property
    def tagged_reference(self) -> str:
        return f"{self.repository}:{self.tag}"

    @property
    def locked_reference(self) -> str:
        return f"{self.tagged_reference}@{self.index_digest}"


class SemgrepRulesLock(_StrictModel):
    repository: Literal["https://github.com/semgrep/semgrep-rules"]
    commit: Annotated[
        str,
        Field(min_length=40, max_length=40, pattern=r"^[0-9a-f]{40}$"),
    ]
    subdirectory: Literal["python"]
    finding_category: Literal["security"]
    tree_sha256: Annotated[
        str,
        Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$"),
    ]


class SemgrepLock(_StrictModel):
    schema_version: Literal[3]
    image: SemgrepImageLock
    rules: SemgrepRulesLock


def load_semgrep_lock(path: Path = SEMGREP_LOCK_PATH) -> SemgrepLock:
    """Load the tracked scanner lock with a strict, bounded schema."""
    try:
        raw = read_bounded(path, MAX_SEMGREP_LOCK_BYTES, label="Semgrep lock")
        return SemgrepLock.model_validate(load_strict_json(raw))
    except (OSError, UnicodeDecodeError, ValueError, ValidationError):
        raise RuntimeError("Semgrep artifact lock is invalid") from None


SEMGREP_LOCK: Final = load_semgrep_lock()
SEMGREP_IMAGE_REFERENCE: Final = SEMGREP_LOCK.image.locked_reference


def semgrep_rules_checkout_path(
    lock: SemgrepLock = SEMGREP_LOCK,
    *,
    cache_root: Path = SEMGREP_RULES_CACHE_ROOT,
) -> Path:
    """Return the stable cache path for the pinned Git checkout."""
    return cache_root / lock.rules.commit


def load_locked_rules_directory(
    lock: SemgrepLock = SEMGREP_LOCK,
    *,
    cache_root: Path = SEMGREP_RULES_CACHE_ROOT,
) -> Path:
    """Validate and return the operator-provided Python rules directory."""
    try:
        cache_details = cache_root.lstat()
    except FileNotFoundError:
        raise FileNotFoundError(
            "The operator-provided Semgrep rules checkout is missing. Prepare "
            "the pinned checkout described in README.md before prefetch or "
            "evaluation."
        ) from None
    except OSError:
        raise RuntimeError("Cached Semgrep rules cache is invalid") from None
    if not stat.S_ISDIR(cache_details.st_mode):
        raise RuntimeError("Cached Semgrep rules cache is invalid")
    if stat.S_IMODE(cache_details.st_mode) != 0o700:
        raise RuntimeError("Cached Semgrep rules permissions are invalid")

    checkout = semgrep_rules_checkout_path(lock, cache_root=cache_root)
    rules = checkout / lock.rules.subdirectory
    try:
        checkout_details = checkout.lstat()
        rules_details = rules.lstat()
    except FileNotFoundError:
        raise FileNotFoundError(
            "The operator-provided Semgrep rules checkout is missing. Prepare "
            "the pinned checkout described in README.md before prefetch or "
            "evaluation."
        ) from None
    except OSError:
        raise RuntimeError("Cached Semgrep rules are invalid") from None
    if not stat.S_ISDIR(checkout_details.st_mode) or not stat.S_ISDIR(
        rules_details.st_mode
    ):
        raise RuntimeError("Cached Semgrep rules are invalid")
    try:
        tree_sha256 = _rules_tree_sha256(rules)
    except (OSError, UnicodeEncodeError, ValueError):
        raise RuntimeError("Cached Semgrep rules are invalid") from None
    if tree_sha256 != lock.rules.tree_sha256:
        raise RuntimeError("Cached Semgrep rules are invalid")
    return rules


def _rules_tree_sha256(rules: Path) -> str:
    """Hash every stable regular file in the mounted rules tree."""
    files: list[tuple[bytes, Path]] = []
    for path in rules.rglob("*", recurse_symlinks=False):
        details = path.lstat()
        if stat.S_ISLNK(details.st_mode):
            raise ValueError("Semgrep rules tree contains a symlink")
        if stat.S_ISDIR(details.st_mode):
            continue
        if not stat.S_ISREG(details.st_mode):
            raise ValueError("Semgrep rules tree contains a special file")
        relative_raw = path.relative_to(rules).as_posix().encode("utf-8")
        files.append((relative_raw, path))

    digest = hashlib.sha256()
    total_bytes = 0
    for relative_raw, path in sorted(files, key=lambda item: item[0]):
        content = read_bounded(
            path,
            MAX_RULE_FILE_BYTES,
            label="Semgrep rules file",
        )
        total_bytes += len(content)
        if total_bytes > MAX_RULE_TREE_BYTES:
            raise ValueError("Semgrep rules tree exceeds the total size limit")
        digest.update(len(relative_raw).to_bytes(8, "big"))
        digest.update(relative_raw)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


@cache
def load_default_locked_rules_directory() -> Path:
    """Validate the operator checkout once per evaluation process."""
    return load_locked_rules_directory()


def semgrep_provenance(lock: SemgrepLock = SEMGREP_LOCK) -> dict[str, object]:
    """Return stable scanner provenance suitable for task and score metadata."""
    return {
        "version": lock.image.version,
        "engine": SEMGREP_ENGINE,
        "execution": "inspect-sandbox:semgrep",
        "image": lock.image.tagged_reference,
        "image_digest": lock.image.index_digest,
        "rules_repository": lock.rules.repository,
        "rules_commit": lock.rules.commit,
        "rules_subdirectory": lock.rules.subdirectory,
        "rules_tree_sha256": lock.rules.tree_sha256,
        "finding_category": lock.rules.finding_category,
        "measured_subcategories": sorted(ALL_SEMGREP_SUBCATEGORIES),
        "measured_severities": sorted(MEASURED_SEVERITIES),
        "rule_id_rewriting": SEMGREP_RULE_ID_REWRITING,
    }
