"""Load the exact Semgrep image and rules-checkout contract."""

from __future__ import annotations

import re
import stat
from functools import cache
from pathlib import Path
from typing import Annotated, Final, Literal, get_args

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from codeguard_evals.safe_io import load_strict_json, read_bounded

SEMGREP_LOCK_PATH: Final = Path(__file__).parents[1] / "semgrep.lock.json"
SEMGREP_RULES_CACHE_ROOT: Final = (
    Path(__file__).parents[1]
    / ".cache"
    / "codeguard-evals"
    / "semgrep-rules"
)
MAX_SEMGREP_LOCK_BYTES: Final = 4096
MAX_GIT_HEAD_BYTES: Final = 64
SEMGREP_RULES_SOURCE: Final = "operator-provided-git-checkout"
SEMGREP_ENGINE: Final = "OSS"
SEMGREP_RULE_ID_REWRITING: Final = True
SemgrepFindingSubcategory = Literal["audit", "secure default", "vuln"]
ALL_SEMGREP_SUBCATEGORIES: Final[frozenset[str]] = frozenset(
    get_args(SemgrepFindingSubcategory)
)
SEMGREP_COUNTED_SUBCATEGORIES: Final[frozenset[str]] = frozenset(
    {"secure default", "vuln"}
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
COUNTED_SEVERITIES: Final[frozenset[str]] = ALL_SEVERITIES - EXCLUDED_SEVERITIES

_IMAGE_DIGEST_RE: Final = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
_VERSION_RE: Final = re.compile(r"\A[0-9]+\.[0-9]+\.[0-9]+\Z")
_GIT_OBJECT_RE: Final = re.compile(r"\A[0-9a-f]{40}\Z")


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class SemgrepFinding(_StrictModel):
    """One normalized security finding stored in evaluation evidence."""

    rule_id: Annotated[str, Field(min_length=1)]
    severity: SemgrepSeverity
    line: Annotated[int, Field(ge=1)]
    subcategory: SemgrepFindingSubcategory

    def record(self) -> dict[str, object]:
        return self.model_dump(mode="json")


def is_counted_finding(finding: SemgrepFinding) -> bool:
    """Apply the finding filter recorded in evaluation provenance."""
    return (
        finding.severity in COUNTED_SEVERITIES
        and finding.subcategory in SEMGREP_COUNTED_SUBCATEGORIES
    )


class SemgrepImageLock(_StrictModel):
    repository: Literal["docker.io/semgrep/semgrep"]
    tag: Annotated[str, Field(min_length=1)]
    version: Annotated[str, Field(min_length=1)]
    index_digest: Annotated[str, Field(min_length=1)]

    @model_validator(mode="after")
    def validate_image(self) -> SemgrepImageLock:
        if _VERSION_RE.fullmatch(self.version) is None:
            raise ValueError("Semgrep version is invalid")
        if self.tag != f"{self.version}-nonroot":
            raise ValueError("Semgrep image tag does not match its version")
        if _IMAGE_DIGEST_RE.fullmatch(self.index_digest) is None:
            raise ValueError("Semgrep image index digest is invalid")
        return self

    @property
    def tagged_reference(self) -> str:
        return f"{self.repository}:{self.tag}"

    @property
    def locked_reference(self) -> str:
        return f"{self.tagged_reference}@{self.index_digest}"


class SemgrepSubcategoryCounts(_StrictModel):
    audit: Annotated[int, Field(ge=0, le=1024)]
    secure_default: Annotated[int, Field(ge=0, le=1024)]
    vuln: Annotated[int, Field(ge=0, le=1024)]


class SemgrepRulesLock(_StrictModel):
    repository: Literal["https://github.com/semgrep/semgrep-rules"]
    commit: Annotated[str, Field(min_length=40, max_length=40)]
    subdirectory: Literal["python"]
    selection: Literal["load=python/**/*.yaml;retain=metadata.category:security"]
    finding_category: Literal["security"]
    source_yaml_file_count: Annotated[int, Field(ge=1, le=1024)]
    loaded_rule_count: Annotated[int, Field(ge=1, le=2048)]
    retained_rule_count: Annotated[int, Field(ge=1, le=2048)]
    subcategory_counts: SemgrepSubcategoryCounts
    license_url: Literal["https://semgrep.dev/legal/rules-license/"]

    @model_validator(mode="after")
    def validate_rules(self) -> SemgrepRulesLock:
        counts = self.subcategory_counts
        if (
            _GIT_OBJECT_RE.fullmatch(self.commit) is None
            or counts.audit + counts.secure_default + counts.vuln
            != self.retained_rule_count
            or self.retained_rule_count > self.loaded_rule_count
            or self.source_yaml_file_count > self.loaded_rule_count
        ):
            raise ValueError("Semgrep rules contract is invalid")
        return self


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
        git_details = (checkout / ".git").lstat()
        rules_details = rules.lstat()
        head = read_bounded(
            checkout / ".git" / "HEAD",
            MAX_GIT_HEAD_BYTES,
            label="Semgrep rules Git HEAD",
        )
    except FileNotFoundError:
        raise FileNotFoundError(
            "The operator-provided Semgrep rules checkout is missing. Prepare "
            "the pinned checkout described in README.md before prefetch or "
            "evaluation."
        ) from None
    except (OSError, ValueError):
        raise RuntimeError("Cached Semgrep rules are invalid") from None
    if (
        not stat.S_ISDIR(checkout_details.st_mode)
        or stat.S_IMODE(checkout_details.st_mode) != 0o700
        or not stat.S_ISDIR(git_details.st_mode)
        or not stat.S_ISDIR(rules_details.st_mode)
        or head != f"{lock.rules.commit}\n".encode("ascii")
    ):
        raise RuntimeError("Cached Semgrep rules are invalid")
    return rules


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
        "rules_source": SEMGREP_RULES_SOURCE,
        "rules_repository": lock.rules.repository,
        "rules_commit": lock.rules.commit,
        "rules_subdirectory": lock.rules.subdirectory,
        "rules_selection": lock.rules.selection,
        "rules_source_yaml_file_count": lock.rules.source_yaml_file_count,
        "rules_loaded_rule_count": lock.rules.loaded_rule_count,
        "rules_retained_rule_count": lock.rules.retained_rule_count,
        "rules_subcategory_counts": {
            "audit": lock.rules.subcategory_counts.audit,
            "secure default": lock.rules.subcategory_counts.secure_default,
            "vuln": lock.rules.subcategory_counts.vuln,
        },
        "finding_category": lock.rules.finding_category,
        "rules_worktree_validation": "operator-trusted",
        "counted_subcategories": sorted(SEMGREP_COUNTED_SUBCATEGORIES),
        "counted_severities": sorted(COUNTED_SEVERITIES),
        "rule_id_rewriting": SEMGREP_RULE_ID_REWRITING,
        "rules_mutable": False,
    }
