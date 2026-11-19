"""Load the Semgrep image pin and SecurityEval-specific rules contract."""

from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Annotated, Final, Literal, get_args

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from codeguard_evals.artifact_locks import (
    FilePin,
    GitFilesLock,
    RelativePath,
)
from codeguard_evals.artifacts import (
    verify_files,
)
from codeguard_evals.safe_io import load_strict_json, read_bounded

SEMGREP_LOCK_PATH: Final = Path(__file__).parents[2] / "semgrep.lock.json"
SEMGREP_RULES_CACHE_ROOT: Final = (
    Path(__file__).parents[2]
    / ".cache"
    / "codeguard-evals"
    / "semgrep-rules-only"
)
MAX_SEMGREP_LOCK_BYTES: Final = 128 * 1024
SEMGREP_ENGINE: Final = "OSS"
SEMGREP_RULE_ID_REWRITING: Final = True
SemgrepFindingSubcategory = Literal["audit", "secure default", "vuln"]
ALL_SEMGREP_SUBCATEGORIES: Final[frozenset[str]] = frozenset(
    get_args(SemgrepFindingSubcategory)
)
SemgrepConfidence = Literal["HIGH", "MEDIUM", "LOW"]
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


class SemgrepRulesLock(GitFilesLock):
    repository: Literal["https://github.com/semgrep/semgrep-rules"]
    subdirectory: Literal["python"]
    finding_category: Literal["security"]
    # Semgrep's rule catalog exceeds the shared file-count limit. Shared path
    # and total-size validation still applies.
    files: Annotated[dict[RelativePath, FilePin], Field(min_length=2, max_length=512)]

    @model_validator(mode="after")
    def rules_and_license_only(self) -> SemgrepRulesLock:
        if "LICENSE" not in self.files:
            raise ValueError("Semgrep bundle requires rules and the upstream license")
        for name in self.files:
            if name == "LICENSE":
                continue
            path = PurePosixPath(name)
            if (
                not name.startswith(f"{self.subdirectory}/")
                or path.suffix not in {".yaml", ".yml"}
                or path.stem.endswith((".test", ".fixed"))
            ):
                raise ValueError(
                    "Semgrep manifest must contain only Python rule definitions and LICENSE"
                )
        return self


class SemgrepLock(_StrictModel):
    schema_version: Literal[4]
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
    """Return the rules-only bundle path, separate from legacy full checkouts."""
    return cache_root / lock.rules.commit


def rules_access_error(error: PermissionError, cache_root: Path) -> RuntimeError:
    return RuntimeError(
        "Access to pinned Semgrep rules was denied. Check filesystem permissions "
        f"and endpoint-protection history for {error.filename or cache_root}."
    )


def load_locked_rules_directory(
    lock: SemgrepLock = SEMGREP_LOCK,
    *,
    cache_root: Path = SEMGREP_RULES_CACHE_ROOT,
) -> Path:
    """Validate and return SecurityEval's cached Python rules, without downloads."""
    try:
        # Verify the exact manifest, including LICENSE, before exposing any rules.
        root = verify_files(lock.rules, cache_root)
        return root / lock.rules.subdirectory
    except FileNotFoundError:
        raise FileNotFoundError(
            "Prepare the pinned SecurityEval rules with: python -m "
            "codeguard_evals.prefetch --benchmark securityeval --stage scan"
        ) from None
    except PermissionError as error:
        raise rules_access_error(error, cache_root) from error
    except (OSError, ValueError) as error:
        raise RuntimeError(f"Cached Semgrep rules are invalid: {error}") from None


def load_default_locked_rules_directory() -> Path:
    """Validate cached rules on every preflight, without memoization."""
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
