"""Prepare the pinned artifacts required by a registered benchmark."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

import yaml

from codeguard_evals.artifacts import (
    prefetch_files,
    publish_verified_tree,
    require_directory,
)
from codeguard_evals.cyberseceval.dataset import prefetch_dataset
from codeguard_evals.graders import icd
from codeguard_evals.safe_io import read_bounded
from codeguard_evals.securityeval.dataset import prefetch_securityeval
from codeguard_evals.graders.semgrep_artifacts import (
    SEMGREP_LOCK,
    SEMGREP_RULES_CACHE_ROOT,
    SemgrepLock,
    load_locked_rules_directory,
    rules_access_error,
)


def prefetch_securityeval_rules(
    lock: SemgrepLock = SEMGREP_LOCK,
    *,
    cache_root: Path = SEMGREP_RULES_CACHE_ROOT,
) -> Path:
    """Fetch only pinned rule definitions and LICENSE, never upstream test code.

    Each response is size/hash checked before writing. Paths and rule bytes are
    unchanged so Semgrep's rule IDs and detection behavior remain stable.
    """
    try:
        destination = cache_root / lock.rules.commit
        if destination.exists() or destination.is_symlink():
            return load_locked_rules_directory(lock, cache_root=cache_root)
        root = prefetch_files(lock.rules, cache_root)
    except PermissionError as error:
        raise rules_access_error(error, cache_root) from error
    return root / lock.rules.subdirectory


def prefetch_detector(
    cache_root: Path = icd.CACHE_ROOT,
    source_cache_root: Path = icd.SOURCE_CACHE_ROOT,
) -> Path:
    """Prepare a pinned JSON bundle; the scanner never needs a YAML parser."""
    cache_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    require_directory(cache_root, private=True)
    expected = icd.ICD_LOCK.prepared_tree_sha256
    destination = cache_root / expected
    if destination.exists() or destination.is_symlink():
        return icd.verify_detector(cache_root)

    source = prefetch_files(icd.ICD_LOCK.source, source_cache_root)
    with tempfile.TemporaryDirectory(prefix=".prepare-", dir=cache_root) as temporary:
        staging = Path(temporary)
        for name, pin in sorted(icd.ICD_LOCK.source.files.items()):
            raw = read_bounded(source / name, pin.size, label="Pinned upstream rule")
            # Check the bytes we parse, even if the cache changes after prefetch.
            pin.verify(raw, name)
            path = Path(name)
            if path.suffix == ".yaml":
                path = path.with_suffix(".json")
                raw = (
                    json.dumps(
                        yaml.safe_load(raw),
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    )
                    + "\n"
                ).encode("utf-8")
            target = staging / path
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            target.write_bytes(raw)
        root = publish_verified_tree(staging, destination, expected)
    return root / icd.DETECTOR_SUBDIRECTORY


def _securityeval(stage="all"):
    if stage != "generation":
        print(
            f"Verified pinned SecurityEval Semgrep rules: {prefetch_securityeval_rules()}"
        )
    if stage != "scan":
        print(f"Verified pinned SecurityEval dataset: {prefetch_securityeval()}")


def _cyberseceval(stage="all"):
    if stage != "generation":
        print(f"Verified pinned Meta ICD JSON rules: {prefetch_detector()}")
    if stage != "scan":
        print(f"Verified pinned CyberSecEval dataset: {prefetch_dataset()}")


# Only reviewed, installed adapters can prepare artifacts. No arbitrary module loading.
PREPARERS = {"securityeval": _securityeval, "cyberseceval": _cyberseceval}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark", choices=tuple(PREPARERS), default="securityeval")
    parser.add_argument("--stage", choices=("generation", "scan", "all"), default="all")
    args = parser.parse_args(argv)
    PREPARERS[args.benchmark](args.stage)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
