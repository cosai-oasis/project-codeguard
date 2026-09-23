"""Verify operator rules and prefetch the pinned benchmark dataset."""

from __future__ import annotations

from codeguard_evals.securityeval.dataset import prefetch_securityeval
from codeguard_evals.semgrep_artifacts import load_locked_rules_directory


def main() -> int:
    rules_path = load_locked_rules_directory()
    dataset_path = prefetch_securityeval()
    print(f"Verified pinned SecurityEval dataset: {dataset_path}")
    print(f"Verified pinned Semgrep rules: {rules_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
