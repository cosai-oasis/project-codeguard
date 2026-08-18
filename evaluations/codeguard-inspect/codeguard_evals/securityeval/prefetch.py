"""Prefetch the one supported SecurityEval dataset revision."""

from __future__ import annotations

from codeguard_evals.securityeval.dataset import prefetch_securityeval


def main() -> int:
    path = prefetch_securityeval()
    print(f"Verified pinned SecurityEval dataset: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
