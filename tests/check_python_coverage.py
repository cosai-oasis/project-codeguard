"""Require each top-level src module's own test file to cover at least 95%."""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

from coverage import Coverage

ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = ROOT / "src"
TEST_DIR = ROOT / "tests"
MINIMUM_COVERAGE = 95.0


def run_covered_test(
    source: Path, test: Path, data_file: Path, environment: dict[str, str]
) -> bool:
    """Run one test module with coverage restricted to its assigned source."""
    command = [
        sys.executable,
        "-m",
        "coverage",
        "run",
        "--data-file",
        str(data_file),
        f"--include={source}",
        "-m",
        "unittest",
        "discover",
        "-s",
        str(TEST_DIR),
        "-p",
        test.name,
        "-q",
    ]
    result = subprocess.run(
        command, cwd=ROOT, env=environment, check=False, capture_output=True, text=True
    )
    if result.returncode:
        print(result.stdout, file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        return False
    return True


def test_environment() -> dict[str, str]:
    """Make source modules importable by each isolated test process."""
    python_path = [str(SOURCE_DIR)]
    if inherited_path := os.environ.get("PYTHONPATH"):
        python_path.append(inherited_path)
    return {**os.environ, "PYTHONPATH": os.pathsep.join(python_path)}


def coverage_failure(source: Path, test: Path, data_file: Path) -> str | None:
    """Report measured coverage and describe a failed threshold, if any."""
    coverage = Coverage(data_file=str(data_file))
    coverage.load()
    _, statements, _, missing, _ = coverage.analysis2(str(source))
    covered = len(statements) - len(missing)
    percent = 100.0 * covered / len(statements) if statements else 100.0
    print(f"{source.name}: {percent:.1f}% ({covered}/{len(statements)}) via {test.name}")
    if percent < MINIMUM_COVERAGE:
        return (
            f"{source.name}: {percent:.1f}% is below {MINIMUM_COVERAGE:.0f}% "
            f"(missing lines: {missing})"
        )
    return None


def source_failure(source: Path, temporary: Path, environment: dict[str, str]) -> str | None:
    """Check the assigned test file and coverage for one source module."""
    test = TEST_DIR / f"test_{source.stem}.py"
    if not test.is_file():
        return f"{source.name}: missing {test.name}"
    data_file = temporary / f".coverage.{source.stem}"
    if not run_covered_test(source, test, data_file, environment):
        return f"{test.name}: tests failed"
    return coverage_failure(source, test, data_file)


def collect_failures(sources: list[Path]) -> list[str]:
    """Run each source's test file in an independent coverage process."""
    failures = []
    environment = test_environment()
    with tempfile.TemporaryDirectory(prefix="codeguard-coverage-") as temporary:
        for source in sources:
            if failure := source_failure(source, Path(temporary), environment):
                failures.append(failure)
    return failures


def report_failures(failures: list[str]) -> None:
    """Show every failed source or coverage requirement."""
    print("\nPython coverage requirements failed:", file=sys.stderr)
    for failure in failures:
        print(f"- {failure}", file=sys.stderr)


def main() -> int:
    """Check every top-level source against its matching unit test file."""
    sources = sorted(SOURCE_DIR.glob("*.py"))
    if not sources:
        print("No top-level Python sources found", file=sys.stderr)
        return 1
    failures = collect_failures(sources)
    if failures:
        report_failures(failures)
        return 1
    print(f"\nEvery top-level src module meets {MINIMUM_COVERAGE:.0f}% coverage.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
