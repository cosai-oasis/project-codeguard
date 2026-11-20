"""Local command locks coordinate processes without replacing their lock inode."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from codeguard_evals.locking import exclusive_file_lock


def test_lock_coordinates_processes_and_keeps_existing_contents(tmp_path):
    path = tmp_path / ".scan.lock"
    path.write_bytes(b"existing settings")
    script = """
import sys
from pathlib import Path
from codeguard_evals.locking import exclusive_file_lock
try:
    with exclusive_file_lock(Path(sys.argv[1]), description='this job'):
        pass
except ValueError as error:
    sys.exit(str(error))
"""

    def attempt():
        return subprocess.run(
            [sys.executable, "-B", "-c", script, str(path)],
            cwd=Path(__file__).parents[1],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )

    with exclusive_file_lock(path, description="this job"):
        blocked = attempt()
        assert blocked.returncode == 1 and "already using" in blocked.stderr
    assert attempt().returncode == 0
    assert path.read_bytes() == b"existing settings"


@pytest.mark.parametrize("kind", ["symlink", "fifo", "directory"])
def test_lock_rejects_links_and_nonregular_files(tmp_path, kind):
    path = tmp_path / "lock"
    if kind == "symlink":
        target = tmp_path / "target"
        target.write_bytes(b"unchanged")
        path.symlink_to(target)
    elif kind == "fifo":
        os.mkfifo(path)
    else:
        path.mkdir()
    with (
        pytest.raises((OSError, ValueError)),
        exclusive_file_lock(path, description="test"),
    ):
        pytest.fail("Invalid lock was accepted")
    if kind == "symlink":
        assert target.read_bytes() == b"unchanged"
