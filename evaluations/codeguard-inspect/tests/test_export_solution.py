from __future__ import annotations

import base64
import errno
import hashlib
import json
import os
from pathlib import Path

import pytest

import codeguard_evals.sandbox_client as sandbox_client
from codeguard_evals.export_solution import (
    MAX_PYTHON_SOURCE_BYTES,
    SOLUTION_PATH,
    export_solution,
)
from codeguard_evals.sandbox_protocol import SANDBOX_WORKDIR, SOURCE_FILENAME


def test_default_solution_path_matches_the_sandbox_contract() -> None:
    assert SOLUTION_PATH == Path(SANDBOX_WORKDIR) / SOURCE_FILENAME


def test_export_solution_reads_one_bounded_utf8_file(tmp_path: Path) -> None:
    source = b"def generated(value):\n    return str(value)\n"
    solution = tmp_path / SOURCE_FILENAME
    solution.write_bytes(source)

    assert export_solution(solution) == {
        "status": "valid",
        "reason": None,
        "size_bytes": len(source),
        "sha256": hashlib.sha256(source).hexdigest(),
        "content_base64": base64.b64encode(source).decode("ascii"),
    }


def test_export_report_round_trips_through_the_host_protocol(tmp_path: Path) -> None:
    source = b"def generated(value):\n    return str(value)\n"
    solution = tmp_path / SOURCE_FILENAME
    solution.write_bytes(source)

    report = export_solution(solution)
    exported = sandbox_client._parse_export_report(json.dumps(report))

    assert exported == sandbox_client.ExportedSolution(source, None)


def test_export_solution_preserves_exact_newlines(tmp_path: Path) -> None:
    source = b"def generated(value):\r\n    return value\r\n\r\n"
    solution = tmp_path / SOURCE_FILENAME
    solution.write_bytes(source)

    report = export_solution(solution)

    assert base64.b64decode(str(report["content_base64"]), validate=True) == source


@pytest.mark.parametrize(
    ("contents", "reason"),
    [
        (b"x" * (MAX_PYTHON_SOURCE_BYTES + 1), "exceeds"),
        (b"\xff", "not valid UTF-8"),
    ],
)
def test_export_solution_rejects_invalid_content(
    tmp_path: Path,
    contents: bytes,
    reason: str,
) -> None:
    solution = tmp_path / SOURCE_FILENAME
    solution.write_bytes(contents)

    report = export_solution(solution)

    assert report["status"] == "invalid"
    assert reason in str(report["reason"])
    assert report["content_base64"] is None


def test_export_solution_rejects_missing_links_and_special_files(
    tmp_path: Path,
) -> None:
    missing = export_solution(tmp_path / "missing.py")
    assert missing["status"] == "invalid"
    assert missing["reason"] == "missing output"

    target = tmp_path / "target.py"
    target.write_text("pass\n", encoding="utf-8")
    symlink = tmp_path / "symlink.py"
    symlink.symlink_to(target)
    assert export_solution(symlink)["status"] == "invalid"

    fifo = tmp_path / "fifo.py"
    os.mkfifo(fifo)
    report = export_solution(fifo)
    assert report["status"] == "invalid"
    assert report["reason"] == "output is not a regular file"

    assert export_solution(tmp_path)["status"] == "invalid"


def test_export_solution_rejects_a_file_changed_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    solution = tmp_path / SOURCE_FILENAME
    solution.write_bytes(b"first\n")
    real_fstat = os.fstat
    calls = 0

    def racing_fstat(descriptor: int) -> os.stat_result:
        nonlocal calls
        status = real_fstat(descriptor)
        calls += 1
        if calls == 1:
            solution.write_bytes(b"other-longer\n")
        return status

    monkeypatch.setattr(os, "fstat", racing_fstat)

    report = export_solution(solution)

    assert report["status"] == "invalid"
    assert report["reason"] == "output changed while being read"
    assert report["content_base64"] is None


def test_export_solution_does_not_execute_top_level_side_effects(tmp_path: Path) -> None:
    sentinel = tmp_path / "executed"
    solution = tmp_path / SOURCE_FILENAME
    solution.write_text(
        "from pathlib import Path\n"
        f"Path({str(sentinel)!r}).write_text('executed')\n"
        "while True:\n    pass\n",
        encoding="utf-8",
    )

    assert export_solution(solution)["status"] == "valid"
    assert not sentinel.exists()


@pytest.mark.parametrize("error_number", [errno.ELOOP, errno.ENXIO])
def test_export_solution_treats_nonregular_open_errors_as_invalid_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error_number: int,
) -> None:
    def fail_open(*args: object, **kwargs: object) -> int:
        raise OSError(error_number, "open error")

    monkeypatch.setattr(os, "open", fail_open)

    report = export_solution(tmp_path / SOURCE_FILENAME)

    assert report["status"] == "invalid"
    assert report["reason"] == "output is not a regular file"


def test_export_solution_propagates_unexpected_open_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_open(*args: object, **kwargs: object) -> int:
        raise OSError(errno.EIO, "open error")

    monkeypatch.setattr(os, "open", fail_open)

    with pytest.raises(OSError) as error:
        export_solution(tmp_path / SOURCE_FILENAME)

    assert error.value.errno == errno.EIO
