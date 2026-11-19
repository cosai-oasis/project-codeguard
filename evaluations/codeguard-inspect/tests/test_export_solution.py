from __future__ import annotations

import base64
import errno
import hashlib
import json
import os
from pathlib import Path

import pytest

import codeguard_evals.sandbox_client as sandbox_client
import codeguard_evals.export_solution as exporter
from codeguard_evals.export_solution import (
    MAX_PYTHON_SOURCE_BYTES,
    export_solution,
)
from codeguard_evals.sandbox_protocol import SOURCE_FILENAME


def test_export_cli_reads_the_explicit_language_filename(tmp_path, monkeypatch, capsys):
    source = b"int example() { return 1; }\n"
    (tmp_path / "solution.cpp").write_bytes(source)
    monkeypatch.setattr(exporter, "SANDBOX_WORKDIR", str(tmp_path))
    assert exporter.main(["--filename", "solution.cpp"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "valid"
    assert base64.b64decode(report["content_base64"]) == source


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
        (b"x" * (MAX_PYTHON_SOURCE_BYTES + 1), f"output exceeds {MAX_PYTHON_SOURCE_BYTES} bytes"),
        (b"\xff", "output is not valid UTF-8"),
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
    assert report["reason"] == reason
    assert report["size_bytes"] == len(contents)
    assert report["content_base64"] is None


def test_export_solution_rejects_missing_links_and_special_files(
    tmp_path: Path,
) -> None:
    missing = export_solution(tmp_path / "missing.py")
    assert missing["status"] == "invalid"
    assert missing["reason"] == "missing output"
    assert missing["size_bytes"] == 0

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
    assert report["size_bytes"] == fifo.stat().st_size

    assert export_solution(tmp_path)["status"] == "invalid"


@pytest.mark.parametrize(
    ("replacement", "reason"),
    [
        (b"other-longer\n", "output changed while being read"),
        (b"x" * (MAX_PYTHON_SOURCE_BYTES + 10), f"output exceeds {MAX_PYTHON_SOURCE_BYTES} bytes"),
    ],
)
def test_export_solution_rejects_a_file_changed_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replacement: bytes,
    reason: str,
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
            solution.write_bytes(replacement)
        return status

    monkeypatch.setattr(os, "fstat", racing_fstat)

    report = export_solution(solution)

    assert report["status"] == "invalid"
    assert report["reason"] == reason
    assert report["size_bytes"] == min(len(replacement), MAX_PYTHON_SOURCE_BYTES + 1)
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


@pytest.mark.parametrize(
    ("error_number", "reason"),
    [
        (errno.ELOOP, "output is not a regular file"),
        (errno.ENXIO, "output is not a regular file"),
        (errno.EACCES, "output is not readable"),
    ],
)
def test_export_solution_treats_expected_open_errors_as_invalid_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error_number: int,
    reason: str,
) -> None:
    def fail_open(*args: object, **kwargs: object) -> int:
        raise OSError(error_number, "open error")

    monkeypatch.setattr(os, "open", fail_open)

    report = export_solution(tmp_path / SOURCE_FILENAME)

    assert report["status"] == "invalid"
    assert report["reason"] == reason
    assert report["size_bytes"] == 0


@pytest.mark.parametrize("operation", ["open", "fdopen"])
def test_export_solution_propagates_unexpected_io_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    solution = tmp_path / SOURCE_FILENAME
    solution.write_bytes(b"pass\n")

    def fail_io(*args: object, **kwargs: object) -> int:
        raise OSError(errno.EIO, "I/O error")

    monkeypatch.setattr(os, operation, fail_io)

    with pytest.raises(OSError) as error:
        export_solution(solution)

    assert error.value.errno == errno.EIO
