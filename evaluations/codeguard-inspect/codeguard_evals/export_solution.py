"""Export one bounded, untrusted solution from the agent sandbox."""

from __future__ import annotations

import base64
import errno
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Final

from codeguard_evals.safe_io import READ_FLAGS, stat_changed
from codeguard_evals.sandbox_protocol import (
    MAX_PYTHON_SOURCE_BYTES,
    SANDBOX_WORKDIR,
    SOURCE_FILENAME,
)

SOLUTION_PATH: Final = Path(SANDBOX_WORKDIR) / SOURCE_FILENAME
_NONREGULAR_FILE_ERRNOS: Final = frozenset({errno.ELOOP, errno.ENXIO})


def main() -> int:
    sys.stdout.write(
        json.dumps(
            export_solution(),
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


def export_solution(path: Path = SOLUTION_PATH) -> dict[str, object]:
    try:
        descriptor = os.open(path, READ_FLAGS)
    except FileNotFoundError:
        return _invalid("missing output", 0)
    except PermissionError:
        return _invalid("output is not readable", 0)
    except OSError as exc:
        if exc.errno in _NONREGULAR_FILE_ERRNOS:
            return _invalid("output is not a regular file", 0)
        raise

    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            return _invalid("output is not a regular file", before.st_size)
        if before.st_size > MAX_PYTHON_SOURCE_BYTES:
            return _invalid(
                f"output exceeds {MAX_PYTHON_SOURCE_BYTES} bytes",
                before.st_size,
            )
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            raw = source.read(MAX_PYTHON_SOURCE_BYTES + 1)
            after = os.fstat(source.fileno())
    finally:
        os.close(descriptor)

    if len(raw) > MAX_PYTHON_SOURCE_BYTES:
        return _invalid(f"output exceeds {MAX_PYTHON_SOURCE_BYTES} bytes", len(raw))
    if len(raw) != before.st_size or stat_changed(before, after):
        return _invalid("output changed while being read", len(raw))
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        return _invalid("output is not valid UTF-8", len(raw))
    return {
        "status": "valid",
        "reason": None,
        "size_bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "content_base64": base64.b64encode(raw).decode("ascii"),
    }


def _invalid(reason: str, size_bytes: int) -> dict[str, object]:
    return {
        "status": "invalid",
        "reason": reason,
        "size_bytes": size_bytes,
        "sha256": None,
        "content_base64": None,
    }


if __name__ == "__main__":
    raise SystemExit(main())
