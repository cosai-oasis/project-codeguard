"""Export one bounded, untrusted solution from the agent sandbox."""

from __future__ import annotations

import argparse
import base64
import errno
import hashlib
import json
import sys
from pathlib import Path
from typing import Final

from codeguard_evals.safe_io import BoundedReadError, read_bounded
from codeguard_evals.sandbox_protocol import (
    MAX_PYTHON_SOURCE_BYTES,
    LANGUAGE_FILENAMES,
    SANDBOX_WORKDIR,
)

_NONREGULAR_FILE_ERRNOS: Final = frozenset({errno.ELOOP, errno.ENXIO})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--filename",
        choices=tuple(LANGUAGE_FILENAMES.values()),
        required=True,
    )
    args = parser.parse_args(argv)
    sys.stdout.write(
        json.dumps(
            export_solution(Path(SANDBOX_WORKDIR) / args.filename),
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


def export_solution(path: Path) -> dict[str, object]:
    try:
        raw = read_bounded(path, MAX_PYTHON_SOURCE_BYTES, label="output")
    except BoundedReadError as exc:
        return _invalid(exc.reason, exc.size_bytes)
    except FileNotFoundError:
        return _invalid("missing output", 0)
    except PermissionError:
        return _invalid("output is not readable", 0)
    except OSError as exc:
        if exc.errno in _NONREGULAR_FILE_ERRNOS:
            return _invalid("output is not a regular file", 0)
        raise

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
