"""Cooperative process locks for scan output publication."""

import fcntl
import os
import stat
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from codeguard_evals.safe_io import READ_FLAGS


@contextmanager
def exclusive_file_lock(path: Path, *, description: str) -> Generator[None]:
    """Acquire without waiting, following links, or truncating existing data.

    Keep the lock file after release: unlinking it lets another process lock a
    different inode while a previous holder still owns the original lock.
    """
    flags = READ_FLAGS | os.O_CREAT
    with os.fdopen(os.open(path, flags, 0o600), "rb") as locked:
        if not stat.S_ISREG(os.fstat(locked.fileno()).st_mode):
            raise ValueError("Lock must be a regular file")
        try:
            fcntl.flock(locked, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError(f"Another command is already using {description}") from None
        yield
