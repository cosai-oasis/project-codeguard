"""Structured logging with log-injection prevention."""

from __future__ import annotations

import logging
import sys


class _SafeFormatter(logging.Formatter):
    """Escapes CR/LF to prevent log injection."""

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        return msg.replace("\n", r"\n").replace("\r", r"\r")


def setup_logging(level: str = "INFO") -> None:
    level = level.upper()
    numeric = getattr(logging, level, None)
    if not isinstance(numeric, int):
        numeric = logging.INFO

    fmt = "%(asctime)s  %(name)s  %(levelname)s  %(message)s"
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_SafeFormatter(fmt, datefmt="%Y-%m-%dT%H:%M:%S"))
    handler.setLevel(numeric)

    logging.basicConfig(level=numeric, handlers=[handler], force=True)
