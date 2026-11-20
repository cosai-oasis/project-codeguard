"""Constants for bounded source export and static scanner protocols.

Standard library only: this module is installed into the agent sandbox image.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Final, Literal

SANDBOX_NAME: Final = "default"
SEMGREP_SANDBOX_NAME: Final = "semgrep"
SEMGREP_SANDBOX_USER: Final = "1000:1000"
SANDBOX_WORKDIR: Final = "/workspace"
SANDBOX_USER: Final = "nonroot"
SANDBOX_ROOT_USER: Final = "0:0"
SANDBOX_USER_HOME: Final = "/home/nonroot"
CODEX_HOME_DIR: Final = f"{SANDBOX_USER_HOME}/.codex"
CODEX_SKILLS_DIR: Final = f"{CODEX_HOME_DIR}/skills"

Language = Literal["c", "cpp", "csharp", "java", "javascript", "php", "python", "rust"]
LANGUAGE_FILENAMES: Final = MappingProxyType(
    {
        "c": "solution.c",
        "cpp": "solution.cpp",
        "csharp": "solution.cs",
        "java": "solution.java",
        "javascript": "solution.js",
        "php": "solution.php",
        "python": "solution.py",
        "rust": "solution.rs",
    }
)
SOURCE_FILENAME: Final = LANGUAGE_FILENAMES["python"]

MAX_SOURCE_BYTES: Final = 64 * 1024
# Leave half the scanner tmpfs available for Semgrep and reports.
MAX_SCAN_SOURCE_BYTES: Final = 32 * 1024 * 1024
MAX_PYTHON_SOURCE_BYTES: Final = MAX_SOURCE_BYTES
MAX_EXPORT_REPORT_BYTES: Final = 128 * 1024
MAX_SCAN_REPORT_BYTES: Final = 8 * 1024 * 1024
MAX_REASON_LENGTH: Final = 4_096


def validate_source_filename(filename: str) -> str:
    """Restrict capture to one fixed basename for a supported language."""
    if filename not in LANGUAGE_FILENAMES.values():
        raise ValueError("Unsupported solution filename")
    return filename
