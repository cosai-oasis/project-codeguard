"""Constants for the bounded solution-export wire protocol.

Standard library only: this module is installed into the agent sandbox image.
"""

from __future__ import annotations

from typing import Final

SOURCE_FILENAME: Final = "solution.py"
SANDBOX_NAME: Final = "default"
SEMGREP_SANDBOX_NAME: Final = "semgrep"
SEMGREP_SANDBOX_USER: Final = "1000:1000"
SANDBOX_WORKDIR: Final = "/workspace"
SANDBOX_USER: Final = "nonroot"
SANDBOX_ROOT_USER: Final = "0:0"
CODEX_HOME_DIR: Final = f"{SANDBOX_WORKDIR}/.codex"
CODEX_SKILLS_DIR: Final = f"{CODEX_HOME_DIR}/skills"

MAX_PYTHON_SOURCE_BYTES: Final = 64 * 1024
MAX_EXPORT_REPORT_BYTES: Final = 128 * 1024
MAX_REASON_LENGTH: Final = 4_096
