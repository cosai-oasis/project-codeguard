from __future__ import annotations

import tomllib
from pathlib import Path

EVALUATION_DIR = Path(__file__).parents[1]


def test_runtime_configuration_pins_the_supported_minor() -> None:
    pyproject = tomllib.loads((EVALUATION_DIR / "pyproject.toml").read_text())
    dockerfile = (EVALUATION_DIR / "sandbox" / "Dockerfile").read_text()

    assert pyproject["project"]["requires-python"] == ">=3.13,<3.14"
    assert pyproject["tool"]["uv"]["exclude-newer"] == "7 days"
    assert (EVALUATION_DIR / ".python-version").read_text() == "3.13\n"
    assert dockerfile.startswith("FROM python:3.13-slim@sha256:")
