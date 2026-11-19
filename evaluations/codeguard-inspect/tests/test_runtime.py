from __future__ import annotations

import os
import tomllib
from pathlib import Path
from urllib.parse import urlsplit

EVALUATION_DIR = Path(__file__).parents[1]


def test_unit_tests_use_a_missing_private_docker_socket(tmp_path):
    endpoint = urlsplit(os.environ["DOCKER_HOST"])
    assert endpoint.scheme == "unix" and not endpoint.netloc
    socket = Path(endpoint.path)
    assert socket.parent == tmp_path and not socket.exists()
    assert os.environ["DOCKER_CONTEXT"] == ""


def test_runtime_configuration_pins_the_supported_minor() -> None:
    pyproject = tomllib.loads((EVALUATION_DIR / "pyproject.toml").read_text())
    dockerfile = (EVALUATION_DIR / "sandbox" / "Dockerfile").read_text()

    assert pyproject["project"]["requires-python"] == ">=3.13,<3.14"
    assert pyproject["tool"]["uv"]["exclude-newer"] == "7 days"
    assert (EVALUATION_DIR / ".python-version").read_text() == "3.13\n"
    assert dockerfile.startswith("FROM python:3.13-slim@sha256:")


def test_dependency_cooldown_has_no_package_exceptions() -> None:
    pyproject = tomllib.loads((EVALUATION_DIR / "pyproject.toml").read_text())
    lock = tomllib.loads((EVALUATION_DIR / "uv.lock").read_text())

    assert not pyproject["tool"]["uv"].get("exclude-newer-package")
    assert lock["options"]["exclude-newer-span"] == "P7D"
    assert not lock["options"].get("exclude-newer-package")
