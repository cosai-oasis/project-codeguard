from __future__ import annotations

import os
import re
from pathlib import Path

import yaml

from codeguard_evals.sandbox_protocol import (
    SANDBOX_NAME,
    SANDBOX_ROOT_USER,
    SANDBOX_WORKDIR,
    SEMGREP_SANDBOX_NAME,
    SEMGREP_SANDBOX_USER,
)
from codeguard_evals.securityeval.securityeval import SANDBOX_CONFIG
from codeguard_evals.semgrep_artifacts import (
    SEMGREP_IMAGE_REFERENCE,
    SEMGREP_LOCK,
    semgrep_rules_checkout_path,
)
from tests.conftest import assert_tmpfs_policy

DOCKERFILE = SANDBOX_CONFIG.with_name("Dockerfile")
DOCKERIGNORE = SANDBOX_CONFIG.parent.parent / ".dockerignore"
EXPECTED_SANDBOX_ID = 65_532


def test_agent_container_is_isolated_with_a_bounded_root_supervisor() -> None:
    compose = yaml.safe_load(SANDBOX_CONFIG.read_text(encoding="utf-8"))

    assert set(compose) == {"services"}
    assert set(compose["services"]) == {SANDBOX_NAME, SEMGREP_SANDBOX_NAME}
    service = compose["services"][SANDBOX_NAME]

    assert service["working_dir"] == SANDBOX_WORKDIR
    assert service["user"] == SANDBOX_ROOT_USER
    assert service["command"] == ["/usr/bin/tail", "-f", "/dev/null"]
    assert service["network_mode"] == "none"
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert service["cap_add"] == ["KILL", "SETGID", "SETUID"]
    assert service["security_opt"] == ["no-new-privileges:true"]
    assert service["init"] is True
    assert service["pids_limit"] == 64
    assert service["cpus"] == 1.0
    assert service["mem_limit"] == "768m"
    assert service["memswap_limit"] == "768m"
    assert service["stop_grace_period"] == "2s"
    assert service["ulimits"] == {
        "cpu": {"soft": 300, "hard": 310},
        "nofile": {"soft": 256, "hard": 256},
    }
    for absent in (
        "volumes",
        "ports",
        "privileged",
        "devices",
        "secrets",
        "environment",
        "env_file",
    ):
        assert absent not in service, absent
    entries = service["tmpfs"]
    assert isinstance(entries, list)
    parsed: list[tuple[str, str]] = []
    for entry in entries:
        assert isinstance(entry, str)
        path, separator, options = entry.partition(":")
        assert separator and path and options, entry
        parsed.append((path, options))
    tmpfs = dict(parsed)
    assert len(tmpfs) == len(parsed), "tmpfs paths must be unique"
    assert_tmpfs_policy(tmpfs)


def test_semgrep_container_is_a_locked_read_only_named_environment() -> None:
    compose = yaml.safe_load(SANDBOX_CONFIG.read_text(encoding="utf-8"))
    service = compose["services"][SEMGREP_SANDBOX_NAME]
    rules_source = Path(
        os.path.relpath(
            semgrep_rules_checkout_path() / SEMGREP_LOCK.rules.subdirectory,
            SANDBOX_CONFIG.parent,
        )
    ).as_posix()

    assert service["image"] == SEMGREP_IMAGE_REFERENCE
    assert service["pull_policy"] == "missing"
    assert service["command"] == ["/usr/bin/tail", "-f", "/dev/null"]
    assert service["working_dir"] == "/tmp"
    assert service["user"] == SEMGREP_SANDBOX_USER
    assert service["network_mode"] == "none"
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert "cap_add" not in service
    assert service["security_opt"] == ["no-new-privileges:true"]
    assert service["init"] is True
    assert service["pids_limit"] == 128
    assert service["cpus"] == 1.0
    assert service["mem_limit"] == "2g"
    assert service["memswap_limit"] == "2g"
    assert service["stop_grace_period"] == "2s"
    assert service["ulimits"] == {
        "core": {"soft": 0, "hard": 0},
        "nofile": {"soft": 256, "hard": 256},
    }
    # Inspect follows service logs while managing the sandbox. Docker's `none`
    # driver does not support that operation.
    assert service.get("logging", {}).get("driver", "json-file") in {
        "json-file",
        "local",
    }
    assert service["volumes"] == [
        {
            "type": "bind",
            "source": rules_source,
            "target": "/rules/python",
            "read_only": True,
            "bind": {"create_host_path": False},
        }
    ]
    for absent in (
        "ports",
        "privileged",
        "devices",
        "secrets",
        "environment",
        "env_file",
    ):
        assert absent not in service, absent
    entries = service["tmpfs"]
    assert isinstance(entries, list)
    tmpfs = dict(entry.split(":", maxsplit=1) for entry in entries)
    assert len(tmpfs) == len(entries)
    assert_tmpfs_policy(
        tmpfs,
        {
            "/tmp": frozenset(
                {
                    "rw",
                    "nosuid",
                    "nodev",
                    "noexec",
                    "size=64m",
                    "uid=1000",
                    "gid=1000",
                    "mode=1777",
                }
            ),
            "/home/semgrep": frozenset(
                {
                    "rw",
                    "nosuid",
                    "nodev",
                    "noexec",
                    "size=16m",
                    "uid=1000",
                    "gid=1000",
                    "mode=0700",
                }
            ),
        },
    )


def test_dockerfile_pins_its_base_and_creates_the_nonroot_identity() -> None:
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")

    base = re.search(r"^FROM\s+(\S+)", dockerfile, re.MULTILINE)
    assert base is not None
    assert re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", base.group(1))
    assert f"groupadd --gid {EXPECTED_SANDBOX_ID} nonroot" in dockerfile
    assert (
        f"useradd --uid {EXPECTED_SANDBOX_ID} --gid {EXPECTED_SANDBOX_ID}"
        in dockerfile
    )
    assert f"--home-dir {SANDBOX_WORKDIR}" in dockerfile
    assert "--no-create-home" in dockerfile
    assert "--no-log-init" in dockerfile
    assert "--shell /usr/sbin/nologin" in dockerfile
    assert "USER nonroot" in dockerfile
    assert "USER 0:0" not in dockerfile
    assert "install -d -m 0555" in dockerfile
    assert "COPY --chmod=0444" in dockerfile
    assert "codeguard_evals/export_solution.py" in dockerfile
    assert f"ENV HOME={SANDBOX_WORKDIR} " in dockerfile
    assert f"WORKDIR {SANDBOX_WORKDIR}" in dockerfile
    assert ">> /etc/passwd" not in dockerfile
    assert ">> /etc/group" not in dockerfile
    assert "/opt/codeguard" not in dockerfile
    assert ".codex/codex" not in dockerfile
    for forbidden in ("ADD ", "curl ", "wget ", "--platform", "ARG BASE_IMAGE"):
        assert forbidden not in dockerfile, forbidden


def test_docker_context_is_default_deny_with_narrow_reincludes() -> None:
    entries = DOCKERIGNORE.read_text(encoding="utf-8").splitlines()

    assert entries[0] == "**", "the build context must deny everything by default"
    for entry in entries[1:]:
        if not entry.startswith("!"):
            # Re-denials exist only to re-narrow a re-included directory.
            assert entry.endswith("/**"), entry
            continue
        # A re-include must name an exact path, never a pattern; a wildcard
        # re-include would widen the build context silently.
        assert "*" not in entry, entry

    reincluded = {entry[1:] for entry in entries if entry.startswith("!")}
    assert reincluded == {
        "sandbox/",
        "sandbox/Dockerfile",
        "codeguard_evals/",
        "codeguard_evals/__init__.py",
        "codeguard_evals/export_solution.py",
        "codeguard_evals/safe_io.py",
        "codeguard_evals/sandbox_protocol.py",
    }
