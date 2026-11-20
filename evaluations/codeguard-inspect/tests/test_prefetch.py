from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path

import pytest
import yaml

from codeguard_evals import prefetch
from codeguard_evals.artifacts import tree_sha256

PREPARATION_STEPS = {
    "securityeval": ("prefetch_securityeval_rules", "prefetch_securityeval"),
    "cyberseceval": ("prefetch_detector", "prefetch_dataset"),
}


@pytest.mark.parametrize("benchmark", PREPARATION_STEPS)
@pytest.mark.parametrize("stage", ["all", "generation", "scan"])
def test_prefetch_prepares_only_the_selected_benchmark_and_stage(
    benchmark, stage, monkeypatch, capsys
):
    calls = []

    def prepare(name):
        calls.append(name)
        return Path(name)

    for steps in PREPARATION_STEPS.values():
        for name in steps:
            monkeypatch.setattr(prefetch, name, lambda name=name: prepare(name))
    args = ["--benchmark", benchmark, "--stage", stage]
    if benchmark == "securityeval" and stage == "all":
        args = []  # Also cover the CLI defaults.
    assert prefetch.main(args) == 0
    rules, dataset = PREPARATION_STEPS[benchmark]
    expected = {"all": [rules, dataset], "generation": [dataset], "scan": [rules]}[
        stage
    ]
    assert calls == expected
    output = capsys.readouterr().out
    assert all(name in output for name in expected)


@pytest.mark.parametrize("benchmark", PREPARATION_STEPS)
def test_prefetch_stops_when_rules_preparation_fails(benchmark, monkeypatch):
    def reject():
        raise ValueError("invalid rules")

    for steps in PREPARATION_STEPS.values():
        for name in steps:
            monkeypatch.setattr(
                prefetch, name, lambda: pytest.fail("unexpected preparation")
            )
    monkeypatch.setattr(prefetch, PREPARATION_STEPS[benchmark][0], reject)
    with pytest.raises(ValueError, match="invalid rules"):
        prefetch.main(["--benchmark", benchmark])


@pytest.fixture
def json_rules(tmp_path, monkeypatch):
    """Independently specified source and expected JSON bytes, with real pins."""
    files = {
        "CodeShield/LICENSE": b"fixture license\n",
        "CodeShield/insecure_code_detector/rules/regex/rust.yaml": (
            b"- pattern_id: example\n  rule: 'unsafe\\w+\\(0\\)'\n"
            b"  severity: Warning\n  examples: [one, two]\n"
        ),
        "CodeShield/insecure_code_detector/rules/semgrep/example.json": b'{"rules": []}\n',
    }
    source_cache = tmp_path / "upstream"
    source_cache.mkdir(mode=0o700)
    source = source_cache / ("a" * 40)
    expected = tmp_path / "expected"
    for name, raw in files.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        target = expected / name
        if target.suffix == ".yaml":
            target = target.with_suffix(".json")
            raw = (
                b'[{"examples":["one","two"],"pattern_id":"example",'
                b'"rule":"unsafe\\\\w+\\\\(0\\\\)","severity":"Warning"}]\n'
            )
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    lock = prefetch.icd.IcdLock.model_validate({
        "schema_version": 2,
        "prepared_tree_sha256": tree_sha256(expected),
        "source": {
            "schema_version": 1,
            "repository": "https://github.com/meta-llama/PurpleLlama",
            "commit": "a" * 40,
            "tree_sha256": tree_sha256(source),
            "files": {
                name: {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                for name, raw in files.items()
            },
        },
    })
    monkeypatch.setattr(prefetch.icd, "ICD_LOCK", lock)
    return tmp_path / "prepared", source_cache, expected


def test_json_preparation_preserves_data_and_verifies_existing_cache(json_rules, monkeypatch):
    cache, source_cache, expected = json_rules
    previous_umask = os.umask(0o077)
    try:
        detector = prefetch.prefetch_detector(cache, source_cache)
    finally:
        os.umask(previous_umask)
    prepared = detector.parents[1]
    assert tree_sha256(prepared) == tree_sha256(expected)
    assert not list(prepared.rglob("*.yaml"))
    source = source_cache / prefetch.icd.ICD_LOCK.source.commit
    for path in source.rglob("*.yaml"):
        target = prepared / path.relative_to(source).with_suffix(".json")
        assert json.loads(target.read_bytes()) == yaml.safe_load(path.read_bytes())
    assert cache.stat().st_mode & 0o777 == 0o700
    assert (detector / "rules/regex").stat().st_mode & 0o777 == 0o755
    assert (detector / "rules/regex/rust.json").stat().st_mode & 0o777 == 0o444

    def reject(*args, **kwargs):
        pytest.fail("A prepared cache must not be downloaded or converted again")

    monkeypatch.setattr(prefetch, "prefetch_files", reject)
    monkeypatch.setattr(prefetch.yaml, "safe_load", reject)
    assert prefetch.prefetch_detector(cache, source_cache) == detector
    (prepared / "CodeShield/LICENSE").chmod(0o644)
    (prepared / "CodeShield/LICENSE").write_bytes(b"changed")
    with pytest.raises(ValueError, match="tree does not match"):
        prefetch.prefetch_detector(cache, source_cache)


def test_changed_upstream_bytes_are_rejected_before_yaml_parsing(json_rules, monkeypatch):
    cache, source_cache, _ = json_rules
    source = source_cache / prefetch.icd.ICD_LOCK.source.commit
    # Model a change after prefetch verified the cache but before conversion reads it.
    (source / "CodeShield/insecure_code_detector/rules/regex/rust.yaml").write_text("bad")
    monkeypatch.setattr(prefetch, "prefetch_files", lambda *args: source)
    monkeypatch.setattr(prefetch.yaml, "safe_load", lambda *args: pytest.fail("unverified YAML parsed"))
    with pytest.raises(ValueError, match="size/SHA-256 pin"):
        prefetch.prefetch_detector(cache, source_cache)
    assert list(cache.iterdir()) == []


def test_unexpected_conversion_output_is_not_published(json_rules, monkeypatch):
    cache, source_cache, _ = json_rules
    monkeypatch.setattr(prefetch.yaml, "safe_load", lambda *args: [])
    with pytest.raises(ValueError, match="tree does not match"):
        prefetch.prefetch_detector(cache, source_cache)
    assert list(cache.iterdir()) == []


@pytest.mark.parametrize("matching", [True, False])
def test_json_publication_verifies_a_concurrent_winner(json_rules, monkeypatch, matching):
    cache, source_cache, expected = json_rules
    rename = Path.rename

    def publish_other_copy(staging, destination):
        shutil.copytree(expected, destination)
        if not matching:
            (destination / "CodeShield/LICENSE").write_bytes(b"changed")
        return rename(staging, destination)

    monkeypatch.setattr(Path, "rename", publish_other_copy)
    destination = cache / prefetch.icd.ICD_LOCK.prepared_tree_sha256
    if matching:
        assert prefetch.prefetch_detector(cache, source_cache).parents[1] == destination
    else:
        with pytest.raises(ValueError, match="tree does not match"):
            prefetch.prefetch_detector(cache, source_cache)
        assert (destination / "CodeShield/LICENSE").read_bytes() == b"changed"
    assert list(cache.iterdir()) == [destination]
