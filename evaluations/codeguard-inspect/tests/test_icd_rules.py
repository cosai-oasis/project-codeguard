"""Our rule runner: selection, findings, process failures and import isolation."""

import asyncio
import json
import signal
import subprocess
import sys
from pathlib import Path

import pytest
from codeguard_evals.graders import scanner_worker as shared_worker
from codeguard_evals.artifacts import tree_sha256
from codeguard_evals.graders import icd_worker as worker
from codeguard_evals.graders.scanner_client import PYTHON_COMMAND


@pytest.fixture
def rules(tmp_path, monkeypatch):
    root = tmp_path / "rules"
    (root / "regex").mkdir(parents=True)
    names = [*worker.LANGUAGE_FILENAMES, "language_agnostic"]
    config = {}
    for name in names:
        pattern = {
            "pattern_id": f"{name}-enabled",
            "rule": f"{name}_unsafe",
            "description": "fixture",
            "cwe_id": "CWE-1",
            "severity": "Warning",
        }
        disabled = {**pattern, "pattern_id": f"{name}-disabled"}
        (root / "regex" / f"{name}.json").write_text(json.dumps([pattern, disabled]))
        config[name] = {"regex": {"rules": [pattern["pattern_id"]]}}
    (root / "config.json").write_text(json.dumps({"config": {"cyberseceval": config}}))
    monkeypatch.setattr(worker, "RULES_DIRECTORY", root)
    return root


def test_cpp_inherits_c_and_shared_rules_without_including_disabled_rules(rules):
    prepared = worker.load_regex_rules()
    findings = worker.regex_findings(
        "cpp_unsafe\nc_unsafe\nlanguage_agnostic_unsafe", prepared["cpp"]
    )
    assert [(f["rule_id"], f["line"]) for f in findings] == [
        ("cpp-enabled", 1),
        ("c-enabled", 2),
        ("language_agnostic-enabled", 3),
    ]
    assert all(f["severity"] == "warning" and f["column"] is None for f in findings)


@pytest.mark.parametrize("prefix", ["# ", "// ", "/* ", "comment */ "])
def test_regex_preserves_first_match_comment_handling(rules, prefix):
    prepared = worker.load_regex_rules()["rust"]
    assert worker.regex_findings(prefix + "rust_unsafe\nrust_unsafe", prepared) == []
    findings = worker.regex_findings("safe(); rust_unsafe; rust_unsafe", prepared)
    assert len(findings) == 1 and findings[0]["line"] == 1


def test_missing_selected_rule_is_an_error(rules):
    (rules / "regex/rust.json").write_text("[]")
    with pytest.raises(ValueError, match="Configured regex rule is missing"):
        worker.load_regex_rules()


def test_non_json_rules_are_rejected(rules):
    (rules / "regex/rust.json").write_text("!!str fixture\n")
    with pytest.raises(ValueError):
        worker.load_regex_rules()


def test_rules_are_prepared_once_outside_the_matching_budget(rules, monkeypatch):
    read, match = worker.read_bounded, worker._regex_findings
    reads = []

    def checked_read(path, *args, **kwargs):
        assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
        reads.append(path)
        return read(path, *args, **kwargs)

    def checked_match(source, prepared):
        assert signal.getitimer(signal.ITIMER_REAL)[0] > 0
        return match(source, prepared)

    monkeypatch.setattr(worker, "read_bounded", checked_read)
    monkeypatch.setattr(worker, "_regex_findings", checked_match)
    scans = asyncio.run(worker.analyze_sources([
        ["rust_unsafe", "rust"], ["rust_unsafe again", "rust"],
    ]))
    assert all(scan["complete"] and scan["findings"] for scan in scans)
    assert reads.count(rules / "config.json") == reads.count(rules / "regex/rust.json") == 1
    assert len(reads) == len(set(reads))


@pytest.mark.parametrize("interrupt_cleanup", [False, True])
def test_regex_timeout_discards_the_source_and_continues_the_batch(
    rules, monkeypatch, interrupt_cleanup
):
    native = worker._regex_findings
    scanned = []

    def regex(source, prepared):
        if source == "slow source":
            raise shared_worker.RegexTimeout
        return native(source, prepared)

    async def semgrep(paths, selected, **kwargs):
        scanned.extend(path.read_text() for path in paths)
        return {path: [] for path in paths}

    monkeypatch.setattr(worker, "_regex_findings", regex)
    monkeypatch.setattr(shared_worker, "semgrep_findings", semgrep)
    if interrupt_cleanup:
        set_timer = signal.setitimer
        interrupted = False

        def cancel_with_pending_alarm(timer, seconds):
            nonlocal interrupted
            previous = set_timer(timer, seconds)
            if seconds == 0 and not interrupted:
                interrupted = True
                raise shared_worker.RegexTimeout
            return previous

        monkeypatch.setattr(signal, "setitimer", cancel_with_pending_alarm)
    handler = signal.getsignal(signal.SIGALRM)
    scans = asyncio.run(worker.analyze_sources([
        ["slow source", "cpp"], ["rust_unsafe", "rust"], ["cpp_unsafe", "cpp"],
    ]))
    assert not scans[0]["complete"] and scans[0]["reason"] == "rule_timeout"
    assert scans[0]["findings"] is None and scans[0]["analyzers"] == []
    assert all(scan["complete"] and scan["findings"] for scan in scans[1:])
    assert scanned == ["cpp_unsafe"]
    assert signal.getsignal(signal.SIGALRM) == handler
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)


def test_regex_configuration_errors_stay_fatal_and_clear_the_timer(rules):
    (rules / "regex/rust.json").write_text("[]")
    handler = signal.getsignal(signal.SIGALRM)
    with pytest.raises(ValueError, match="Configured regex rule is missing"):
        asyncio.run(worker.analyze_sources([["rust_unsafe", "rust"]]))
    assert signal.getsignal(signal.SIGALRM) == handler
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)


@pytest.mark.parametrize("invalid_pattern", [False, True])
def test_worker_verifies_and_compiles_rules_without_site_packages(
    rules, tmp_path, invalid_pattern
):
    bundle = rules
    (bundle / "LICENSE").write_text("fixture license\n")
    if invalid_pattern:
        path = rules / "regex/rust.json"
        patterns = json.loads(path.read_text())
        patterns[0]["rule"] = "("
        path.write_text(json.dumps(patterns))
    lock_path = tmp_path / "icd.lock.json"
    lock_path.write_text(json.dumps({
        "schema_version": 2,
        "prepared_tree_sha256": tree_sha256(bundle),
    }))
    script = """
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from codeguard_evals.graders import icd_worker
icd_worker.RULES_BUNDLE = Path(sys.argv[2])
icd_worker.RULES_DIRECTORY = icd_worker.RULES_BUNDLE
icd_worker.ICD_LOCK_PATH = Path(sys.argv[3])
icd_worker.verify_rules()
assert 'pydantic' not in sys.modules
assert 'yaml' not in sys.modules
"""
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            "-c",
            script,
            str(Path(__file__).parents[1]),
            str(bundle),
            str(lock_path),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if invalid_pattern:
        assert result.returncode != 0 and "unterminated subpattern" in result.stderr
    else:
        assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "lock",
    [
        [],
        {"schema_version": 1, "prepared_tree_sha256": "a" * 64},
        {"schema_version": 2},
        {"schema_version": 2, "prepared_tree_sha256": "invalid"},
        {"schema_version": 2, "prepared_tree_sha256": 7},
    ],
)
def test_worker_rejects_invalid_lock_before_reading_rules(tmp_path, monkeypatch, lock):
    path = tmp_path / "icd.lock.json"
    path.write_text(json.dumps(lock))
    monkeypatch.setattr(worker, "ICD_LOCK_PATH", path)
    monkeypatch.setattr(worker, "verify_tree", lambda *args: pytest.fail("unverified pin"))
    with pytest.raises(ValueError, match="ICD"):
        worker.verify_rules()


def test_worker_rejects_changed_bundle_before_parsing_rules(rules, tmp_path, monkeypatch):
    path = tmp_path / "icd.lock.json"
    path.write_text(json.dumps({
        "schema_version": 2,
        "prepared_tree_sha256": tree_sha256(rules),
    }))
    monkeypatch.setattr(worker, "ICD_LOCK_PATH", path)
    monkeypatch.setattr(worker, "RULES_BUNDLE", rules)
    monkeypatch.setattr(worker, "load_regex_rules", lambda: pytest.fail("unverified rules parsed"))
    (rules / "config.json").write_text("{}")
    with pytest.raises(ValueError, match="SHA-256 pin"):
        worker.verify_rules()


def test_regex_worker_runs_without_a_yaml_parser(rules):
    bootstrap = """
import builtins
import sys
from pathlib import Path
original_import = builtins.__import__
def without_yaml(name, *args, **kwargs):
    if name == 'yaml' or name.startswith('yaml.'):
        raise ImportError('YAML parser is unavailable in the scanner')
    return original_import(name, *args, **kwargs)
builtins.__import__ = without_yaml
from codeguard_evals.graders import icd_worker
icd_worker.RULES_DIRECTORY = Path(sys.argv[1])
rules = icd_worker.load_regex_rules()
findings = icd_worker.regex_findings('cpp_unsafe; c_unsafe; language_agnostic_unsafe', rules['cpp'])
assert [finding['rule_id'] for finding in findings] == [
    'cpp-enabled', 'c-enabled', 'language_agnostic-enabled'
]
"""
    result = subprocess.run(
        [sys.executable, *PYTHON_COMMAND[1:-1], "-c", bootstrap, str(rules)],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("language", list(worker.LANGUAGE_FILENAMES))
def test_language_routes_only_to_its_pinned_analyzers(rules, monkeypatch, language):
    calls = []

    async def semgrep(paths, selected, **kwargs):
        (path,) = paths
        calls.append(language)
        assert path.name == worker.LANGUAGE_FILENAMES[language]
        assert path.read_text() == f"{language}_unsafe"
        return {path: []}

    monkeypatch.setattr(shared_worker, "semgrep_findings", semgrep)
    report = asyncio.run(worker.analyze_sources([[f"{language}_unsafe", language]]))[0]
    expected = [] if language in ("php", "rust") else [language]
    assert calls == expected
    assert report["complete"] and len(report["findings"]) == 1
    assert report["analyzers"] == (["regex", "semgrep"] if expected else ["regex"])


@pytest.mark.parametrize("fault", [False, True])
def test_semgrep_failure_does_not_publish_partial_regex_findings(rules, monkeypatch, fault):
    async def fail(paths, language, **kwargs):
        if fault:
            raise shared_worker.ScannerError("engine failure")
        return {path: "parse_error" for path in paths}

    monkeypatch.setattr(shared_worker, "semgrep_findings", fail)
    if fault:
        with pytest.raises(shared_worker.ScannerError):
            asyncio.run(worker.analyze_sources([["c_unsafe", "c"]]))[0]
    else:
        report = asyncio.run(worker.analyze_sources([["c_unsafe", "c"]]))[0]
        assert report["complete"] is False and report["findings"] is None
        assert report["reason"] == "parse_error"


def test_worker_batches_by_language_and_preserves_sample_order(rules, monkeypatch):
    calls = []

    async def semgrep(paths, language, **kwargs):
        calls.append((language.stem.split("_")[0], [path.read_text() for path in paths]))
        return {path: "parse_error" if "partial" in path.read_text() else [] for path in paths}

    monkeypatch.setattr(shared_worker, "semgrep_findings", semgrep)
    sources = [
        ["cpp_unsafe", "cpp"],
        ["python_unsafe", "python"],
        ["cpp_unsafe partial", "cpp"],
        ["rust_unsafe", "rust"],
    ]
    scans = asyncio.run(worker.analyze_sources(sources))
    assert calls == [("cpp", ["cpp_unsafe", "cpp_unsafe partial"]), ("python", ["python_unsafe"])]
    assert [scan["language"] for scan in scans] == [language for _, language in sources]
    assert scans[2]["reason"] == "parse_error" and scans[2]["findings"] is None
    assert all(scans[index]["complete"] for index in (0, 1, 3))
