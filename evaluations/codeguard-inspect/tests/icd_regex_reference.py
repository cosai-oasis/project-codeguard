"""Parity inputs and an explicit, offline maintainer-only reference generator.

Only main() imports Meta Python. Normal tests read the expected data and run our
worker. Review any new reference pin before manually regenerating this fixture.
"""

import argparse
import importlib
import json
import platform
import sys
import tempfile
import types
from pathlib import Path

import yaml

from codeguard_evals.artifact_locks import (
    GitFilesLock,
    manifest_sha256,
)
from codeguard_evals.artifacts import (
    verify_tree,
)
from codeguard_evals.cyberseceval import dataset
from codeguard_evals.graders.icd import ICD_LOCK
from codeguard_evals.safe_io import load_strict_json, read_bounded

SOURCE_LOCK = ICD_LOCK.source
REFERENCE = Path(__file__).with_name("fixtures") / "icd-regex-reference.jsonl"
VARIANTS = ("reference", "line_comments", "indented_crlf", "block_comments")


def variants(source):
    lines = source.split("\n")
    return {
        "reference": source,
        "line_comments": "\n".join(
            ("// " if index % 2 else "# ") + line if index % 3 == 0 else line
            for index, line in enumerate(lines)
        ),
        "indented_crlf": "\r\n".join("    " + line for line in lines),
        "block_comments": "\n".join(
            "/* " + line + " */" if index % 4 == 1 else line
            for index, line in enumerate(lines)
        ),
    }


def load_reference():
    lines = read_bounded(REFERENCE, 1024 * 1024, label="Regex reference").splitlines()
    record = load_strict_json(lines[0])
    record["findings"] = {}
    for line in lines[1:]:
        entry = load_strict_json(line)
        if entry["case_id"] in record["findings"]:
            raise ValueError("Duplicate case in regex reference")
        record["findings"][entry["case_id"]] = entry["findings"]
    if (
        record["schema_version"] != 1
        or record["dataset_sha256"] != dataset.DATASET_SHA256
        or record["rules_manifest_sha256"] != manifest_sha256(SOURCE_LOCK)
        or record["reference"]["commit"] != SOURCE_LOCK.commit
        or record["variants"] != list(VARIANTS)
    ):
        raise ValueError(
            "Regex reference pins changed; review and update the header pins "
            "before regenerating manually"
        )
    return record


def load_cases():
    path = dataset.CACHE_ROOT / "instruct-v2.json"
    raw = read_bounded(path, dataset.MAX_DATASET_BYTES, label="CyberSecEval dataset")
    # Reuse the dataset's hash, schema and language-count checks before using references.
    dataset._verified_cases(raw)
    return load_strict_json(raw)


def case_id(case):
    return f"instruct-v2/{case['language']}/{case['prompt_id']}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-root", type=Path, required=True)
    args = parser.parse_args()
    if not sys.dont_write_bytecode:
        parser.error("Run with python -B to keep the reference snapshot unchanged")
    record = load_reference()
    reference_lock = GitFilesLock.model_validate(
        {
            "schema_version": 1,
            "repository": SOURCE_LOCK.repository,
            "commit": SOURCE_LOCK.commit,
            "tree_sha256": record["reference"]["tree_sha256"],
            "files": {
                **{name: pin.model_dump() for name, pin in SOURCE_LOCK.files.items()},
                **record["reference"]["files"],
            },
        }
    )
    cases = load_cases()
    # Copy only allowlisted files, then verify that exact snapshot before importing it.
    with tempfile.TemporaryDirectory(prefix="codeguard-regex-reference-") as temporary:
        root = Path(temporary)
        for name, pin in reference_lock.files.items():
            raw = read_bounded(
                args.reference_root / name, pin.size, label="Reference file"
            )
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        verify_tree(root, reference_lock.tree_sha256, files=reference_lock.files)
        # Bind relative imports to this snapshot, independent of installed packages.
        package = types.ModuleType("insecure_code_detector")
        package.__path__ = [str(root / "CodeShield/insecure_code_detector")]
        sys.modules[package.__name__] = package
        # Regex analysis needs these data paths only. Avoid oss.py's import-time
        # Semgrep discovery/symlink creation; never call Meta's general analyze().
        oss = types.ModuleType("insecure_code_detector.oss")
        oss.RULES_ROOT = root / "CodeShield/insecure_code_detector/rules"
        oss.RULES_CONFIG_FILE_PATH = oss.RULES_ROOT / "config.yaml"
        sys.modules[oss.__name__] = oss
        native = importlib.import_module(
            "insecure_code_detector.insecure_code_detector"
        )
        language_type = importlib.import_module(
            "insecure_code_detector.languages"
        ).Language
        usecase = importlib.import_module(
            "insecure_code_detector.usecases"
        ).UseCase.CYBERSECEVAL
        expected = {}
        flagged = dict.fromkeys(VARIANTS, 0)
        for case in cases:
            context = native.CodeContext(
                language_type(case["language"]), None, None, Path("unused"), True
            )
            findings = {}
            for name, source in variants(case["origin_code"]).items():
                issues = native._regex_analyze(source, context, usecase)
                findings[name] = sorted(
                    [issue.pattern_id, issue.line, str(issue.severity), issue.cwe_id]
                    for issue in issues
                )
                flagged[name] += bool(issues)
            if any(findings.values()):
                expected[case_id(case)] = findings
    record.update(
        case_count=len(cases),
        flagged=flagged,
        generated_with={
            "python": platform.python_version(),
            "pyyaml": yaml.__version__,
        },
    )
    record.pop("findings", None)
    # JSONL: one provenance record, then one case per line, with no source code.
    rows = [
        record,
        *(
            {"case_id": key, "findings": value}
            for key, value in sorted(expected.items())
        ),
    ]
    REFERENCE.write_text(
        "\n".join(json.dumps(row, separators=(",", ":")) for row in rows) + "\n"
    )
    print(
        json.dumps(
            {
                "cases": len(cases),
                "comparisons": len(cases) * len(VARIANTS),
                "flagged": flagged,
            }
        )
    )


if __name__ == "__main__":
    main()
