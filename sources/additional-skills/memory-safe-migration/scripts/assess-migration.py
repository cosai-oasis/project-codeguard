#!/usr/bin/env python3
"""
Memory-safe migration assessment tool.

Analyzes C/C++ source files to estimate migration priority based on:
- Unsafe function usage (strcpy, sprintf, malloc, free, etc.)
- Buffer declaration patterns
- Pointer arithmetic
- Network/file I/O exposure
- Concurrency patterns

Usage:
    python assess-migration.py --file <source_file_or_directory>
    python assess-migration.py --file src/ --format json

Output:
    A migration priority report for each file with risk indicators,
    an overall priority score, and recommended migration order.
"""

import argparse
import os
import re
import json
import sys
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Tuple

# ── Risk patterns ──────────────────────────────────────────────────────────

# Unsafe C functions that should be replaced
UNSAFE_FUNCTIONS = {
    # String functions — buffer overflow risk
    "strcpy": ("Buffer overflow — no bounds checking", 3),
    "strcat": ("Buffer overflow — no bounds checking", 3),
    "sprintf": ("Buffer overflow — no bounds checking", 3),
    "gets": ("Buffer overflow — always unsafe, removed in C11", 5),
    "scanf": ("Buffer overflow with %s format", 2),
    "vsprintf": ("Buffer overflow — no bounds checking", 3),

    # Memory functions — overflow or misuse risk
    "memcpy": ("Potential buffer overflow if size unchecked", 2),
    "memmove": ("Potential buffer overflow if size unchecked", 2),
    "memset": ("Potential buffer overflow if size unchecked", 1),

    # Memory management — use-after-free, double-free, leak risk
    "malloc": ("Manual memory management — leak/use-after-free risk", 2),
    "calloc": ("Manual memory management — leak/use-after-free risk", 2),
    "realloc": ("Manual memory management — complex ownership", 3),
    "free": ("Manual memory management — double-free risk", 2),
    "alloca": ("Stack allocation — stack overflow risk", 3),

    # Format string vulnerabilities
    "printf": ("Format string vulnerability if user-controlled", 1),
    "fprintf": ("Format string vulnerability if user-controlled", 1),
    "syslog": ("Format string vulnerability if user-controlled", 2),

    # Other unsafe patterns
    "system": ("Command injection risk", 4),
    "popen": ("Command injection risk", 4),
    "exec": ("Command injection risk", 3),
    "atoi": ("No error checking on conversion", 1),
    "atol": ("No error checking on conversion", 1),
    "atof": ("No error checking on conversion", 1),
}

# Patterns indicating network exposure
NETWORK_PATTERNS = [
    (r"\bsocket\s*\(", "Socket creation — network-facing code"),
    (r"\bbind\s*\(", "Socket binding — server code"),
    (r"\blisten\s*\(", "Socket listening — server code"),
    (r"\baccept\s*\(", "Socket accept — server code"),
    (r"\brecv\s*\(", "Network receive — processes untrusted data"),
    (r"\brecvfrom\s*\(", "Network receive — processes untrusted data"),
    (r"\brecvmsg\s*\(", "Network receive — processes untrusted data"),
    (r"\bSSL_read\s*\(", "TLS data handling"),
    (r"\bSSL_write\s*\(", "TLS data handling"),
    (r"#include\s*<.*?(netinet|arpa|sys/socket|netdb)", "Network headers included"),
]

# Patterns indicating file/input processing
INPUT_PATTERNS = [
    (r"\bfopen\s*\(", "File I/O — may process untrusted files"),
    (r"\bfread\s*\(", "File read — may process untrusted data"),
    (r"\bopen\s*\(", "File descriptor open"),
    (r"\bread\s*\(", "Low-level read — may process untrusted data"),
    (r"\bfscanf\s*\(", "Formatted file input"),
    (r"\b(xml|json|yaml|parse)\b", "Data parsing — untrusted input risk"),
]

# Patterns indicating concurrency
CONCURRENCY_PATTERNS = [
    (r"\bpthread_", "POSIX threads — data race risk"),
    (r"\bstd::thread", "C++ threads — data race risk"),
    (r"\bstd::mutex", "Mutex usage — potential deadlock"),
    (r"\bstd::atomic", "Atomic operations — complex ordering"),
    (r"\bvolatile\b", "Volatile — often misused for synchronization"),
    (r"\bfork\s*\(", "Process forking — shared state risk"),
]

# Patterns indicating cryptographic code
CRYPTO_PATTERNS = [
    (r"\bEVP_|SSL_|HMAC_|SHA[0-9]|AES_|RSA_|EC_KEY", "Cryptographic operations"),
    (r"#include\s*<openssl", "OpenSSL usage"),
    (r"\bcrypt\b|\bhash\b|\bcipher\b", "Crypto-related code"),
]

# Patterns indicating pointer arithmetic
POINTER_PATTERNS = [
    (r"\*\s*\(.*\+", "Pointer arithmetic with dereference"),
    (r"\[\s*\w+\s*\+", "Array index with arithmetic"),
    (r"\bvoid\s*\*", "Void pointer — type safety loss"),
    (r"reinterpret_cast|static_cast.*\*", "C++ pointer casting"),
    (r"\(\s*(char|int|void|unsigned)\s*\*\s*\)", "C-style pointer cast"),
]

# Buffer declaration patterns
BUFFER_PATTERNS = [
    (r"\bchar\s+\w+\s*\[\s*\d+\s*\]", "Fixed-size char buffer — overflow risk"),
    (r"\buint8_t\s+\w+\s*\[\s*\d+\s*\]", "Fixed-size byte buffer"),
    (r"\bchar\s*\*\s*\w+\s*=\s*malloc", "Heap-allocated string buffer"),
]


@dataclass
class FileAssessment:
    filepath: str
    lines_of_code: int = 0
    unsafe_function_calls: List[Dict] = field(default_factory=list)
    network_indicators: List[str] = field(default_factory=list)
    input_indicators: List[str] = field(default_factory=list)
    concurrency_indicators: List[str] = field(default_factory=list)
    crypto_indicators: List[str] = field(default_factory=list)
    pointer_arithmetic: List[str] = field(default_factory=list)
    buffer_declarations: List[str] = field(default_factory=list)
    risk_score: int = 0
    priority: str = ""
    recommended_language: str = ""
    migration_notes: List[str] = field(default_factory=list)


def analyze_file(filepath: str) -> FileAssessment:
    """Analyze a single C/C++ source file for migration assessment."""
    assessment = FileAssessment(filepath=filepath)

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
            lines = content.split("\n")
    except IOError as e:
        assessment.migration_notes.append(f"Could not read file: {e}")
        return assessment

    assessment.lines_of_code = len([l for l in lines if l.strip() and not l.strip().startswith("//")])

    score = 0

    # Check unsafe functions
    for func_name, (description, weight) in UNSAFE_FUNCTIONS.items():
        pattern = rf"\b{re.escape(func_name)}\s*\("
        matches = re.findall(pattern, content)
        if matches:
            count = len(matches)
            assessment.unsafe_function_calls.append({
                "function": func_name,
                "count": count,
                "risk": description,
                "weight": weight,
            })
            score += weight * min(count, 5)  # Cap per-function contribution

    # Check network exposure
    for pattern, description in NETWORK_PATTERNS:
        if re.search(pattern, content):
            assessment.network_indicators.append(description)
            score += 4

    # Check input processing
    for pattern, description in INPUT_PATTERNS:
        if re.search(pattern, content):
            assessment.input_indicators.append(description)
            score += 2

    # Check concurrency
    for pattern, description in CONCURRENCY_PATTERNS:
        if re.search(pattern, content):
            assessment.concurrency_indicators.append(description)
            score += 3

    # Check crypto
    for pattern, description in CRYPTO_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            assessment.crypto_indicators.append(description)
            score += 3

    # Check pointer arithmetic
    for pattern, description in POINTER_PATTERNS:
        matches = re.findall(pattern, content)
        if matches:
            assessment.pointer_arithmetic.append(f"{description} ({len(matches)} instances)")
            score += 2 * min(len(matches), 5)

    # Check buffer declarations
    for pattern, description in BUFFER_PATTERNS:
        matches = re.findall(pattern, content)
        if matches:
            assessment.buffer_declarations.append(f"{description} ({len(matches)} instances)")
            score += 2 * min(len(matches), 5)

    # Set priority
    assessment.risk_score = score
    if score >= 30:
        assessment.priority = "CRITICAL"
    elif score >= 20:
        assessment.priority = "HIGH"
    elif score >= 10:
        assessment.priority = "MEDIUM"
    else:
        assessment.priority = "LOW"

    # Recommend language
    if assessment.network_indicators or assessment.crypto_indicators:
        assessment.recommended_language = "Rust (performance-critical, security-sensitive)"
    elif assessment.concurrency_indicators:
        assessment.recommended_language = "Rust or Go (strong concurrency support)"
    elif assessment.lines_of_code > 5000:
        assessment.recommended_language = "Rust (large codebase, needs fine-grained control)"
    else:
        assessment.recommended_language = "Rust or Go (general recommendation)"

    # Add notes
    if assessment.lines_of_code > 10000:
        assessment.migration_notes.append(
            "Large file — consider incremental migration, one function at a time"
        )
    if len(assessment.unsafe_function_calls) > 10:
        assessment.migration_notes.append(
            "Heavy unsafe function usage — high migration impact, high security benefit"
        )
    if not assessment.network_indicators and not assessment.input_indicators:
        assessment.migration_notes.append(
            "No network/input exposure detected — lower attack surface, lower priority"
        )

    return assessment


def find_source_files(path: str) -> List[str]:
    """Find all C/C++ source files in a path."""
    extensions = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}
    if os.path.isfile(path):
        if Path(path).suffix.lower() in extensions:
            return [path]
        return []

    sources = []
    for root, _, files in os.walk(path):
        for f in files:
            if Path(f).suffix.lower() in extensions:
                sources.append(os.path.join(root, f))
    return sorted(sources)


def print_report(assessments: List[FileAssessment]):
    """Print a human-readable migration assessment report."""
    print("=" * 72)
    print("MEMORY-SAFE MIGRATION ASSESSMENT REPORT")
    print("=" * 72)
    print()

    # Summary
    total_loc = sum(a.lines_of_code for a in assessments)
    critical = [a for a in assessments if a.priority == "CRITICAL"]
    high = [a for a in assessments if a.priority == "HIGH"]
    medium = [a for a in assessments if a.priority == "MEDIUM"]
    low = [a for a in assessments if a.priority == "LOW"]

    print(f"Files analyzed:     {len(assessments)}")
    print(f"Total lines of code: {total_loc:,}")
    print(f"  CRITICAL priority: {len(critical)}")
    print(f"  HIGH priority:     {len(high)}")
    print(f"  MEDIUM priority:   {len(medium)}")
    print(f"  LOW priority:      {len(low)}")
    print()

    # Sort by risk score descending
    assessments_sorted = sorted(assessments, key=lambda a: a.risk_score, reverse=True)

    # Recommended migration order
    print("-" * 72)
    print("RECOMMENDED MIGRATION ORDER")
    print("-" * 72)
    for i, a in enumerate(assessments_sorted[:20], 1):
        print(f"  {i:2d}. [{a.priority:8s}] (score: {a.risk_score:3d}) {a.filepath}")
        print(f"      {a.lines_of_code:,} LOC | {a.recommended_language}")
    if len(assessments_sorted) > 20:
        print(f"  ... and {len(assessments_sorted) - 20} more files")
    print()

    # Detailed per-file reports (top 10 only)
    print("-" * 72)
    print("DETAILED ASSESSMENT (top 10 by risk)")
    print("-" * 72)
    for a in assessments_sorted[:10]:
        print()
        print(f"  File: {a.filepath}")
        print(f"  Lines of code: {a.lines_of_code:,}")
        print(f"  Risk score: {a.risk_score} ({a.priority})")
        print(f"  Recommended: {a.recommended_language}")

        if a.unsafe_function_calls:
            print(f"  Unsafe functions:")
            for uf in sorted(a.unsafe_function_calls, key=lambda x: x["weight"], reverse=True)[:8]:
                print(f"    - {uf['function']}() x{uf['count']}: {uf['risk']}")

        if a.network_indicators:
            print(f"  Network exposure:")
            for n in a.network_indicators[:5]:
                print(f"    - {n}")

        if a.crypto_indicators:
            print(f"  Cryptographic code:")
            for c in a.crypto_indicators[:3]:
                print(f"    - {c}")

        if a.pointer_arithmetic:
            print(f"  Pointer arithmetic: {', '.join(a.pointer_arithmetic[:3])}")

        if a.buffer_declarations:
            print(f"  Buffer declarations: {', '.join(a.buffer_declarations[:3])}")

        if a.migration_notes:
            print(f"  Notes:")
            for n in a.migration_notes:
                print(f"    - {n}")

    print()
    print("=" * 72)
    print("Assessment complete. Migrate CRITICAL and HIGH priority files first.")
    print("Write tests for each component BEFORE starting migration.")
    print("=" * 72)


def main():
    parser = argparse.ArgumentParser(
        description="Assess C/C++ code for memory-safe language migration"
    )
    parser.add_argument(
        "--file", "-f", required=True,
        help="Path to a C/C++ source file or directory to analyze"
    )
    parser.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="Output format (default: text)"
    )
    args = parser.parse_args()

    source_files = find_source_files(args.file)
    if not source_files:
        print(f"No C/C++ source files found in: {args.file}", file=sys.stderr)
        sys.exit(1)

    assessments = [analyze_file(f) for f in source_files]

    if args.format == "json":
        output = {
            "summary": {
                "files_analyzed": len(assessments),
                "total_loc": sum(a.lines_of_code for a in assessments),
                "critical": len([a for a in assessments if a.priority == "CRITICAL"]),
                "high": len([a for a in assessments if a.priority == "HIGH"]),
                "medium": len([a for a in assessments if a.priority == "MEDIUM"]),
                "low": len([a for a in assessments if a.priority == "LOW"]),
            },
            "files": [asdict(a) for a in sorted(
                assessments, key=lambda a: a.risk_score, reverse=True
            )],
        }
        print(json.dumps(output, indent=2))
    else:
        print_report(assessments)


if __name__ == "__main__":
    main()
