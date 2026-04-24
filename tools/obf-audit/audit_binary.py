#!/usr/bin/env python3

import argparse
import json
import pathlib
import re
import subprocess
import sys
from dataclasses import asdict, dataclass


OBF_SYMBOL_PATTERNS = [
    "__obf_vm_impl_",
    "__obf_vm_region_",
    "__obf_vm_seedcase_",
    "__obf_vm_seed_resolve",
    "__obf_vm_target_",
    "__obf_vm_targetseed_",
    "__obf_vm_key_",
    "__obf_vm_retkey_",
]

RUNTIME_SYMBOL_PATTERNS = [
    "__obf_entropy_anchor",
    "__obf_entropy_anchor_ref",
    "__obf_load_entropy_pair",
]

STRING_RULES = {
    "license_demo": {
        "fail": ["delta-7"],
        "warn": [
            "mix_token",
            "verify_license",
            "__obf_vm_impl_",
            "__obf_vm_seedcase_",
            "__obf_vm_seed_resolve",
            "__obf_vm_targetseed_",
        ],
    },
    "config_demo": {
        "fail": [],
        "warn": [
            "parse_mode",
            "fold_value",
            "__obf_vm_impl_",
            "__obf_vm_seedcase_",
            "__obf_vm_seed_resolve",
        ],
    },
    "vm_workflow_demo": {
        "fail": [],
        "warn": [
            "classify_byte",
            "route_score",
            "__obf_vm_impl_",
            "__obf_vm_seedcase_",
            "__obf_vm_seed_resolve",
        ],
    },
}


@dataclass
class AuditFinding:
    severity: str
    benchmark: str
    check: str
    detail: str


@dataclass
class BinaryAuditResult:
    benchmark: str
    binary_path: pathlib.Path
    findings: list[AuditFinding]


def run_tool(argv: list[str]) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(argv, text=True, capture_output=True)
    except FileNotFoundError as error:
        return 127, "", str(error)
    return completed.returncode, completed.stdout, completed.stderr


def is_tool_available(tool: str | None) -> bool:
    if tool is None or tool == "":
        return False
    return not tool.endswith("-NOTFOUND")


def discover_binaries(benchmarks_dir: pathlib.Path) -> list[pathlib.Path]:
    return sorted(
        path
        for path in benchmarks_dir.glob("*/*.obfuscated")
        if path.is_file() and path.suffix == ".obfuscated"
    )


def allowed(text: str, allow_patterns: list[re.Pattern[str]]) -> bool:
    return any(pattern.search(text) for pattern in allow_patterns)


def add_grouped_pattern_findings(
    findings: list[AuditFinding],
    benchmark: str,
    check: str,
    text: str,
    patterns: list[str],
    severity: str,
    allow_patterns: list[re.Pattern[str]],
) -> int:
    matched = 0
    lines = text.splitlines()
    for pattern in patterns:
        hits = [line.strip() for line in lines if pattern in line and not allowed(line, allow_patterns)]
        if not hits:
            continue
        matched += len(hits)
        findings.append(
            AuditFinding(
                severity,
                benchmark,
                check,
                f"{pattern} appears {len(hits)} time(s); first: {hits[0]}",
            )
        )
    return matched


def add_tool_status(
    findings: list[AuditFinding],
    benchmark: str,
    check: str,
    rc: int,
    stderr: str,
) -> None:
    if rc == 0:
        return
    lowered = stderr.lower()
    if "no symbols" in lowered:
        return
    findings.append(
        AuditFinding("warn", benchmark, check, f"tool exited with {rc}: {stderr.strip()}")
    )


def audit_exported_symbols(
    binary_path: pathlib.Path,
    benchmark: str,
    llvm_nm: str,
    allow_patterns: list[re.Pattern[str]],
    fail_on_runtime_symbols: bool,
) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    rc, stdout, stderr = run_tool([llvm_nm, "-g", str(binary_path)])
    add_tool_status(findings, benchmark, "llvm-nm -g", rc, stderr)
    text = stdout + "\n" + stderr
    hard_hits = add_grouped_pattern_findings(
        findings,
        benchmark,
        "exported_symbols",
        text,
        OBF_SYMBOL_PATTERNS,
        "fail",
        allow_patterns,
    )
    runtime_severity = "fail" if fail_on_runtime_symbols else "warn"
    runtime_hits = add_grouped_pattern_findings(
        findings,
        benchmark,
        "exported_runtime_symbols",
        text,
        RUNTIME_SYMBOL_PATTERNS,
        runtime_severity,
        allow_patterns,
    )
    if hard_hits == 0 and runtime_hits == 0:
        findings.append(AuditFinding("ok", benchmark, "exported_symbols", "no exported obfuscator internals"))
    return findings


def audit_all_symbols(
    binary_path: pathlib.Path,
    benchmark: str,
    llvm_nm: str,
    allow_patterns: list[re.Pattern[str]],
    fail_on_local_obf_symbols: bool,
) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    rc, stdout, stderr = run_tool([llvm_nm, "-a", str(binary_path)])
    add_tool_status(findings, benchmark, "llvm-nm -a", rc, stderr)
    severity = "fail" if fail_on_local_obf_symbols else "warn"
    hits = add_grouped_pattern_findings(
        findings,
        benchmark,
        "all_symbols",
        stdout + "\n" + stderr,
        OBF_SYMBOL_PATTERNS,
        severity,
        allow_patterns,
    )
    if hits == 0:
        findings.append(AuditFinding("ok", benchmark, "all_symbols", "no local obfuscator symbol names"))
    return findings


def audit_objdump_symbols(
    binary_path: pathlib.Path,
    benchmark: str,
    llvm_objdump: str,
    allow_patterns: list[re.Pattern[str]],
    fail_on_local_obf_symbols: bool,
) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    rc, stdout, stderr = run_tool([llvm_objdump, "-t", str(binary_path)])
    add_tool_status(findings, benchmark, "llvm-objdump -t", rc, stderr)
    severity = "fail" if fail_on_local_obf_symbols else "warn"
    hits = add_grouped_pattern_findings(
        findings,
        benchmark,
        "objdump_symbols",
        stdout + "\n" + stderr,
        OBF_SYMBOL_PATTERNS,
        severity,
        allow_patterns,
    )
    if hits == 0:
        findings.append(AuditFinding("ok", benchmark, "objdump_symbols", "no obfuscator names in symbol table"))
    return findings


def audit_strings(
    binary_path: pathlib.Path,
    benchmark: str,
    strings_tool: str | None,
    allow_patterns: list[re.Pattern[str]],
) -> tuple[list[AuditFinding], int]:
    findings: list[AuditFinding] = []
    if not is_tool_available(strings_tool):
        findings.append(AuditFinding("warn", benchmark, "strings", "strings tool unavailable; skipped"))
        return findings, 1

    rc, stdout, stderr = run_tool([strings_tool or "strings", "-a", str(binary_path)])
    add_tool_status(findings, benchmark, "strings", rc, stderr)
    rules = STRING_RULES.get(benchmark, {"fail": [], "warn": OBF_SYMBOL_PATTERNS})
    fail_hits = add_grouped_pattern_findings(
        findings,
        benchmark,
        "strings",
        stdout,
        rules.get("fail", []),
        "fail",
        allow_patterns,
    )
    warn_hits = add_grouped_pattern_findings(
        findings,
        benchmark,
        "strings",
        stdout,
        rules.get("warn", []),
        "warn",
        allow_patterns,
    )
    if fail_hits == 0 and warn_hits == 0:
        findings.append(AuditFinding("ok", benchmark, "strings", "no configured high-signal strings found"))
    return findings, 0


def audit_binary(
    binary_path: pathlib.Path,
    llvm_nm: str,
    llvm_objdump: str,
    strings_tool: str | None,
    allow_patterns: list[re.Pattern[str]],
    fail_on_local_obf_symbols: bool,
    fail_on_runtime_symbols: bool,
) -> tuple[BinaryAuditResult, int]:
    benchmark = binary_path.parent.name
    findings: list[AuditFinding] = []
    baseline_path = binary_path.with_name(binary_path.name.replace(".obfuscated", ".baseline"))
    if baseline_path.exists():
        findings.append(AuditFinding("ok", benchmark, "pair", f"found baseline pair {baseline_path.name}"))
    else:
        findings.append(AuditFinding("fail", benchmark, "pair", f"missing baseline pair {baseline_path}"))

    findings.extend(audit_exported_symbols(binary_path, benchmark, llvm_nm, allow_patterns, fail_on_runtime_symbols))
    findings.extend(audit_all_symbols(binary_path, benchmark, llvm_nm, allow_patterns, fail_on_local_obf_symbols))
    findings.extend(audit_objdump_symbols(binary_path, benchmark, llvm_objdump, allow_patterns, fail_on_local_obf_symbols))
    string_findings, skipped = audit_strings(binary_path, benchmark, strings_tool, allow_patterns)
    findings.extend(string_findings)
    return BinaryAuditResult(benchmark, binary_path, findings), skipped


def print_report(results: list[BinaryAuditResult], skipped_checks: int) -> tuple[int, int]:
    failures = 0
    warnings = 0
    for result in results:
        print(f"[{result.benchmark}] {result.binary_path}")
        for finding in result.findings:
            if finding.severity == "fail":
                failures += 1
            elif finding.severity == "warn":
                warnings += 1
            print(f"[{finding.severity}] {finding.benchmark} {finding.check}: {finding.detail}")
    print("summary:")
    print(f"  benchmarks audited: {len(results)}")
    print(f"  failures: {failures}")
    print(f"  warnings: {warnings}")
    print(f"  skipped checks: {skipped_checks}")
    return failures, warnings


def write_json_report(path: pathlib.Path, results: list[BinaryAuditResult], skipped_checks: int) -> None:
    payload = {
        "benchmarks_audited": len(results),
        "skipped_checks": skipped_checks,
        "results": [
            {
                "benchmark": result.benchmark,
                "binary_path": str(result.binary_path),
                "findings": [asdict(finding) for finding in result.findings],
            }
            for result in results
        ],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="audit stripped obfuscated benchmark binaries")
    parser.add_argument("--benchmarks-dir", required=True, type=pathlib.Path)
    parser.add_argument("--llvm-nm", required=True)
    parser.add_argument("--llvm-objdump", required=True)
    parser.add_argument("--strings")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--json-out", type=pathlib.Path)
    parser.add_argument("--allow", action="append", default=[])
    parser.add_argument("--fail-on-local-obf-symbols", action="store_true")
    parser.add_argument("--fail-on-runtime-symbols", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    allow_patterns = [re.compile(pattern) for pattern in args.allow]
    benchmarks_dir = args.benchmarks_dir
    if not benchmarks_dir.exists():
        print(f"[fail] audit benchmarks-dir: missing directory {benchmarks_dir}")
        return 1 if args.strict else 0

    binaries = discover_binaries(benchmarks_dir)
    if not binaries:
        print(f"[fail] audit discovery: no obfuscated binaries under {benchmarks_dir}")
        return 1 if args.strict else 0

    results: list[BinaryAuditResult] = []
    skipped_checks = 0
    for binary_path in binaries:
        result, skipped = audit_binary(
            binary_path,
            args.llvm_nm,
            args.llvm_objdump,
            args.strings,
            allow_patterns,
            args.fail_on_local_obf_symbols,
            args.fail_on_runtime_symbols,
        )
        results.append(result)
        skipped_checks += skipped

    failures, _ = print_report(results, skipped_checks)
    if args.json_out is not None:
        write_json_report(args.json_out, results, skipped_checks)
    if args.strict and failures > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
