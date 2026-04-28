#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any


VM_OPCODE_PATTERN = re.compile(r"icmp eq i8\s+[^,]+,\s+(?:i8\s+)?(?P<opcode>-?\d+)")
COND_BRANCH_PATTERN = re.compile(
    r"br\s+i1\s+[^,]+,\s+label\s+%(?P<true>[0-9A-Za-z$._-]+),\s+label\s+%(?P<false>[0-9A-Za-z$._-]+)"
)
FUNCTION_NAME_PATTERN = re.compile(r"@(?P<name>[^\(]+)\(")
LABEL_PATTERN = re.compile(r"^(?P<label>[0-9A-Za-z_.]+):\s*(?:;.*)?$")

MARKER_GROUPS = {
    "handler_shapes": {
        "direct": r"vm\.handler\.shape\.direct",
        "temp": r"vm\.handler\.shape\.temp",
        "neutral": r"vm\.handler\.shape\.neutral",
    },
    "pointer_materialization": {
        "direct": r"ptrmat\.direct",
        "split": r"ptrmat\.split",
        "addsub": r"ptrmat\.addsub",
    },
    "entropy_thunks": {
        "direct": r"entropy\.thunk\.direct",
        "swap": r"entropy\.thunk\.swap",
        "xor": r"entropy\.thunk\.xor",
        "addsub": r"entropy\.thunk\.addsub",
        "select": r"entropy\.thunk\.select",
        "definition": r"@__obf_entropy_thunk_",
    },
    "mba_shapes": {
        "zero_xor_pair": r"obf\.mba\.zero\.xor_pair",
        "zero_add_sub_pair": r"obf\.mba\.zero\.add_sub_pair",
        "zero_sub_pair": r"obf\.mba\.zero\.sub_pair",
        "zero_rotate_xor_pair": r"obf\.mba\.zero\.rotate_xor_pair",
        "zero_cmp_select_pair": r"obf\.mba\.zero\.cmp_select_pair",
        "entangle": r"obf\.entangle\.[A-Za-z0-9_.]+",
    },
}

SYMBOL_PATTERNS = {
    "vm_impl": r"__obf_vm_i_[A-Za-z0-9_]+",
    "vm_global": r"__obf_vm_g_[A-Za-z0-9_]+",
    "vm_target": r"__obf_vm_t_[A-Za-z0-9_]+",
    "vm_seed": r"__obf_vm_s_[A-Za-z0-9_]+",
    "vm_key": r"__obf_vm_k_[A-Za-z0-9_]+",
    "vm_case": r"__obf_vm_c_[A-Za-z0-9_]+",
    "string": r"__obf_str_[A-Za-z0-9_]+",
    "entropy": r"__obf_entropy_thunk_[A-Za-z0-9_]+",
}


@dataclass(frozen=True)
class BenchmarkSpec:
    name: str
    source: str
    config: str
    compiler_arg: str
    std_flag: str


BENCHMARKS = {
    "license_demo": BenchmarkSpec(
        name="license_demo",
        source="benchmarks/corpus/license_demo.cpp",
        config="benchmarks/config/license_demo.yaml",
        compiler_arg="clangxx",
        std_flag="-std=c++23",
    ),
    "config_demo": BenchmarkSpec(
        name="config_demo",
        source="benchmarks/corpus/config_demo.c",
        config="benchmarks/config/config_demo.yaml",
        compiler_arg="clang",
        std_flag="-std=c17",
    ),
    "vm_workflow_demo": BenchmarkSpec(
        name="vm_workflow_demo",
        source="benchmarks/corpus/vm_workflow_demo.c",
        config="benchmarks/config/vm_workflow_demo.yaml",
        compiler_arg="clang",
        std_flag="-std=c17",
    ),
}


def run_command(command: list[str], *, cwd: Path | None = None) -> None:
    printable = " ".join(command)
    print(f"running: {printable}")
    subprocess.run(command, cwd=cwd, check=True)


def parse_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def parse_functions(ir_text: str) -> dict[str, str]:
    functions: dict[str, str] = {}
    lines = ir_text.splitlines()
    line_index = 0
    while line_index < len(lines):
        line = lines[line_index]
        if not line.startswith("define "):
            line_index += 1
            continue

        header_lines = [line]
        while not header_lines[-1].rstrip().endswith("{"):
            line_index += 1
            if line_index >= len(lines):
                raise AssertionError("unterminated function header")
            header_lines.append(lines[line_index])

        header_text = " ".join(part.strip() for part in header_lines)
        name_match = FUNCTION_NAME_PATTERN.search(header_text)
        if name_match is None:
            raise AssertionError(f"unable to parse function name from header: {header_text}")

        function_name = name_match.group("name")
        line_index += 1
        body_lines: list[str] = []
        while line_index < len(lines) and lines[line_index] != "}":
            body_lines.append(lines[line_index])
            line_index += 1
        if line_index >= len(lines):
            raise AssertionError(f"unterminated function body: {function_name}")

        functions[function_name] = "\n".join(body_lines) + ("\n" if body_lines else "")
        line_index += 1
    return functions


def parse_blocks(function_body: str) -> dict[str, str]:
    blocks: dict[str, str] = {}
    current_label: str | None = None
    current_body: list[str] = []
    for line in function_body.splitlines():
        label_match = LABEL_PATTERN.match(line)
        if label_match is not None:
            if current_label is not None:
                blocks[current_label] = "\n".join(current_body) + ("\n" if current_body else "")
            current_label = label_match.group("label")
            current_body = []
            continue
        if current_label is not None:
            current_body.append(line)
    if current_label is not None:
        blocks[current_label] = "\n".join(current_body) + ("\n" if current_body else "")
    return blocks


def extract_header_opcodes(function_body: str) -> list[int]:
    blocks = parse_blocks(function_body)
    trap_labels = {
        label for label, body in blocks.items() if "@llvm.trap" in body and "unreachable" in body
    }

    opcodes: list[int] = []
    for body in blocks.values():
        opcode_match = VM_OPCODE_PATTERN.search(body)
        if opcode_match is None:
            continue
        branch_match = COND_BRANCH_PATTERN.search(body)
        if branch_match is None:
            continue
        if branch_match.group("true") not in trap_labels and branch_match.group("false") not in trap_labels:
            continue
        opcodes.append(int(opcode_match.group("opcode")))
    return opcodes


def is_vm_implementation(function_body: str) -> bool:
    return "indirectbr" in function_body and bool(extract_header_opcodes(function_body))


def count_markers(ir_text: str, patterns: dict[str, str]) -> dict[str, int]:
    return {name: len(re.findall(pattern, ir_text)) for name, pattern in patterns.items()}


def hash_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:16]


def vm_structure(function_body: str) -> dict[str, int]:
    return {
        "basic_blocks": len(parse_blocks(function_body)),
        "indirectbr": len(re.findall(r"\bindirectbr\b", function_body)),
        "switch": len(re.findall(r"\bswitch\b", function_body)),
        "calls": len(re.findall(r"\bcall\b", function_body)),
        "loads": len(re.findall(r"\bload\b", function_body)),
        "stores": len(re.findall(r"\bstore\b", function_body)),
        "traps": len(re.findall(r"@llvm\.trap", function_body)),
    }


def fingerprint_ir(ir_text: str, marker_text: str) -> dict[str, Any]:
    functions = parse_functions(ir_text)
    vm_bodies = {name: body for name, body in functions.items() if is_vm_implementation(body)}
    opcode_sequences = sorted(extract_header_opcodes(body) for body in vm_bodies.values())
    opcode_histograms = sorted(
        tuple(sorted(Counter(extract_header_opcodes(body)).items())) for body in vm_bodies.values()
    )
    structures = sorted(
        tuple(sorted(vm_structure(body).items())) for body in vm_bodies.values()
    )
    symbol_sets = {
        name: sorted(set(re.findall(pattern, ir_text)))
        for name, pattern in SYMBOL_PATTERNS.items()
    }

    fingerprint: dict[str, Any] = {
        "vm_function_count": len(vm_bodies),
        "opcode_sequences": opcode_sequences,
        "opcode_histograms": opcode_histograms,
        "opcode_map_hash": hash_json(opcode_sequences) if opcode_sequences else "",
        "vm_structures": structures,
        "vm_structure_hash": hash_json(structures) if structures else "",
        "symbol_sets": symbol_sets,
        "symbol_name_hash": hash_json(symbol_sets),
    }
    for group_name, patterns in MARKER_GROUPS.items():
        counts = count_markers(marker_text, patterns)
        fingerprint[group_name] = counts
        fingerprint[f"{group_name}_hash"] = hash_json(counts) if any(counts.values()) else ""
    return fingerprint


def dimension_value(fingerprint: dict[str, Any], dimension: str) -> Any:
    if dimension == "opcode_mapping":
        return fingerprint["opcode_map_hash"]
    if dimension == "handler_shapes":
        return fingerprint["handler_shapes"]
    if dimension == "pointer_materialization":
        return fingerprint["pointer_materialization"]
    if dimension == "entropy_thunks":
        return fingerprint["entropy_thunks"]
    if dimension == "mba_shapes":
        return fingerprint["mba_shapes"]
    if dimension == "symbol_names":
        return fingerprint["symbol_name_hash"]
    if dimension == "vm_structure":
        return fingerprint["vm_structure_hash"]
    raise KeyError(dimension)


def is_applicable(values: list[Any]) -> bool:
    for value in values:
        if isinstance(value, dict):
            if any(value.values()):
                return True
        elif value:
            return True
    return False


def values_differ(values: list[Any]) -> bool:
    serialized = {json.dumps(value, sort_keys=True) for value in values}
    return len(serialized) > 1


def generate_benchmark_ir(
    args: argparse.Namespace,
    benchmark: BenchmarkSpec,
    seed: str,
    baseline_path: Path,
    output_path: Path,
    marker_path: Path,
) -> None:
    compiler = Path(getattr(args, benchmark.compiler_arg))
    source_path = args.source_dir / benchmark.source
    config_path = args.source_dir / benchmark.config
    output_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.parent.mkdir(parents=True, exist_ok=True)

    if not baseline_path.exists():
        run_command(
            [
                str(compiler),
                benchmark.std_flag,
                "-O1",
                "-fno-inline",
                "-fno-inline-functions",
                "-S",
                "-emit-llvm",
                str(source_path),
                "-o",
                str(baseline_path),
            ]
        )

    run_command(
        [
            str(args.opt),
            "-load-pass-plugin",
            str(args.plugin),
            f"--obf-config={config_path}",
            f"--obf-seed={seed}",
            "-passes=obf-safe-pipeline",
            "-S",
            str(baseline_path),
            "-o",
            str(output_path),
        ]
    )
    run_command(
        [
            str(args.opt),
            "-load-pass-plugin",
            str(args.plugin),
            f"--obf-config={config_path}",
            f"--obf-seed={seed}",
            "-passes=obf-vm",
            "-S",
            str(baseline_path),
            "-o",
            str(marker_path),
        ]
    )


def compare_benchmark(seeds: list[str], fingerprints: dict[str, dict[str, Any]]) -> tuple[dict[str, str], list[str]]:
    dimensions = [
        "opcode_mapping",
        "handler_shapes",
        "pointer_materialization",
        "entropy_thunks",
        "mba_shapes",
        "symbol_names",
        "vm_structure",
    ]
    statuses: dict[str, str] = {}
    failures: list[str] = []
    for dimension in dimensions:
        values = [dimension_value(fingerprints[seed], dimension) for seed in seeds]
        if not is_applicable(values):
            statuses[dimension] = "skipped"
        elif values_differ(values):
            statuses[dimension] = "different"
        else:
            statuses[dimension] = "same"

    if any(fingerprints[seed]["vm_function_count"] for seed in seeds):
        primary = [statuses[dimension] for dimension in ("opcode_mapping", "handler_shapes", "vm_structure")]
        if "different" not in primary:
            failures.append("vm output had no opcode, handler-shape, or structure diversity")
    return statuses, failures


def bool_arg(value: str) -> bool:
    normalized = value.lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise argparse.ArgumentTypeError(f"invalid boolean value: {value}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="verify seed-driven obfuscation diversity")
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--plugin", type=Path, required=True)
    parser.add_argument("--opt", type=Path, required=True)
    parser.add_argument("--clang", type=Path, required=True)
    parser.add_argument("--clangxx", type=Path, required=True)
    parser.add_argument("--llvm-link", type=Path)
    parser.add_argument("--seeds", default="10101,20202,30303")
    parser.add_argument("--benchmarks", default="license_demo,config_demo,vm_workflow_demo")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--keep-going", action="store_true")
    parser.add_argument("--min-different-dimensions", type=int, default=3)
    parser.add_argument("--require-handler-diversity", type=bool_arg, default=True)
    parser.add_argument("--require-mba-diversity", type=bool_arg, default=True)
    parser.add_argument("--require-entropy-thunk-diversity", type=bool_arg, default=True)
    parser.add_argument("--require-pointer-materialization-diversity", type=bool_arg, default=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    seeds = parse_csv(args.seeds)
    benchmark_names = parse_csv(args.benchmarks)
    if len(seeds) < 2:
        raise AssertionError("expected at least two explicit seeds")
    unknown = sorted(set(benchmark_names) - set(BENCHMARKS))
    if unknown:
        raise AssertionError(f"unknown benchmark(s): {', '.join(unknown)}")

    report: dict[str, Any] = {"benchmarks": {}, "summary": {}}
    benchmark_statuses: dict[str, dict[str, str]] = {}
    failures: list[str] = []

    for benchmark_name in benchmark_names:
        benchmark = BENCHMARKS[benchmark_name]
        baseline_path = args.build_dir / "diversity" / benchmark.name / "baseline.ll"
        seed_fingerprints: dict[str, dict[str, Any]] = {}
        report["benchmarks"][benchmark.name] = {}
        for seed in seeds:
            obfuscated_path = args.build_dir / "diversity" / benchmark.name / seed / "obfuscated.ll"
            marker_path = args.build_dir / "diversity" / benchmark.name / seed / "marker-probe.ll"
            try:
                generate_benchmark_ir(args, benchmark, seed, baseline_path, obfuscated_path, marker_path)
                ir_text = obfuscated_path.read_text(encoding="utf-8")
                marker_text = marker_path.read_text(encoding="utf-8")
                fingerprint = fingerprint_ir(ir_text, marker_text)
                seed_fingerprints[seed] = fingerprint
                report["benchmarks"][benchmark.name][seed] = fingerprint
            except Exception as error:
                failures.append(f"{benchmark.name}/{seed}: {error}")
                if not args.keep_going:
                    raise

        if len(seed_fingerprints) != len(seeds):
            continue
        statuses, benchmark_failures = compare_benchmark(seeds, seed_fingerprints)
        benchmark_statuses[benchmark.name] = statuses
        failures.extend(f"{benchmark.name}: {failure}" for failure in benchmark_failures)

    dimension_names = [
        "opcode_mapping",
        "handler_shapes",
        "pointer_materialization",
        "entropy_thunks",
        "mba_shapes",
        "symbol_names",
        "vm_structure",
    ]
    different_dimensions = {
        dimension
        for statuses in benchmark_statuses.values()
        for dimension, status in statuses.items()
        if status == "different"
    }
    skipped_dimensions = sum(
        1 for statuses in benchmark_statuses.values() for status in statuses.values() if status == "skipped"
    )

    required_dimensions = {
        "handler_shapes": args.require_handler_diversity,
        "pointer_materialization": args.require_pointer_materialization_diversity,
        "entropy_thunks": args.require_entropy_thunk_diversity,
        "mba_shapes": args.require_mba_diversity,
    }
    for dimension, required in required_dimensions.items():
        if required and any(statuses.get(dimension) != "skipped" for statuses in benchmark_statuses.values()):
            if dimension not in different_dimensions:
                failures.append(f"required dimension did not differ across seeds: {dimension}")

    if args.strict and len(different_dimensions) < args.min_different_dimensions:
        failures.append(
            f"only {len(different_dimensions)} diversity dimension(s) differed; "
            f"expected at least {args.min_different_dimensions}"
        )

    for benchmark_name in benchmark_names:
        statuses = benchmark_statuses.get(benchmark_name, {})
        print(f"benchmark: {benchmark_name}")
        print(f"  seeds: {', '.join(seeds)}")
        for dimension in dimension_names:
            print(f"  {dimension.replace('_', ' ')}: {statuses.get(dimension, 'failed')}")

    report["summary"] = {
        "benchmarks_checked": len(benchmark_statuses),
        "dimensions_different": len(different_dimensions),
        "dimensions_skipped": skipped_dimensions,
        "failures": len(failures),
        "failure_messages": failures,
    }
    print("summary:")
    print(f"  benchmarks checked: {len(benchmark_statuses)}")
    print(f"  dimensions different: {len(different_dimensions)}")
    print(f"  dimensions skipped: {skipped_dimensions}")
    print(f"  failures: {len(failures)}")
    for failure in failures:
        print(f"  failure: {failure}")

    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
