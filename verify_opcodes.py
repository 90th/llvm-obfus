#!/usr/bin/env python3

from collections import Counter
import re
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parent
LICENSE_BASELINE_IR = ROOT / "build/benchmarks/license_demo/license_demo.baseline.ll"
LICENSE_OBF_IR = ROOT / "build/benchmarks/license_demo/license_demo.obfuscated.ll"
CONFIG_BASELINE_IR = ROOT / "build/benchmarks/config_demo/config_demo.baseline.ll"
CONFIG_OBF_IR = ROOT / "build/benchmarks/config_demo/config_demo.obfuscated.ll"


WRAPPER_CALL_PATTERN = re.compile(
    r"call\s+.*?@(?P<impl>[_A-Za-z$\.0-9]+)\([^\n]*,\s*i64\s+%[0-9A-Za-z_.]+\)"
)
EQ_OPCODE_PATTERN = re.compile(r"icmp eq i8\s+[^,]+,\s+(?:i8\s+)?(?P<opcode>-?\d+)")
COND_BRANCH_PATTERN = re.compile(
    r"br\s+i1\s+[^,]+,\s+label\s+%(?P<true>[0-9A-Za-z$._-]+),\s+label\s+%(?P<false>[0-9A-Za-z$._-]+)"
)
ASSIGNED_VALUE_PATTERN = re.compile(r"%(?:[-A-Za-z$._0-9]+)\s*=\s+(?P<opcode>[a-z][a-z0-9]*)\b")
ASSIGNED_CALL_PATTERN = re.compile(
    r"%(?:[-A-Za-z$._0-9]+)\s*=\s+(?:(?:tail|musttail|notail)\s+)?(?:call|invoke)\b"
)
DIRECT_CALL_PATTERN = re.compile(r"(?:(?:tail|musttail|notail)\s+)?(?:call|invoke)\b")


@dataclass(frozen=True)
class VmFunctionSummary:
    display_name: str
    implementation_name: str
    logical_sequence: list[str]
    opcode_map: dict[str, int]


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
        name_match = re.search(r"@(?P<name>[^\(]+)\(", header_text)
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
        label_match = re.match(r"^(?P<label>[0-9A-Za-z_.]+):\s*(?:;.*)?$", line)
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


def find_wrapper_implementations(function_bodies: dict[str, str]) -> dict[str, str]:
    wrappers: dict[str, str] = {}
    for function_name, body in function_bodies.items():
        if is_vm_implementation_body(body):
            continue
        match = WRAPPER_CALL_PATTERN.search(body)
        if match is None:
            continue
        implementation_name = match.group("impl")
        implementation_body = function_bodies.get(implementation_name)
        if implementation_body is None:
            continue
        if not is_vm_implementation_body(implementation_body):
            continue
        wrappers[function_name] = implementation_name
    return wrappers


def classify_store_instruction(stripped: str) -> str:
    store_match = re.search(r"store\s+([^,]+),", stripped)
    if store_match is None:
        return "store_int"
    store_type = store_match.group(1).strip()
    if store_type.startswith("ptr"):
        return "store_ptr"
    if store_type.startswith("<"):
        return "store_vector"
    if store_type.startswith(("half", "bfloat", "float", "double", "fp128", "x86_fp80")):
        return "store_float"
    return "store_int"


def classify_load_kind(stripped: str) -> str:
    load_match = re.search(r"load\s+([^,]+),", stripped)
    if load_match is None:
        return "load_int"
    load_type = load_match.group(1).strip()
    if load_type.startswith("ptr"):
        return "load_ptr"
    if load_type.startswith("<"):
        return "load_vector"
    if load_type.startswith(("half", "bfloat", "float", "double", "fp128", "x86_fp80")):
        return "load_float"
    return "load_int"


def classify_baseline_instruction(line: str) -> str | None:
    stripped = line.strip()
    if not stripped or stripped.startswith(";"):
        return None
    if stripped.endswith(":"):
        return None
    if stripped.startswith("ret "):
        return "ret"
    if stripped.startswith("br "):
        return "jump" if "i1 " not in stripped else "branch"
    if stripped.startswith("switch "):
        return "switch_op"
    if stripped.startswith("unreachable"):
        return "unreachable_op"
    if stripped.startswith("store "):
        return classify_store_instruction(stripped)
    if DIRECT_CALL_PATTERN.match(stripped):
        return "call"
    if ASSIGNED_CALL_PATTERN.match(stripped):
        return "call"

    value_match = ASSIGNED_VALUE_PATTERN.match(stripped)
    if value_match is None:
        return None

    opcode = value_match.group("opcode")
    if opcode in {
        "add",
        "sub",
        "mul",
        "udiv",
        "sdiv",
        "urem",
        "srem",
        "shl",
        "lshr",
        "ashr",
        "and",
        "or",
        "xor",
        "fadd",
        "fsub",
        "fmul",
        "fdiv",
        "frem",
    }:
        return opcode
    if opcode in {
        "trunc",
        "zext",
        "sext",
        "fptrunc",
        "fpext",
        "uitofp",
        "sitofp",
        "fptoui",
        "fptosi",
        "ptrtoint",
        "inttoptr",
        "bitcast",
        "addrspacecast",
    }:
        cast_map = {
            "fptrunc": "fp_trunc",
            "fpext": "fp_ext",
            "uitofp": "ui_to_fp",
            "sitofp": "si_to_fp",
            "fptoui": "fp_to_ui",
            "fptosi": "fp_to_si",
            "ptrtoint": "ptr_to_int",
            "inttoptr": "int_to_ptr",
            "addrspacecast": "addrspace_cast",
        }
        return cast_map.get(opcode, opcode)
    if opcode == "freeze":
        return "freeze"
    if opcode == "icmp":
        predicate_match = re.search(r"icmp\s+(eq|ne|ugt|uge|ult|ule|sgt|sge|slt|sle)\b", stripped)
        return f"icmp_{predicate_match.group(1)}" if predicate_match else "icmp"
    if opcode == "fcmp":
        predicate_match = re.search(
            r"fcmp\s+(false|oeq|ogt|oge|olt|ole|one|ord|uno|ueq|ugt|uge|ult|ule|une|true)\b",
            stripped,
        )
        return f"fcmp_{predicate_match.group(1)}" if predicate_match else "fcmp"
    if opcode == "select":
        return "select"
    if opcode == "load":
        return classify_load_kind(stripped)
    if opcode == "getelementptr":
        return "gep_inbounds" if " inbounds " in f" {stripped} " else "gep"
    return None


def extract_baseline_logical_sequence(
    function_bodies: dict[str, str], function_name: str
) -> list[str]:
    body = function_bodies.get(function_name)
    if body is None:
        raise AssertionError(f"missing baseline function: {function_name}")

    sequence: list[str] = []
    for line in body.splitlines():
        logical_opcode = classify_baseline_instruction(line)
        if logical_opcode is not None:
            sequence.append(logical_opcode)

    if not sequence:
        raise AssertionError(f"baseline function has no logical opcode sequence: {function_name}")
    return sequence


def extract_header_opcodes(function_body: str) -> list[int]:
    blocks = parse_blocks(function_body)
    trap_labels = {
        label
        for label, body in blocks.items()
        if "@llvm.trap" in body and "unreachable" in body
    }

    header_opcodes: list[int] = []
    for body in blocks.values():
        opcode_match = EQ_OPCODE_PATTERN.search(body)
        if opcode_match is None:
            continue

        branch_match = COND_BRANCH_PATTERN.search(body)
        if branch_match is None:
            continue

        true_target = branch_match.group("true")
        false_target = branch_match.group("false")
        if true_target not in trap_labels and false_target not in trap_labels:
            continue

        header_opcodes.append(int(opcode_match.group("opcode")))

    return header_opcodes


def is_vm_implementation_body(function_body: str) -> bool:
    return "indirectbr" in function_body and bool(extract_header_opcodes(function_body))


def build_family_opcode_map(
    function_name: str, logical_sequence: list[str], physical_sequence: list[int]
) -> dict[str, int]:
    if len(logical_sequence) != len(physical_sequence):
        raise AssertionError(
            f"{function_name}: baseline/logical count mismatch "
            f"({len(logical_sequence)} logical vs {len(physical_sequence)} vm headers)"
        )

    opcode_map: dict[str, int] = {}
    for logical_family, physical_opcode in zip(logical_sequence, physical_sequence):
        existing = opcode_map.get(logical_family)
        if existing is None:
            opcode_map[logical_family] = physical_opcode
            continue
        if existing != physical_opcode:
            raise AssertionError(
                f"{function_name}: logical family {logical_family} used multiple physical opcodes "
                f"({existing} and {physical_opcode})"
            )

    return opcode_map


def extract_vm_summary(
    obfuscated_ir_text: str,
    baseline_ir_text: str,
) -> list[VmFunctionSummary]:
    function_bodies = parse_functions(obfuscated_ir_text)
    baseline_function_bodies = parse_functions(baseline_ir_text)
    wrapper_to_impl = find_wrapper_implementations(function_bodies)

    summaries: list[VmFunctionSummary] = []
    for wrapper_name, implementation_name in wrapper_to_impl.items():
        implementation_body = function_bodies.get(implementation_name)
        if implementation_body is None:
            continue

        if not is_vm_implementation_body(implementation_body):
            continue

        physical_sequence = extract_header_opcodes(implementation_body)
        if not physical_sequence:
            continue

        logical_sequence = extract_baseline_logical_sequence(
            baseline_function_bodies, wrapper_name
        )
        opcode_map = build_family_opcode_map(
            wrapper_name, logical_sequence, physical_sequence
        )

        summaries.append(
            VmFunctionSummary(
                display_name=wrapper_name,
                implementation_name=implementation_name,
                logical_sequence=logical_sequence,
                opcode_map=opcode_map,
            )
        )

    return summaries


def print_summary(title: str, summaries: list[VmFunctionSummary]) -> None:
    print(title)
    if not summaries:
        print("  <no benchmark vm functions found>")
        return

    for summary in summaries:
        counts = Counter(summary.logical_sequence)
        print(f"  {summary.display_name} -> {summary.implementation_name}")
        for logical_family, opcode_value in summary.opcode_map.items():
            count_suffix = ""
            if counts[logical_family] > 1:
                count_suffix = f" x{counts[logical_family]}"
            print(f"    {logical_family}{count_suffix}: {opcode_value}")


@dataclass(frozen=True)
class OpcodeComparison:
    left_name: str
    right_name: str
    differing: list[tuple[str, int, int]]
    matching: list[tuple[str, int]]


def compare_common_opcode_families(
    left: list[VmFunctionSummary], right: list[VmFunctionSummary]
) -> list[OpcodeComparison]:
    comparisons: list[OpcodeComparison] = []
    for left_summary in left:
        for right_summary in right:
            common_families = sorted(set(left_summary.opcode_map) & set(right_summary.opcode_map))
            if not common_families:
                continue

            differing: list[tuple[str, int, int]] = []
            matching: list[tuple[str, int]] = []
            for family in common_families:
                left_opcode = left_summary.opcode_map[family]
                right_opcode = right_summary.opcode_map[family]
                if left_opcode == right_opcode:
                    matching.append((family, left_opcode))
                else:
                    differing.append((family, left_opcode, right_opcode))

            comparisons.append(
                OpcodeComparison(
                    left_name=left_summary.display_name,
                    right_name=right_summary.display_name,
                    differing=differing,
                    matching=matching,
                )
            )

    return comparisons


def print_comparisons(title: str, comparisons: list[OpcodeComparison]) -> None:
    print(title)
    if not comparisons:
        print("  <no shared logical opcode families>")
        return

    for comparison in comparisons:
        print(f"  {comparison.left_name} vs {comparison.right_name}")
        if comparison.differing:
            diff_text = ", ".join(
                f"{family}: {left_opcode}->{right_opcode}"
                for family, left_opcode, right_opcode in comparison.differing
            )
            print(f"    differing: {diff_text}")
        if comparison.matching:
            match_text = ", ".join(
                f"{family}: {opcode}" for family, opcode in comparison.matching
            )
            print(f"    matching: {match_text}")


def main() -> int:
    required_paths = (
        LICENSE_BASELINE_IR,
        LICENSE_OBF_IR,
        CONFIG_BASELINE_IR,
        CONFIG_OBF_IR,
    )
    for path in required_paths:
        if not path.exists():
            print(f"missing IR file: {path}", file=sys.stderr)
            return 1

    license_baseline_text = LICENSE_BASELINE_IR.read_text(encoding="utf-8")
    license_obf_text = LICENSE_OBF_IR.read_text(encoding="utf-8")
    config_baseline_text = CONFIG_BASELINE_IR.read_text(encoding="utf-8")
    config_obf_text = CONFIG_OBF_IR.read_text(encoding="utf-8")

    license_summaries = extract_vm_summary(license_obf_text, license_baseline_text)
    config_summaries = extract_vm_summary(config_obf_text, config_baseline_text)

    print_summary("license_demo opcode mapping:", license_summaries)
    print_summary("config_demo opcode mapping:", config_summaries)

    if not license_summaries or not config_summaries:
        raise AssertionError("expected benchmark vm opcode mappings in both benchmark IR files")

    comparisons = compare_common_opcode_families(config_summaries, license_summaries)
    print_comparisons("cross-demo opcode comparison:", comparisons)
    if not comparisons:
        raise AssertionError(
            "expected shared logical opcode families across config_demo and license_demo"
        )

    if not any(comparison.differing for comparison in comparisons):
        raise AssertionError(
            "expected at least one shared logical opcode family to use a different physical encoding"
        )

    print("opcode scrambling verified: shared logical opcode families use different physical encodings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
