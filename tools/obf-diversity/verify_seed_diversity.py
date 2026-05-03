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


VM_OPCODE_PATTERN = re.compile(
    r"(?:%[-A-Za-z$._0-9]*obf\.vm\.opcode\.match[-A-Za-z$._0-9]*\s*=\s*)?"
    r"\bicmp eq i8\s+[^,\n]+,\s+(?:i8\s+)?(?P<opcode>-?\d+)"
)
VM_TRANSFORMED_OPCODE_PATTERN = re.compile(
    r"(?:%[-A-Za-z$._0-9]*obf\.vm\.opcode\.match[-A-Za-z$._0-9]*\s*=\s*)?"
    r"\bicmp eq i32\s+[^,\n]+,\s+(?:i32\s+)?(?P<opcode>-?\d+)"
)
VM_SPLIT_OPCODE_PATTERN = re.compile(
    r"\bicmp eq i32\s+[^,\n]+,\s+(?:i32\s+)?(?P<opcode>-?\d+)"
)
NAMED_SPLIT_OPCODE_COMPARE_PATTERN = re.compile(
    r"%[-A-Za-z$._0-9]*obf\.vm\.opcode\.split\.(?:low|high)\.ok"
    r"[-A-Za-z$._0-9]*\s*=\s*\bicmp eq i32\b"
)
NONLOCAL_SPLIT_RELOAD_PATTERN = re.compile(
    r"%[-A-Za-z$._0-9]*obf\.vm\.opcode\.split\.(?:low|high)\.reload"
    r"[-A-Za-z$._0-9]*\s*=\s*\bload\s+i32\s*,\s*ptr\s+"
    r"%[-A-Za-z$._0-9]*obf\.vm\.pred\.slot"
)
OPCODE_WIDEN_PATTERN = re.compile(r"\bzext\s+i8\b[^\n]*\bto\s+i32\b")
COND_BRANCH_PATTERN = re.compile(
    r"br\s+i1\s+[^,]+,\s+label\s+%(?P<true>[0-9A-Za-z$._-]+),\s+label\s+%(?P<false>[0-9A-Za-z$._-]+)"
)
UNCOND_BRANCH_PATTERN = re.compile(r"\bbr\s+label\s+%(?P<target>[0-9A-Za-z$._-]+)")
DIRECT_CALL_PATTERN = re.compile(
    r"\b(?:tail\s+|musttail\s+|notail\s+)?(?:call|invoke)\b[^@\n]*@(?P<name>[A-Za-z$._0-9-]+)\s*\("
)
ENTROPY_ACCESSOR_PATTERN = re.compile(r"__obf_load_entropy_pair(?:_v[1-9][0-9]*)?")
FUNCTION_NAME_PATTERN = re.compile(r"@(?P<name>[^\(]+)\(")
LABEL_PATTERN = re.compile(r"^(?P<label>[0-9A-Za-z_.]+):\s*(?:;.*)?$")
VM_DATA_GLOBAL_PATTERN = re.compile(
    r"@(?P<name>__obf_vm_(?:bc|g|k|ptrconst|retkey)_[A-Za-z0-9_]+)"
)

MARKER_GROUPS = {
    "handler_shapes": {
        "direct": r"vm\.handler\.shape\.direct",
        "temp": r"vm\.handler\.shape\.temp",
        "neutral": r"vm\.handler\.shape\.neutral",
    },
    "cmp_shapes": {
        "direct": r"vm\.compare\.shape\.direct",
        "xor": r"vm\.compare\.shape\.xor",
        "invert": r"vm\.compare\.shape\.invert",
        "select": r"vm\.compare\.shape\.select",
    },
    "branch_shapes": {
        "direct": r"vm\.branch\.shape\.direct",
        "invert": r"vm\.branch\.shape\.invert",
        "neutral": r"vm\.branch\.shape\.neutral",
        "select": r"vm\.branch\.shape\.select",
    },
    "memory_shapes": {
        "direct": r"vm\.memory\.shape\.direct",
        "ptr": r"vm\.memory\.shape\.ptr",
        "offset": r"vm\.memory\.shape\.offset",
        "select": r"vm\.memory\.shape\.select",
        "slot": r"vm\.memory\.shape\.slot",
    },
    "gep_shapes": {
        "direct": r"vm\.gep\.shape\.direct",
        "split": r"vm\.gep\.shape\.split",
        "ptrint": r"vm\.gep\.shape\.ptrint",
        "bias": r"vm\.gep\.shape\.bias",
        "select": r"vm\.gep\.shape\.select",
    },
    "call_shapes": {
        "direct": r"vm\.call\.shape\.direct",
        "shuffle": r"vm\.call\.shape\.shuffle",
        "token": r"vm\.call\.shape\.token",
        "slot": r"vm\.call\.shape\.slot",
    },
    "return_shapes": {
        "direct": r"vm\.return\.shape\.direct",
        "slot": r"vm\.return\.shape\.slot",
        "neutral": r"vm\.return\.shape\.neutral",
        "split": r"vm\.return\.shape\.split",
    },
    "dispatcher_shapes": {
        "direct": r"vm\.dispatch\.shape\.direct",
        "switch": r"vm\.dispatch\.shape\.switch",
        "banked": r"vm\.dispatch\.shape\.banked",
        "bank": r"vm\.dispatch\.bank",
    },
    "status_choreography": {
        "direct": r"vm\.choreo\.status\.direct",
        "temp": r"vm\.choreo\.status\.temp",
        "split": r"vm\.choreo\.status\.split",
        "select": r"vm\.choreo\.status\.select",
    },
    "route_choreography": {
        "direct": r"vm\.choreo\.route\.direct",
        "di": r"vm\.choreo\.route\.di",
        "id": r"vm\.choreo\.route\.id",
        "pack": r"vm\.choreo\.route\.pack",
        "temp": r"vm\.choreo\.route\.temp",
    },
    "slot_choreography": {
        "direct": r"vm\.choreo\.slot\.direct",
        "temp": r"vm\.choreo\.slot\.temp",
        "rotate": r"vm\.choreo\.slot\.rotate",
        "select": r"vm\.choreo\.slot\.select",
        "split": r"vm\.choreo\.slot\.split",
    },
    "table_choreography": {
        "direct": r"vm\.choreo\.table\.direct",
        "temp": r"vm\.choreo\.table\.temp",
        "bias": r"vm\.choreo\.table\.bias",
        "split": r"vm\.choreo\.table\.split",
        "select": r"vm\.choreo\.table\.select",
    },
    "dispatch_choreography": {
        "direct": r"vm\.choreo\.dispatch\.direct",
        "bias": r"vm\.choreo\.dispatch\.bias",
        "split": r"vm\.choreo\.dispatch\.split",
        "select": r"vm\.choreo\.dispatch\.select",
    },
    "vm_islands": {
        "topology": r"vm\.island\.topology\.helper_shards",
        "count": r"vm\.island\.count\.\d+",
        "entry": r"vm\.island\.entry",
        "helper": r"vm\.island\.helper",
        "helper_decode": r"vm\.island\.helper\.decode",
        "helper_dispatch": r"vm\.island\.helper\.dispatch",
        "helper_table": r"vm\.island\.helper\.table",
        "helper_cap": r"vm\.island\.helper\.cap",
        "helper_large": r"vm\.island\.helper\.large",
        "helper_split": r"vm\.island\.helper\.split",
        "next_island": r"vm\.island\.next_island",
        "route": r"vm\.island\.route",
        "root_finalize": r"vm\.island\.root\.finalize",
        "root_route": r"vm\.island\.root\.route",
        "root_small": r"vm\.island\.root\.small",
        "state": r"vm\.island\.state",
        "subhelper": r"vm\.island\.subhelper",
        "subroute": r"vm\.island\.subroute",
        "subtable_shard": r"vm\.island\.subtable\.shard",
        "table_shard": r"vm\.island\.table\.shard",
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
    "entry_thunks": {
        "direct": r"vm\.entry\.thunk\.shape\.direct",
        "neutral": r"vm\.entry\.thunk\.shape\.neutral",
        "split": r"vm\.entry\.thunk\.shape\.split",
        "definition": r"obf\.vm\.entry\.thunk",
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
    "vm_entry": r"__obf_vm_e_[A-Za-z0-9_]+",
    "vm_global": r"__obf_vm_g_[A-Za-z0-9_]+",
    "vm_target": r"__obf_vm_t_[A-Za-z0-9_]+",
    "vm_seed": r"__obf_vm_s_[A-Za-z0-9_]+",
    "vm_key": r"__obf_vm_k_[A-Za-z0-9_]+",
    "vm_case": r"__obf_vm_c_[A-Za-z0-9_]+",
    "vm_helper": r"__obf_vm_h_[A-Za-z0-9_]+",
    "vm_subhelper": r"__obf_vm_hs_[A-Za-z0-9_]+",
    "string": r"__obf_str_[A-Za-z0-9_]+",
    "entropy": r"__obf_entropy_thunk_[A-Za-z0-9_]+",
    "entropy_accessor": r"__obf_load_entropy_pair(?:_v[1-9][0-9]*)?",
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


def is_failure_block(label: str, body: str, trap_labels: set[str]) -> bool:
    branch_match = UNCOND_BRANCH_PATTERN.search(body)
    branches_to_trap = branch_match is not None and branch_match.group("target") in trap_labels
    return "fail" in label.lower() or branches_to_trap


def looks_like_opcode_block(body: str) -> bool:
    return "obf.vm.opcode" in body or bool(OPCODE_WIDEN_PATTERN.search(body))


def split_opcode_compare_count(body: str) -> int:
    named_count = len(NAMED_SPLIT_OPCODE_COMPARE_PATTERN.findall(body))
    if named_count:
        return named_count
    if not looks_like_opcode_block(body):
        return 0
    zero_matches = [
        match for match in VM_SPLIT_OPCODE_PATTERN.finditer(body)
        if int(match.group("opcode")) == 0
    ]
    return len(zero_matches) if len(zero_matches) >= 2 else 0


def stable_split_encoding(body: str) -> int:
    locality = "nonlocal" if NONLOCAL_SPLIT_RELOAD_PATTERN.search(body) else "local"
    relevant_lines = [
        line.strip()
        for line in body.splitlines()
        if "obf.vm.opcode" in line
        or "obf.vm.pred.slot" in line
        or "icmp eq i32" in line
        or "br i1" in line
    ]
    digest = hashlib.sha256((locality + "\n" + "\n".join(relevant_lines)).encode("utf-8")).hexdigest()
    return int(digest[:8], 16)


def extract_header_opcodes(function_body: str) -> list[int]:
    blocks = parse_blocks(function_body)
    trap_labels = {
        label for label, body in blocks.items() if "@llvm.trap" in body and "unreachable" in body
    }
    failure_labels = {
        label for label, body in blocks.items() if is_failure_block(label, body, trap_labels)
    }

    opcodes: list[int] = []
    for body in blocks.values():
        opcode_match = VM_OPCODE_PATTERN.search(body)
        split_encoding: int | None = None
        if opcode_match is None and split_opcode_compare_count(body) >= 2:
            split_encoding = stable_split_encoding(body)
        if opcode_match is None and split_encoding is None and looks_like_opcode_block(body):
            opcode_match = VM_TRANSFORMED_OPCODE_PATTERN.search(body)
        if opcode_match is None and split_encoding is None:
            continue
        branch_match = COND_BRANCH_PATTERN.search(body)
        if branch_match is None:
            continue
        if (
            branch_match.group("true") not in trap_labels
            and branch_match.group("false") not in trap_labels
            and branch_match.group("true") not in failure_labels
            and branch_match.group("false") not in failure_labels
        ):
            continue
        opcodes.append(
            split_encoding if split_encoding is not None else int(opcode_match.group("opcode"))
        )
    return opcodes


def is_vm_implementation(function_body: str) -> bool:
    return "indirectbr" in function_body and bool(extract_header_opcodes(function_body))


def functions_with_opcode_headers(functions: dict[str, str]) -> dict[str, str]:
    return {
        name: body for name, body in functions.items() if extract_header_opcodes(body)
    }


def is_vm_like_function(function_name: str, function_body: str) -> bool:
    return (
        function_name.startswith("__obf_vm_i_")
        or function_name.startswith("__obf_vm_h_")
        or function_name.startswith("__obf_vm_hs_")
        or "obf.vm." in function_body
        or "vm.island." in function_body
    )


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


def vm_island_structure(functions: dict[str, str], marker_text: str) -> dict[str, int]:
    vm_like_bodies = {
        name: body for name, body in functions.items() if is_vm_like_function(name, body)
    }
    first_level_helper_bodies = {
        name: body for name, body in functions.items() if name.startswith("__obf_vm_h_")
    }
    subhelper_bodies = {
        name: body
        for name, body in functions.items()
        if name.startswith("__obf_vm_hs_") or "vm.island.subhelper" in body
    }
    helper_bodies = {**first_level_helper_bodies, **subhelper_bodies}
    primary_bodies = {
        name: body for name, body in functions.items() if name.startswith("__obf_vm_i_")
    }
    helper_line_counts = [
        len([line for line in body.splitlines() if line.strip()]) for body in helper_bodies.values()
    ]
    primary_line_counts = [
        len([line for line in body.splitlines() if line.strip()]) for body in primary_bodies.values()
    ]
    first_level_helper_line_counts = [
        len([line for line in body.splitlines() if line.strip()])
        for body in first_level_helper_bodies.values()
    ]
    subhelper_line_counts = [
        len([line for line in body.splitlines() if line.strip()]) for body in subhelper_bodies.values()
    ]
    top_helper_line_counts = sorted(helper_line_counts, reverse=True)[:5]
    vm_like_line_counts = [
        len([line for line in body.splitlines() if line.strip()]) for body in vm_like_bodies.values()
    ]
    data_symbol_refs: Counter[str] = Counter()
    data_ref_function_counts: list[int] = []
    helper_data_ref_function_counts: list[int] = []
    primary_data_ref_function_counts: list[int] = []
    for body in vm_like_bodies.values():
        refs = [match.group("name") for match in VM_DATA_GLOBAL_PATTERN.finditer(body)]
        data_symbol_refs.update(refs)
        data_ref_function_counts.append(len(refs))
    for body in helper_bodies.values():
        helper_data_ref_function_counts.append(len(list(VM_DATA_GLOBAL_PATTERN.finditer(body))))
    for body in primary_bodies.values():
        primary_data_ref_function_counts.append(len(list(VM_DATA_GLOBAL_PATTERN.finditer(body))))

    primary_root_lines = max(primary_line_counts, default=0)
    helper_total_lines = sum(helper_line_counts)
    helper_max_lines = max(helper_line_counts, default=0)
    subhelper_total_lines = sum(subhelper_line_counts)
    subhelper_max_lines = max(subhelper_line_counts, default=0)
    root_helper_ratio_x1000 = (
        int((primary_root_lines * 1000) / helper_total_lines) if helper_total_lines else 0
    )
    primary_decode_markers = sum(
        body.count("obf.vm.bc") + body.count("vm.island.helper.decode")
        for body in primary_bodies.values()
    )
    helper_decode_markers = sum(
        body.count("obf.vm.bc") + body.count("vm.island.helper.decode")
        for body in helper_bodies.values()
    )
    primary_dispatch_bank_markers = sum(
        body.count("obf.vm.dispatch.index.bank") for body in primary_bodies.values()
    )
    helper_dispatch_markers = sum(
        body.count("vm.island.helper.dispatch") for body in helper_bodies.values()
    )
    marker_counts = count_markers(marker_text, MARKER_GROUPS["vm_islands"])
    return {
        "island_marker_count": sum(marker_counts.values()),
        "route_marker_count": marker_counts.get("route", 0),
        "state_marker_count": marker_counts.get("state", 0),
        "island_root_route_marker_count": marker_counts.get("root_route", 0),
        "island_state_marker_count": marker_counts.get("state", 0),
        "island_table_shard_marker_count": marker_counts.get("table_shard", 0),
        "island_subtable_shard_marker_count": marker_counts.get("subtable_shard", 0),
        "helper_split_marker_count": marker_counts.get("helper_split", 0),
        "helper_large_marker_count": marker_counts.get("helper_large", 0),
        "helper_cap_marker_count": marker_counts.get("helper_cap", 0),
        "subroute_marker_count": marker_counts.get("subroute", 0),
        "helper_count": len(helper_bodies),
        "first_level_helper_count": len(first_level_helper_bodies),
        "subhelper_count": len(subhelper_bodies),
        "vm_like_function_count": len(vm_like_bodies),
        "largest_vm_like_function_lines": max(vm_like_line_counts, default=0),
        "largest_vm_like_function_instruction_proxy": max(vm_like_line_counts, default=0),
        "largest_helper_function_lines": helper_max_lines,
        "largest_helper_instruction_proxy": helper_max_lines,
        "top_helper_instruction_proxies": top_helper_line_counts,
        "largest_first_level_helper_instruction_proxy": max(first_level_helper_line_counts, default=0),
        "largest_subhelper_instruction_proxy": subhelper_max_lines,
        "helper_instruction_proxy_total": helper_total_lines,
        "subhelper_instruction_proxy_total": subhelper_total_lines,
        "primary_vm_entry_lines": primary_root_lines,
        "primary_vm_root_size_proxy": primary_root_lines,
        "primary_root_instruction_proxy": primary_root_lines,
        "root_helper_instruction_ratio_x1000": root_helper_ratio_x1000,
        "primary_root_decode_marker_count": primary_decode_markers,
        "helper_decode_marker_count": helper_decode_markers,
        "primary_root_dispatch_bank_marker_count": primary_dispatch_bank_markers,
        "helper_dispatch_marker_count": helper_dispatch_markers,
        "top_vm_data_ref_function_refs": max(data_ref_function_counts, default=0),
        "top_primary_data_ref_function_refs": max(primary_data_ref_function_counts, default=0),
        "top_helper_data_ref_function_refs": max(helper_data_ref_function_counts, default=0),
        "top_vm_data_ref_symbol_refs": max(data_symbol_refs.values(), default=0),
    }


def vm_data_anchor_structure(functions: dict[str, str], ir_text: str) -> dict[str, Any]:
    vm_like_bodies = {
        name: body for name, body in functions.items() if is_vm_like_function(name, body)
    }
    vm_data_ref_occurrences: Counter[str] = Counter()
    for body in vm_like_bodies.values():
        refs = [match.group("name") for match in VM_DATA_GLOBAL_PATTERN.finditer(body)]
        vm_data_ref_occurrences.update(refs)

    bytecode_ref_occurrences = Counter(
        {
            name: count
            for name, count in vm_data_ref_occurrences.items()
            if name.startswith("__obf_vm_bc_")
        }
    )
    bytecode_globals = sorted(set(re.findall(r"__obf_vm_bc_[A-Za-z0-9_]+", ir_text)))
    vm_data_ref_count = sum(vm_data_ref_occurrences.values())
    max_refs_to_single_vm_data = max(vm_data_ref_occurrences.values(), default=0)
    vm_data_ref_concentration = (
        round(max_refs_to_single_vm_data / vm_data_ref_count, 4) if vm_data_ref_count else 0.0
    )
    # detect decoy globals by _d<hex> name suffix (pr27.5+) and by unreferenced
    # globals (pre-pr27.5 inference). union of both for accurate reporting.
    bytecode_named_decoys = {
        name for name in bytecode_globals if re.search(r"_d[0-9A-Fa-f]+$", name)
    }
    bytecode_named_decoy_count = len(bytecode_named_decoys)
    inferred_decoy_count = max(0, len(bytecode_globals) - len(bytecode_ref_occurrences))
    bytecode_decoy_count = max(bytecode_named_decoy_count, inferred_decoy_count)
    bytecode_real_anchor_count = max(
        0, len(bytecode_ref_occurrences) - min(bytecode_named_decoy_count, len(bytecode_ref_occurrences))
    )
    # anchor_order_hash captures the relative ordering of anchor globals in ir
    # emission order — useful for verifying that two seeds produce different layouts.
    anchor_order_hash = hash_json(bytecode_globals)

    return {
        "vm_data_ref_count": vm_data_ref_count,
        "unique_vm_data_ref_count": len(vm_data_ref_occurrences),
        "bytecode_global_count": len(bytecode_globals),
        "bytecode_ref_count": sum(bytecode_ref_occurrences.values()),
        "bytecode_anchor_count": len(bytecode_ref_occurrences),
        "bytecode_real_anchor_count": bytecode_real_anchor_count,
        "bytecode_shard_count": len(bytecode_ref_occurrences),
        "bytecode_decoy_count": bytecode_decoy_count,
        "max_refs_to_single_vm_data": max_refs_to_single_vm_data,
        "vm_data_ref_concentration": vm_data_ref_concentration,
        "anchor_assignment_hash": hash_json(sorted(vm_data_ref_occurrences.items())),
        "anchor_order_hash": anchor_order_hash,
    }


def classify_entropy_thunk_shape(function_body: str) -> str:
    if " freeze " in function_body and " select " in function_body:
        return "select"
    if function_body.count(" xor i64 ") >= 4:
        return "xor"
    if function_body.count(" add i64 ") >= 2 and function_body.count(" sub i64 ") >= 2:
        return "addsub"
    if function_body.count(" extractvalue ") >= 4 and function_body.count(" insertvalue ") >= 4:
        return "swap"
    return "direct"


def entropy_accessor_structure(functions: dict[str, str]) -> dict[str, Any]:
    thunk_shape_counts: Counter[str] = Counter()
    accessor_shape_counts: Counter[str] = Counter()
    thunk_to_accessor: list[tuple[str, str]] = []

    for name, body in sorted(functions.items()):
        accessor_names: list[str] = []
        for match in DIRECT_CALL_PATTERN.finditer(body):
            accessor_name = match.group("name")
            if not ENTROPY_ACCESSOR_PATTERN.fullmatch(accessor_name):
                continue
            accessor_names.append(accessor_name)
            accessor_shape_counts[accessor_name] += 1
            thunk_to_accessor.append((name, accessor_name))

        if not accessor_names:
            continue

        thunk_shape_counts[classify_entropy_thunk_shape(body)] += 1

    return {
        "thunk_count": sum(thunk_shape_counts.values()),
        "thunk_shape_counts": dict(sorted(thunk_shape_counts.items())),
        "accessor_count": sum(accessor_shape_counts.values()),
        "accessor_variant_count": len(accessor_shape_counts),
        "accessor_shape_counts": dict(sorted(accessor_shape_counts.items())),
        "dominant_accessor": max(accessor_shape_counts.values(), default=0),
        "callgraph_hash": hash_json(thunk_to_accessor) if thunk_to_accessor else "",
    }


def fingerprint_ir(ir_text: str, marker_text: str) -> dict[str, Any]:
    functions = parse_functions(ir_text)
    marker_functions = parse_functions(marker_text)
    vm_bodies = {name: body for name, body in functions.items() if is_vm_implementation(body)}
    opcode_bodies = functions_with_opcode_headers(marker_functions)
    if not opcode_bodies:
        opcode_bodies = functions_with_opcode_headers(functions)
    if not opcode_bodies:
        opcode_bodies = vm_bodies
    opcode_sequences = sorted(extract_header_opcodes(body) for body in opcode_bodies.values())
    opcode_histograms = sorted(
        tuple(sorted(Counter(extract_header_opcodes(body)).items())) for body in opcode_bodies.values()
    )
    structures = sorted(
        tuple(sorted(vm_structure(body).items())) for body in vm_bodies.values()
    )
    symbol_sets = {
        name: sorted(set(re.findall(pattern, ir_text)))
        for name, pattern in SYMBOL_PATTERNS.items()
    }
    island_structure = vm_island_structure(functions, marker_text)
    data_anchor_structure = vm_data_anchor_structure(functions, ir_text)
    entropy_structure = entropy_accessor_structure(functions)

    fingerprint: dict[str, Any] = {
        "vm_function_count": len(vm_bodies) if vm_bodies else len(opcode_bodies),
        "opcode_sequences": opcode_sequences,
        "opcode_histograms": opcode_histograms,
        "opcode_map_hash": hash_json(opcode_sequences) if opcode_sequences else "",
        "vm_structures": structures,
        "vm_structure_hash": hash_json(structures) if structures else "",
        "symbol_sets": symbol_sets,
        "symbol_name_hash": hash_json(symbol_sets),
        "vm_island_structure": island_structure,
        "vm_island_hash": hash_json(island_structure)
        if island_structure["island_marker_count"] or island_structure["helper_count"]
        else "",
        "vm_data_anchor_structure": data_anchor_structure,
        "vm_data_anchor_hash": hash_json(data_anchor_structure)
        if data_anchor_structure["vm_data_ref_count"] or data_anchor_structure["bytecode_global_count"]
        else "",
        "entropy_accessor_structure": entropy_structure,
        "entropy_accessor_hash": hash_json(entropy_structure)
        if entropy_structure["accessor_count"] or entropy_structure["thunk_count"]
        else "",
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
    if dimension == "cmp_shapes":
        return fingerprint["cmp_shapes"]
    if dimension == "branch_shapes":
        return fingerprint["branch_shapes"]
    if dimension == "memory_shapes":
        return fingerprint["memory_shapes"]
    if dimension == "gep_shapes":
        return fingerprint["gep_shapes"]
    if dimension == "call_shapes":
        return fingerprint["call_shapes"]
    if dimension == "return_shapes":
        return fingerprint["return_shapes"]
    if dimension == "dispatcher_shapes":
        return fingerprint["dispatcher_shapes"]
    if dimension == "status_choreography":
        return fingerprint["status_choreography"]
    if dimension == "route_choreography":
        return fingerprint["route_choreography"]
    if dimension == "slot_choreography":
        return fingerprint["slot_choreography"]
    if dimension == "table_choreography":
        return fingerprint["table_choreography"]
    if dimension == "dispatch_choreography":
        return fingerprint["dispatch_choreography"]
    if dimension == "vm_islands":
        return fingerprint["vm_island_hash"]
    if dimension == "vm_data_anchors":
        return fingerprint["vm_data_anchor_hash"]
    if dimension == "pointer_materialization":
        return fingerprint["pointer_materialization"]
    if dimension == "entropy_thunks":
        return fingerprint["entropy_thunks"]
    if dimension == "entropy_accessors":
        return fingerprint["entropy_accessor_hash"]
    if dimension == "entry_thunks":
        return fingerprint["entry_thunks"]
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
        "cmp_shapes",
        "branch_shapes",
        "memory_shapes",
        "gep_shapes",
        "call_shapes",
        "return_shapes",
        "dispatcher_shapes",
        "status_choreography",
        "route_choreography",
        "slot_choreography",
        "table_choreography",
        "dispatch_choreography",
        "vm_islands",
        "vm_data_anchors",
        "pointer_materialization",
        "entropy_thunks",
        "entropy_accessors",
        "entry_thunks",
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
        primary = [
            statuses[dimension]
            for dimension in (
                "opcode_mapping",
                "handler_shapes",
                "cmp_shapes",
                "branch_shapes",
                "memory_shapes",
                "gep_shapes",
                "return_shapes",
                "dispatcher_shapes",
                "status_choreography",
                "route_choreography",
                "slot_choreography",
                "table_choreography",
                "dispatch_choreography",
                "vm_islands",
                "vm_data_anchors",
                "vm_structure",
            )
        ]
        if "different" not in primary:
            failures.append(
                "vm output had no opcode, handler-shape, dispatcher-shape, island, or structure diversity"
            )
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
        "cmp_shapes",
        "branch_shapes",
        "memory_shapes",
        "gep_shapes",
        "call_shapes",
        "return_shapes",
        "dispatcher_shapes",
        "status_choreography",
        "route_choreography",
        "slot_choreography",
        "table_choreography",
        "dispatch_choreography",
        "vm_islands",
        "pointer_materialization",
        "entropy_thunks",
        "entropy_accessors",
        "entry_thunks",
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
        "entropy_accessors": args.require_entropy_thunk_diversity,
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
