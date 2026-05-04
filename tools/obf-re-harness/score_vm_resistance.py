#!/usr/bin/env python3

"""
emit a deterministic json report describing llvm-ir vm recoverability.

schema version 1 contains a top-level summary and one benchmark record per
requested benchmark. each benchmark record reports recovered vm-like functions,
wrapper candidates, wrapper-to-implementation mappings, raw and transformed
opcode constants, dispatcher and handler candidates, state/program-counter
candidates, vm data
references, generated-symbol leakage, repeated helper shapes, findings, and a
recovery score. higher scores mean the script recovered more attacker-useful vm
structure; --fail-max-recovery-score can turn that score into a gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any


SCHEMA_VERSION = 1
DEFAULT_BENCHMARKS = ("license_demo", "config_demo", "vm_workflow_demo")
STRONG_VM_EXPECTED_WRAPPERS = {"config_demo": ("fold_value",)}

FUNCTION_NAME_PATTERN = re.compile(r"@(?P<name>\"[^\"]+\"|[^\s(]+)\s*\(")
ATTRIBUTE_GROUP_PATTERN = re.compile(
    r"^attributes\s+#(?P<num>\d+)\s*=\s*\{(?P<attrs>.*)\}\s*$"
)
LABEL_PATTERN = re.compile(r"^(?P<label>[0-9A-Za-z$._-]+):\s*(?:;.*)?$")
RAW_OPCODE_COMPARE_PATTERN = re.compile(
    r"(?:%[-A-Za-z$._0-9]*obf\.vm\.opcode\.match[-A-Za-z$._0-9]*\s*=\s*)?"
    r"\bicmp\s+eq\s+i8\s+[^,\n]+,\s+(?:i8\s+)?(?P<opcode>-?\d+)\b"
)
TRANSFORMED_OPCODE_COMPARE_PATTERN = re.compile(
    r"(?:%[-A-Za-z$._0-9]*obf\.vm\.opcode\.match[-A-Za-z$._0-9]*\s*=\s*)?"
    r"\bicmp\s+eq\s+i(?P<width>32)\s+[^,\n]+,\s+"
    r"(?:i32\s+)?(?P<opcode>-?\d+)\b"
)
SPLIT_OPCODE_COMPARE_PATTERN = re.compile(
    r"\bicmp\s+eq\s+i32\s+[^,\n]+,\s+(?:i32\s+)?(?P<opcode>-?\d+)\b"
)
NAMED_SPLIT_OPCODE_COMPARE_PATTERN = re.compile(
    r"%[-A-Za-z$._0-9]*obf\.vm\.opcode\.split\.(?:low|high)\.ok"
    r"[-A-Za-z$._0-9]*\s*=\s*\bicmp\s+eq\s+i32\b"
)
NONLOCAL_SPLIT_RELOAD_PATTERN = re.compile(
    r"%[-A-Za-z$._0-9]*obf\.vm\.opcode\.split\.(?:low|high)\.reload"
    r"[-A-Za-z$._0-9]*\s*=\s*\bload\s+i32\s*,\s*ptr\s+"
    r"%[-A-Za-z$._0-9]*obf\.vm\.pred\.slot"
)
NONLOCAL_SPLIT_STORE_PATTERN = re.compile(
    r"\bstore\s+i32\s+%[-A-Za-z$._0-9]*obf\.vm\.opcode\.split\."
    r"(?:low|high)\.delta[-A-Za-z$._0-9]*\s*,\s*ptr\s+"
    r"%[-A-Za-z$._0-9]*obf\.vm\.pred\.slot"
)
GENERIC_I32_STACK_LOAD_PATTERN = re.compile(r"\bload\s+i32\s*,\s*ptr\s+%[-A-Za-z$._0-9]+")
OPCODE_WIDEN_PATTERN = re.compile(r"\bzext\s+i8\b[^\n]*\bto\s+i32\b")
COND_BRANCH_PATTERN = re.compile(
    r"\bbr\s+i1\s+[^,]+,\s+label\s+%(?P<true>[0-9A-Za-z$._-]+),\s+label\s+%(?P<false>[0-9A-Za-z$._-]+)"
)
UNCOND_BRANCH_PATTERN = re.compile(r"\bbr\s+label\s+%(?P<target>[0-9A-Za-z$._-]+)")
DIRECT_CALL_PATTERN = re.compile(
    r"\b(?:tail\s+|musttail\s+|notail\s+)?(?:call|invoke)\b[^@\n]*@(?P<name>[A-Za-z$._0-9-]+)\s*\("
)
ENTROPY_ACCESSOR_PATTERN = re.compile(r"__obf_load_entropy_pair(?:_v[1-9][0-9]*)?")
# Matches a call to a named function that passes a hidden i64 token — used to detect thunk→impl calls
HIDDEN_TOKEN_CALL_PATTERN = re.compile(
    r"\b(?:tail\s+|musttail\s+|notail\s+)?(?:call|invoke)\b[^@\n]*@(?P<impl>[A-Za-z$._0-9-]+)\s*\([^\n]*,\s*i64\s+%[-A-Za-z$._0-9]+"
)
FUNCTION_PTR_REF_PATTERN = re.compile(
    r"ptrtoint\s+(?:\(\s*)?ptr\s+@(?P<name>[A-Za-z$._0-9-]+)\s+to\s+i\d+\s*\)?"
)
INDIRECT_HIDDEN_TOKEN_CALL_PATTERN = re.compile(
    r"\bcall\b[^\n]*%[-A-Za-z$._0-9]+\([^\n]*\bi64\s+(?:%[-A-Za-z$._0-9]+|-?\d+)"
)
GLOBAL_I64_STORE_PATTERN = re.compile(
    r"\bstore\s+i64\s+[^,\n]+,\s+ptr\s+@[A-Za-z$._0-9-]+"
)
VM_DATA_SYMBOL_REF_PATTERN = re.compile(
    r"@(?P<name>__obf_vm_(?:bc|g|k|ptrconst|retkey|t|s|c)_[A-Za-z0-9_]+)"
)
GLOBAL_DEFINITION_PATTERN = re.compile(
    r"^@(?P<name>__obf_[A-Za-z0-9_]+)\s*=", re.MULTILINE
)
SSA_NAME_PATTERN = re.compile(r"%([-A-Za-z$._0-9]+)")
SWITCH_CASE_PATTERN = re.compile(r"\bi\d+\s+-?\d+\s*,\s+label\s+%")
SWITCH_INST_PATTERN = re.compile(r"^\s*switch\b", re.MULTILINE)
INDIRECTBR_INST_PATTERN = re.compile(r"^\s*indirectbr\b", re.MULTILINE)

SYMBOL_PATTERNS = {
    "vm_impl": r"__obf_vm_i_[A-Za-z0-9_]+",
    "vm_helper": r"__obf_vm_h_[A-Za-z0-9_]+",
    "vm_subhelper": r"__obf_vm_hs_[A-Za-z0-9_]+",
    "vm_bytecode": r"__obf_vm_bc_[A-Za-z0-9_]+",
    "vm_global": r"__obf_vm_g_[A-Za-z0-9_]+",
    "vm_key": r"__obf_vm_k_[A-Za-z0-9_]+",
    "vm_retkey": r"__obf_vm_retkey_[A-Za-z0-9_]+",
    "vm_target": r"__obf_vm_t_[A-Za-z0-9_]+",
    "vm_target_seed": r"__obf_vm_s_[A-Za-z0-9_]+",
    "vm_seed_case": r"__obf_vm_c_[A-Za-z0-9_]+",
    "vm_ptrconst": r"__obf_vm_ptrconst_[A-Za-z0-9_]+",
    "entropy_thunk": r"__obf_entropy_thunk_[A-Za-z0-9_]+",
    "string_data": r"__obf_str_[A-Za-z0-9_]+",
}

MARKER_PATTERNS = {
    "branch.direct": r"vm\.branch\.shape\.direct",
    "branch.invert": r"vm\.branch\.shape\.invert",
    "branch.neutral": r"vm\.branch\.shape\.neutral",
    "branch.select": r"vm\.branch\.shape\.select",
    "call.direct": r"vm\.call\.shape\.direct",
    "call.shuffle": r"vm\.call\.shape\.shuffle",
    "call.slot": r"vm\.call\.shape\.slot",
    "call.token": r"vm\.call\.shape\.token",
    "choreo.dispatch.bias": r"vm\.choreo\.dispatch\.bias",
    "choreo.dispatch.direct": r"vm\.choreo\.dispatch\.direct",
    "choreo.dispatch.select": r"vm\.choreo\.dispatch\.select",
    "choreo.dispatch.split": r"vm\.choreo\.dispatch\.split",
    "choreo.route.direct": r"vm\.choreo\.route\.direct",
    "choreo.route.di": r"vm\.choreo\.route\.di",
    "choreo.route.id": r"vm\.choreo\.route\.id",
    "choreo.route.pack": r"vm\.choreo\.route\.pack",
    "choreo.route.temp": r"vm\.choreo\.route\.temp",
    "choreo.slot.direct": r"vm\.choreo\.slot\.direct",
    "choreo.slot.rotate": r"vm\.choreo\.slot\.rotate",
    "choreo.slot.select": r"vm\.choreo\.slot\.select",
    "choreo.slot.split": r"vm\.choreo\.slot\.split",
    "choreo.slot.temp": r"vm\.choreo\.slot\.temp",
    "choreo.status.direct": r"vm\.choreo\.status\.direct",
    "choreo.status.select": r"vm\.choreo\.status\.select",
    "choreo.status.split": r"vm\.choreo\.status\.split",
    "choreo.status.temp": r"vm\.choreo\.status\.temp",
    "choreo.table.bias": r"vm\.choreo\.table\.bias",
    "choreo.table.direct": r"vm\.choreo\.table\.direct",
    "choreo.table.select": r"vm\.choreo\.table\.select",
    "choreo.table.split": r"vm\.choreo\.table\.split",
    "choreo.table.temp": r"vm\.choreo\.table\.temp",
    "compare.direct": r"vm\.compare\.shape\.direct",
    "compare.invert": r"vm\.compare\.shape\.invert",
    "compare.select": r"vm\.compare\.shape\.select",
    "compare.xor": r"vm\.compare\.shape\.xor",
    "dispatch.bank": r"vm\.dispatch\.bank",
    "dispatch.banked": r"vm\.dispatch\.shape\.banked",
    "dispatch.direct": r"vm\.dispatch\.shape\.direct",
    "dispatch.switch": r"vm\.dispatch\.shape\.switch",
    "gep.bias": r"vm\.gep\.shape\.bias",
    "gep.direct": r"vm\.gep\.shape\.direct",
    "gep.ptrint": r"vm\.gep\.shape\.ptrint",
    "gep.select": r"vm\.gep\.shape\.select",
    "gep.split": r"vm\.gep\.shape\.split",
    "handler.direct": r"vm\.handler\.shape\.direct",
    "handler.neutral": r"vm\.handler\.shape\.neutral",
    "handler.temp": r"vm\.handler\.shape\.temp",
    "island.count": r"vm\.island\.count\.\d+",
    "island.entry": r"vm\.island\.entry",
    "island.helper": r"vm\.island\.helper",
    "island.helper.decode": r"vm\.island\.helper\.decode",
    "island.helper.dispatch": r"vm\.island\.helper\.dispatch",
    "island.helper.large": r"vm\.island\.helper\.large",
    "island.helper.split": r"vm\.island\.helper\.split",
    "island.root.finalize": r"vm\.island\.root\.finalize",
    "island.root.route": r"vm\.island\.root\.route",
    "island.route": r"vm\.island\.route",
    "island.state": r"vm\.island\.state",
    "island.subhelper": r"vm\.island\.subhelper",
    "island.subroute": r"vm\.island\.subroute",
    "island.table.shard": r"vm\.island\.table\.shard",
    "island.topology": r"vm\.island\.topology\.helper_shards",
    "memory.direct": r"vm\.memory\.shape\.direct",
    "memory.offset": r"vm\.memory\.shape\.offset",
    "memory.ptr": r"vm\.memory\.shape\.ptr",
    "memory.select": r"vm\.memory\.shape\.select",
    "memory.slot": r"vm\.memory\.shape\.slot",
    "ptrmat.addsub": r"ptrmat\.addsub",
    "ptrmat.direct": r"ptrmat\.direct",
    "ptrmat.split": r"ptrmat\.split",
    "return.direct": r"vm\.return\.shape\.direct",
    "return.neutral": r"vm\.return\.shape\.neutral",
    "return.slot": r"vm\.return\.shape\.slot",
    "return.split": r"vm\.return\.shape\.split",
    "anchor.scattered": r"vm\.bytecode\.anchor\.scattered",
    "anchor.decoys": r"vm\.bytecode\.anchor\.decoys",
}

ENTRY_THUNK_SHAPE_MARKERS = {
    "direct": "vm.entry.thunk.shape.direct",
    "neutral": "vm.entry.thunk.shape.neutral",
    "split": "vm.entry.thunk.shape.split",
    # pr29.5: router opacity shapes
    "indirect": "vm.entry.thunk.shape.indirect",
    "decoy_indirect": "vm.entry.thunk.shape.decoy_indirect",
    "decoy_split": "vm.entry.thunk.shape.decoy_split",
    "decoy": "vm.entry.thunk.shape.decoy",
}

SELF_TEST_IR = r'''
@__obf_vm_bc_i_self = private unnamed_addr constant [4 x i8] c"\01\02\03\04"
@__obf_vm_retkey_i_self = private global i64 7
@__obf_vm_t_self = private global i64 0
@__obf_vm_s_self = private global i64 1
@__obf_vm_k_self = private global i64 2

define i32 @self_wrapper(i32 %x) #0 {
entry:
  %self_wrapper.obf.wrapper.thunkref = ptrtoint (ptr @__obf_vm_e_self to i64)
  %self_wrapper.obf.wrapper.check = load i64, ptr @__obf_vm_t_self
  %self_wrapper.obf.wrapper.indirect = inttoptr i64 %self_wrapper.obf.wrapper.check to ptr
  %self_wrapper.obf.wrapper.call = call i32 %self_wrapper.obf.wrapper.indirect(i32 %x, i64 123)
  %self_wrapper.obf.retkey = load i64, ptr @__obf_vm_retkey_i_self
  ret i32 %self_wrapper.obf.wrapper.call
}

define internal i32 @__obf_vm_i_self(i32 %x, i64 %obf.hidden_token) #1 {
entry.obf.vm:
  %obf.vm.state = alloca i64
  %obf.vm.pred.slot = alloca i32
  br label %vm.dispatch.shape.switch.vm.dispatch.switch.0

vm.dispatch.shape.switch.vm.dispatch.switch.0:
  %obf.vm.dispatch.index.bank = phi i32 [ 7, %entry.obf.vm ], [ 9, %vm.exec.0 ]
  switch i32 %obf.vm.dispatch.index.bank, label %obf.vm.fail.shared [
    i32 7, label %vm.0
    i32 9, label %vm.1
  ]

vm.0:
  %obf.vm.bc.slot = getelementptr inbounds [4 x i8], ptr @__obf_vm_bc_i_self, i32 0, i32 0
  %obf.vm.bc.enc = load i8, ptr %obf.vm.bc.slot
  %obf.vm.opcode.wide = zext i8 %obf.vm.bc.enc to i32
  %obf.vm.opcode.mix = xor i32 %obf.vm.opcode.wide, 99
  %obf.vm.opcode.split.low.actual = and i32 %obf.vm.opcode.mix, 15
  %obf.vm.opcode.split.low.delta = xor i32 %obf.vm.opcode.split.low.actual, 9
  store i32 %obf.vm.opcode.split.low.delta, ptr %obf.vm.pred.slot
  br label %vm.pred.0

vm.pred.0:
  %obf.vm.opcode.split.low.reload = load i32, ptr %obf.vm.pred.slot
  %obf.vm.opcode.split.low.ok = icmp eq i32 %obf.vm.opcode.split.low.reload, 0
  %obf.vm.opcode.split.high.actual = lshr i32 %obf.vm.opcode.mix, 4
  %obf.vm.opcode.split.high.delta = xor i32 %obf.vm.opcode.split.high.actual, 4
  %obf.vm.opcode.split.high.ok = icmp eq i32 %obf.vm.opcode.split.high.delta, 0
  %obf.vm.opcode.split.match = and i1 %obf.vm.opcode.split.low.ok, %obf.vm.opcode.split.high.ok
  br i1 %obf.vm.opcode.split.match, label %obf.vm.route.entry.0, label %obf.vm.fail.shared

obf.vm.route.entry.0:
  br label %vm.exec.0

vm.exec.0:
  br label %vm.dispatch.shape.switch.vm.dispatch.switch.0

vm.1:
  %obf.vm.opcode.match.1 = icmp eq i8 %obf.vm.bc.enc, -3
  br i1 %obf.vm.opcode.match.1, label %obf.vm.route.entry.1, label %obf.vm.fail.shared

obf.vm.route.entry.1:
  br label %vm.exec.1

vm.exec.1:
  %obf.vm.ret.retkey = load i64, ptr @__obf_vm_retkey_i_self
  ret i32 %x

obf.vm.fail.shared:
  br label %trap.obf.vm

trap.obf.vm:
  call void @llvm.trap()
  unreachable
}

declare void @llvm.trap()

define internal i32 @__obf_vm_e_self(i32 %x, i64 %obf.hidden_token) #2 {
obf.vm.entry.thunk:
  %thunk.call = call i32 @__obf_vm_i_self(i32 %x, i64 %obf.hidden_token)
  ret i32 %thunk.call
}

attributes #0 = { noinline }
attributes #1 = { noinline "vm.dispatch.shape.switch" "vm.handler.shape.direct" "vm.island.entry" "vm.island.count.1" "vm.island.state" }
attributes #2 = { noinline "obf.vm.entry.thunk" "vm.entry.thunk.shape.direct" }
'''


@dataclass(frozen=True)
class BlockIR:
    label: str
    body: str
    start_line: int


@dataclass(frozen=True)
class FunctionIR:
    name: str
    header: str
    body: str
    full_text: str
    attrs: str
    start_line: int
    end_line: int


@dataclass(frozen=True)
class FunctionSignature:
    return_type: str
    arg_types: tuple[str, ...]


def parse_csv(value: str | None) -> list[str]:
    if value is None or value.strip() == "":
        return list(DEFAULT_BENCHMARKS)
    return sorted(dict.fromkeys(item.strip() for item in value.split(",") if item.strip()))


def stable_hash_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:16]


def parse_attribute_groups(ir_text: str) -> dict[str, str]:
    groups: dict[str, str] = {}
    for line in ir_text.splitlines():
        match = ATTRIBUTE_GROUP_PATTERN.match(line.strip())
        if match is not None:
            groups[match.group("num")] = match.group("attrs")
    return groups


def normalize_function_name(name: str) -> str:
    if len(name) >= 2 and name[0] == '"' and name[-1] == '"':
        return name[1:-1]
    return name


def split_top_level_csv(text: str) -> list[str]:
    items: list[str] = []
    start = 0
    depth = 0
    pairs = {"(": ")", "[": "]", "{": "}", "<": ">"}
    closing = set(pairs.values())
    for index, char in enumerate(text):
        if char in pairs:
            depth += 1
        elif char in closing and depth > 0:
            depth -= 1
        elif char == "," and depth == 0:
            items.append(text[start:index].strip())
            start = index + 1
    tail = text[start:].strip()
    if tail:
        items.append(tail)
    return items


def parse_type_token(text: str) -> str:
    stripped = text.strip()
    if not stripped or stripped == "...":
        return ""
    if stripped.startswith("{"):
        end = stripped.find("}")
        return stripped[: end + 1] if end != -1 else stripped
    if stripped.startswith("["):
        end = stripped.find("]")
        return stripped[: end + 1] if end != -1 else stripped
    if stripped.startswith("<"):
        end = stripped.find(">")
        return stripped[: end + 1] if end != -1 else stripped
    return stripped.split()[0]


def parse_return_type(prefix: str) -> str:
    tokens = prefix.strip().split()
    return tokens[-1] if tokens else ""


def parse_function_signature(function: FunctionIR) -> FunctionSignature:
    name_match = FUNCTION_NAME_PATTERN.search(function.header)
    if name_match is None:
        return FunctionSignature("", ())
    prefix = function.header[len("define ") : name_match.start()].strip()
    args_start = name_match.end() - 1
    args_end = function.header.rfind(")")
    if args_start < 0 or args_end < args_start:
        return FunctionSignature(parse_return_type(prefix), ())
    args_text = function.header[args_start + 1 : args_end]
    arg_types = tuple(
        arg_type
        for arg_type in (parse_type_token(arg) for arg in split_top_level_csv(args_text))
        if arg_type
    )
    return FunctionSignature(parse_return_type(prefix), arg_types)


def parse_functions(ir_text: str) -> dict[str, FunctionIR]:
    attribute_groups = parse_attribute_groups(ir_text)
    functions: dict[str, FunctionIR] = {}
    lines = ir_text.splitlines()
    line_index = 0
    while line_index < len(lines):
        line = lines[line_index]
        if not line.startswith("define "):
            line_index += 1
            continue

        start_line = line_index + 1
        header_lines = [line]
        while not header_lines[-1].rstrip().endswith("{"):
            line_index += 1
            if line_index >= len(lines):
                raise ValueError(f"unterminated function header at line {start_line}")
            header_lines.append(lines[line_index])

        header_text = " ".join(part.strip() for part in header_lines)
        name_match = FUNCTION_NAME_PATTERN.search(header_text)
        if name_match is None:
            raise ValueError(f"unable to parse function name from line {start_line}: {header_text}")
        function_name = normalize_function_name(name_match.group("name"))

        line_index += 1
        body_lines: list[str] = []
        while line_index < len(lines) and lines[line_index] != "}":
            body_lines.append(lines[line_index])
            line_index += 1
        if line_index >= len(lines):
            raise ValueError(f"unterminated function body: {function_name}")

        attr_refs = sorted(set(re.findall(r"#(\d+)", header_text)))
        attr_text = " ".join([header_text] + [attribute_groups.get(ref, "") for ref in attr_refs])
        body = "\n".join(body_lines) + ("\n" if body_lines else "")
        full_text = "\n".join(header_lines + body_lines + ["}"])
        functions[function_name] = FunctionIR(
            name=function_name,
            header=header_text,
            body=body,
            full_text=full_text,
            attrs=attr_text,
            start_line=start_line,
            end_line=line_index + 1,
        )
        line_index += 1
    return functions


def parse_blocks(function_body: str) -> dict[str, BlockIR]:
    blocks: dict[str, BlockIR] = {}
    current_label: str | None = None
    current_start = 0
    current_body: list[str] = []
    for offset, line in enumerate(function_body.splitlines(), start=1):
        label_match = LABEL_PATTERN.match(line)
        if label_match is not None:
            if current_label is not None:
                blocks[current_label] = BlockIR(
                    current_label,
                    "\n".join(current_body) + ("\n" if current_body else ""),
                    current_start,
                )
            current_label = label_match.group("label")
            current_start = offset
            current_body = []
            continue

        if current_label is not None:
            current_body.append(line)
    if current_label is not None:
        blocks[current_label] = BlockIR(
            current_label,
            "\n".join(current_body) + ("\n" if current_body else ""),
            current_start,
        )
    return blocks


def count_markers(text: str) -> dict[str, int]:
    return {name: len(re.findall(pattern, text)) for name, pattern in MARKER_PATTERNS.items()}


def collect_symbols_by_role(text: str) -> dict[str, list[str]]:
    return {
        role: sorted(set(re.findall(pattern, text)))
        for role, pattern in SYMBOL_PATTERNS.items()
    }


def collect_symbol_counts_by_role(text: str) -> dict[str, int]:
    return {role: len(symbols) for role, symbols in collect_symbols_by_role(text).items()}


def tag_from_symbol_name(name: str) -> str | None:
    if name.startswith("__obf_vm_i_"):
        return name.removeprefix("__obf_vm_")
    retkey_match = re.match(r"__obf_vm_retkey_(?P<tag>[A-Za-z0-9_]+)$", name)
    if retkey_match is not None:
        return retkey_match.group("tag")
    bytecode_match = re.match(r"__obf_vm_bc_(?P<tag>[A-Za-z0-9_]+?)(?:_s\d+)?$", name)
    if bytecode_match is not None:
        return bytecode_match.group("tag")
    return None


def collect_vm_data_refs(text: str) -> list[str]:
    return sorted(set(match.group("name") for match in VM_DATA_SYMBOL_REF_PATTERN.finditer(text)))


def collect_vm_data_ref_mentions(text: str) -> list[str]:
    return [match.group("name") for match in VM_DATA_SYMBOL_REF_PATTERN.finditer(text)]


def collect_tags_from_refs(text: str) -> list[str]:
    tags = {tag_from_symbol_name(ref) for ref in collect_vm_data_refs(text)}
    return sorted(tag for tag in tags if tag is not None)


def classify_vm_function(function: FunctionIR) -> str:
    name = function.name
    combined = function.body + "\n" + function.attrs
    if name.startswith("__obf_vm_e_"):
        return "entry_thunk"
    if '"obf.vm.entry.thunk"' in combined:
        return "entry_thunk"
    # structural fallback: single block, direct call to vm impl, no indirectbr
    if "obf.vm.entry.thunk" in function.body and "indirectbr" not in function.body:
        body_call = HIDDEN_TOKEN_CALL_PATTERN.search(function.body)
        if body_call and not name.startswith("__obf_vm_i_"):
            return "entry_thunk"
    if name.startswith("__obf_vm_hs_"):
        return "subhelper"
    if name.startswith("__obf_vm_h_"):
        return "helper"
    if name.startswith("__obf_vm_i_"):
        return "implementation"
    if "vm.island.subhelper" in combined:
        return "subhelper"
    if "vm.island.helper" in combined:
        return "helper"
    if "vm.island.entry" in combined:
        return "implementation"
    if "vm.opcode.predicate.nonlocal" in combined:
        return "implementation"
    if (
        "entry.obf.vm" in function.body
        or "obf.vm.opcode.match" in function.body
        or "obf.vm.opcode.split" in function.body
    ):
        return "implementation"
    if "indirectbr" in function.body and has_opcode_compare(function.body):
        return "implementation"
    return ""


def is_vm_function(function: FunctionIR) -> bool:
    return classify_vm_function(function) != ""


def is_trap_block(label: str, body: str) -> bool:
    return "trap" in label or ("@llvm.trap" in body and "unreachable" in body)


def is_failure_block(label: str, body: str, trap_labels: set[str]) -> bool:
    branch_match = UNCOND_BRANCH_PATTERN.search(body)
    branches_to_trap = branch_match is not None and branch_match.group("target") in trap_labels
    return "fail" in label.lower() or branches_to_trap


def is_handler_label(label: str) -> bool:
    return bool(re.search(r"(^|\.)exec(\.|$)", label)) or label.startswith("vm.exec")


def is_route_block(label: str, body: str) -> bool:
    return "obf.vm.route" in label or "obf.vm.route" in body


def classify_handler_mapping(
    target: str, blocks: dict[str, BlockIR], failure_labels: set[str]
) -> dict[str, str]:
    if not target:
        return {"handler_mapping": "low", "resolved_handler_target": "", "route_target": ""}
    if is_handler_label(target):
        return {
            "handler_mapping": "branch_target",
            "resolved_handler_target": target,
            "route_target": "",
        }
    target_block = blocks.get(target)
    if target_block is None or not is_route_block(target, target_block.body):
        return {"handler_mapping": "routed", "resolved_handler_target": "", "route_target": target}

    branch_match = UNCOND_BRANCH_PATTERN.search(target_block.body)
    if branch_match is not None:
        route_target = branch_match.group("target")
        if is_handler_label(route_target):
            return {
                "handler_mapping": "trampoline",
                "resolved_handler_target": route_target,
                "route_target": target,
            }
        if route_target in failure_labels:
            return {
                "handler_mapping": "decoy_ambiguous",
                "resolved_handler_target": "",
                "route_target": target,
            }
        return {"handler_mapping": "routed", "resolved_handler_target": route_target, "route_target": target}

    branch_match = COND_BRANCH_PATTERN.search(target_block.body)
    if branch_match is not None:
        branch_targets = [branch_match.group("true"), branch_match.group("false")]
        handler_targets = [branch_target for branch_target in branch_targets if is_handler_label(branch_target)]
        fail_targets = [branch_target for branch_target in branch_targets if branch_target in failure_labels]
        if handler_targets and fail_targets:
            return {
                "handler_mapping": "decoy_ambiguous",
                "resolved_handler_target": handler_targets[0],
                "route_target": target,
            }
        if handler_targets:
            return {
                "handler_mapping": "routed",
                "resolved_handler_target": handler_targets[0],
                "route_target": target,
            }
    return {"handler_mapping": "routed", "resolved_handler_target": "", "route_target": target}


def has_opcode_compare(text: str) -> bool:
    return bool(
        RAW_OPCODE_COMPARE_PATTERN.search(text)
        or (
            (
                TRANSFORMED_OPCODE_COMPARE_PATTERN.search(text)
                or looks_like_split_opcode_block(text, allow_generic_nonlocal=True)
            )
            and looks_like_transformed_opcode_block(text)
        )
    )


def looks_like_transformed_opcode_block(block_body: str) -> bool:
    return "obf.vm.opcode" in block_body or bool(OPCODE_WIDEN_PATTERN.search(block_body))


def split_opcode_compare_count(block_body: str, allow_generic_nonlocal: bool = False) -> int:
    named_count = len(NAMED_SPLIT_OPCODE_COMPARE_PATTERN.findall(block_body))
    if named_count:
        return named_count
    if not allow_generic_nonlocal and not looks_like_transformed_opcode_block(block_body):
        return 0
    matches = list(SPLIT_OPCODE_COMPARE_PATTERN.finditer(block_body))
    zero_matches = [match for match in matches if int(match.group("opcode")) == 0]
    return len(zero_matches) if len(zero_matches) >= 2 else 0


def looks_like_split_opcode_block(block_body: str, allow_generic_nonlocal: bool = False) -> bool:
    return "obf.vm.opcode.split" in block_body or split_opcode_compare_count(
        block_body, allow_generic_nonlocal
    ) >= 2


def is_nonlocal_split_opcode_block(block_body: str, allow_generic_nonlocal: bool = False) -> bool:
    return bool(NONLOCAL_SPLIT_RELOAD_PATTERN.search(block_body)) or (
        allow_generic_nonlocal and bool(GENERIC_I32_STACK_LOAD_PATTERN.search(block_body))
    )


def opcode_compare_matches(
    block_body: str, allow_generic_nonlocal: bool = False
) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for match in RAW_OPCODE_COMPARE_PATTERN.finditer(block_body):
        matches.append(
            {
                "compare_kind": "raw_i8",
                "compare_width": 8,
                "constant": int(match.group("opcode")),
            }
        )
    if not allow_generic_nonlocal and not looks_like_transformed_opcode_block(block_body):
        return matches
    split_count = split_opcode_compare_count(block_body, allow_generic_nonlocal)
    if split_count:
        split_immediates = sorted(
            {int(match.group("opcode")) for match in SPLIT_OPCODE_COMPARE_PATTERN.finditer(block_body)}
        )
        nonlocal_split = is_nonlocal_split_opcode_block(block_body, allow_generic_nonlocal)
        matches.append(
            {
                "compare_kind": "split_i32_nonlocal" if nonlocal_split else "split_i32_local",
                "compare_width": 32,
                "constant": None,
                "predicate_locality": "non_local" if nonlocal_split else "local_complete",
                "split_compare_count": split_count,
                "split_immediates": split_immediates,
            }
        )
        return matches
    if not looks_like_transformed_opcode_block(block_body):
        return matches
    for match in TRANSFORMED_OPCODE_COMPARE_PATTERN.finditer(block_body):
        matches.append(
            {
                "compare_kind": f"transformed_full_i{match.group('width')}",
                "compare_width": int(match.group("width")),
                "constant": int(match.group("opcode")),
                "split_compare_count": 0,
                "split_immediates": [],
            }
        )
    return matches


def extract_opcode_headers(function: FunctionIR) -> list[dict[str, Any]]:
    blocks = parse_blocks(function.body)
    allow_generic_nonlocal = "vm.opcode.predicate.nonlocal" in function.attrs
    trap_labels = {label for label, block in blocks.items() if is_trap_block(label, block.body)}
    failure_labels = {
        label for label, block in blocks.items() if is_failure_block(label, block.body, trap_labels)
    }
    headers: list[dict[str, Any]] = []
    for label, block in blocks.items():
        compare_matches = opcode_compare_matches(block.body, allow_generic_nonlocal)
        if not compare_matches:
            continue
        branch_match = COND_BRANCH_PATTERN.search(block.body)
        true_target = branch_match.group("true") if branch_match is not None else ""
        false_target = branch_match.group("false") if branch_match is not None else ""
        branch_targets = [target for target in (true_target, false_target) if target]
        handler_targets = [
            target
            for target in branch_targets
            if target not in trap_labels and target not in failure_labels
        ]
        trap_targets = [target for target in branch_targets if target in trap_labels]
        failure_targets = [target for target in branch_targets if target in failure_labels]
        for compare_match in compare_matches:
            success_target = handler_targets[0] if handler_targets else ""
            mapping = classify_handler_mapping(success_target, blocks, failure_labels)
            headers.append(
                {
                    "block": label,
                    "compare_kind": compare_match["compare_kind"],
                    "compare_width": compare_match["compare_width"],
                    "constant": compare_match["constant"],
                    "direct_success_to_handler": mapping["handler_mapping"] == "branch_target",
                    "failure_target": failure_targets[0] if failure_targets else "",
                    "handler_mapping": mapping["handler_mapping"],
                    "handler_target": mapping["resolved_handler_target"],
                    "opcode": compare_match["constant"],
                    "predicate_locality": compare_match.get("predicate_locality", "local"),
                    "route_target": mapping["route_target"],
                    "split_compare_count": compare_match.get("split_compare_count", 0),
                    "split_immediates": compare_match.get("split_immediates", []),
                    "success_target": success_target,
                    "trap_oracle": "direct" if trap_targets else "indirect" if failure_targets else "none",
                    "trap_target": trap_targets[0] if trap_targets else "",
                }
            )
    return sorted(
        headers,
        key=lambda item: (item["block"], item["compare_kind"], str(item["constant"])),
    )


def extract_dispatcher_blocks(function: FunctionIR) -> list[str]:
    blocks = parse_blocks(function.body)
    labels: set[str] = set()
    for label, block in blocks.items():
        label_text = label.lower()
        body = block.body
        if (
            "dispatch" in label_text
            or "route" in label_text
            or SWITCH_INST_PATTERN.search(body)
            or INDIRECTBR_INST_PATTERN.search(body)
        ):
            labels.add(label)
    return sorted(labels)


def extract_handler_candidates(function: FunctionIR) -> list[str]:
    blocks = parse_blocks(function.body)
    candidates: set[str] = set()
    for header in extract_opcode_headers(function):
        handler_target = header["handler_target"]
        if handler_target:
            candidates.add(handler_target)
    for label in blocks:
        if re.search(r"(^|\.)exec(\.|$)", label) or label.startswith("vm.exec"):
            candidates.add(label)
    return sorted(candidates)


def collect_name_candidates(function: FunctionIR, fragments: tuple[str, ...]) -> list[str]:
    names = set()
    for name in SSA_NAME_PATTERN.findall(function.body):
        lowered = name.lower()
        if any(fragment in lowered for fragment in fragments):
            names.add(name)
    return sorted(names)


def count_instruction_proxy(function: FunctionIR) -> int:
    count = 0
    for line in function.body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(";") or stripped.endswith(":"):
            continue
        count += 1
    return count


def limited(values: list[str], limit: int = 64) -> list[str]:
    return values[:limit]


def summarize_vm_function(function: FunctionIR) -> dict[str, Any]:
    role = classify_vm_function(function)
    blocks = parse_blocks(function.body)
    opcode_headers = extract_opcode_headers(function)
    raw_opcode_headers = [
        header for header in opcode_headers if header["compare_kind"] == "raw_i8"
    ]
    transformed_opcode_headers = [
        header for header in opcode_headers if header["compare_kind"].startswith("transformed_full")
    ]
    split_opcode_headers = [
        header for header in opcode_headers if header["compare_kind"].startswith("split_i32")
    ]
    local_split_opcode_headers = [
        header for header in split_opcode_headers if header["predicate_locality"] == "local_complete"
    ]
    nonlocal_split_opcode_headers = [
        header for header in split_opcode_headers if header["predicate_locality"] == "non_local"
    ]
    physical_opcodes = sorted({header["constant"] for header in raw_opcode_headers})
    transformed_opcode_constants = sorted(
        {
            header["constant"]
            for header in transformed_opcode_headers
            if header["constant"] is not None
        }
    )
    split_opcode_immediates = sorted(
        {
            immediate
            for header in split_opcode_headers
            for immediate in header["split_immediates"]
        }
    )
    dispatcher_blocks = extract_dispatcher_blocks(function)
    handler_candidates = extract_handler_candidates(function)
    state_candidates = collect_name_candidates(function, ("state", "token"))
    pc_candidates = collect_name_candidates(
        function, ("pc", "dispatch", "route", "opcode", "island")
    )
    marker_counts = count_markers(function.body + "\n" + function.attrs)
    nonzero_markers = {key: value for key, value in marker_counts.items() if value}
    bytecode_refs = sorted(
        ref for ref in collect_vm_data_refs(function.body) if ref.startswith("__obf_vm_bc_")
    )
    pointer_data_refs = sorted(
        ref for ref in collect_vm_data_refs(function.body) if ref.startswith("__obf_vm_ptrconst_")
    )
    retkey_refs = sorted(
        ref for ref in collect_vm_data_refs(function.body) if ref.startswith("__obf_vm_retkey_")
    )
    named_nonlocal_fragment_count = len(NONLOCAL_SPLIT_STORE_PATTERN.findall(function.body))
    named_nonlocal_reload_count = len(NONLOCAL_SPLIT_RELOAD_PATTERN.findall(function.body))
    route_target_counts = Counter(
        header["route_target"] for header in opcode_headers if header["route_target"]
    )
    route_family_counts = Counter(header["handler_mapping"] for header in opcode_headers)
    return {
        "alloca_count": len(re.findall(r"\balloca\b", function.body)),
        "basic_block_count": len(blocks),
        "bytecode_refs": bytecode_refs,
        "call_count": len(re.findall(r"\bcall\b", function.body)),
        "dispatcher_blocks": dispatcher_blocks,
        "dispatcher_block_count": len(dispatcher_blocks),
        "function": function.name,
        "handler_block_candidates": handler_candidates,
        "handler_block_candidate_count": len(handler_candidates),
        "handler_mapped_opcode_header_count": sum(
            1 for header in opcode_headers if header["handler_target"]
        ),
        "direct_success_to_handler_count": route_family_counts.get("branch_target", 0),
        "success_to_trampoline_count": route_family_counts.get("trampoline", 0),
        "trampoline_to_handler_count": route_family_counts.get("trampoline", 0),
        "routed_success_count": route_family_counts.get("routed", 0),
        "decoy_route_block_count": route_family_counts.get("decoy_ambiguous", 0),
        "shared_route_block_count": sum(1 for count in route_target_counts.values() if count > 1),
        "route_family_counts": dict(sorted(route_family_counts.items())),
        "indirectbr_count": len(INDIRECTBR_INST_PATTERN.findall(function.body)),
        "instruction_proxy_count": count_instruction_proxy(function),
        "kind": role,
        "line_range": [function.start_line, function.end_line],
        "load_count": len(re.findall(r"\bload\b", function.body)),
        "marker_counts": nonzero_markers,
        "opcode_compare_blocks": opcode_headers,
        "opcode_compare_count": len(opcode_headers),
        "physical_opcodes": physical_opcodes,
        "pointer_data_refs": pointer_data_refs,
        "program_counter_candidates": limited(pc_candidates),
        "program_counter_candidate_count": len(pc_candidates),
        "retkey_refs": retkey_refs,
        "state_candidates": limited(state_candidates),
        "state_candidate_count": len(state_candidates),
        "store_count": len(re.findall(r"\bstore\b", function.body)),
        "switch_case_count": len(SWITCH_CASE_PATTERN.findall(function.body)),
        "switch_count": len(SWITCH_INST_PATTERN.findall(function.body)),
        "tag": primary_tag_for_function(function),
        "split_opcode_compare_count": sum(
            header["split_compare_count"] for header in split_opcode_headers
        ),
        "split_opcode_header_count": len(split_opcode_headers),
        "split_opcode_immediates": split_opcode_immediates,
        "local_split_opcode_header_count": len(local_split_opcode_headers),
        "nonlocal_split_opcode_header_count": len(nonlocal_split_opcode_headers),
        "nonlocal_split_fragment_count": max(
            len(nonlocal_split_opcode_headers), named_nonlocal_fragment_count
        ),
        "nonlocal_split_reload_count": max(
            len(nonlocal_split_opcode_headers), named_nonlocal_reload_count
        ),
        "transformed_opcode_compare_count": len(transformed_opcode_headers),
        "transformed_opcode_constants": transformed_opcode_constants,
        "trap_count": len(re.findall(r"@llvm\.trap", function.body)),
        "trap_oracle_direct_count": sum(
            1 for header in opcode_headers if header["trap_oracle"] == "direct"
        ),
        "trap_oracle_indirect_count": sum(
            1 for header in opcode_headers if header["trap_oracle"] == "indirect"
        ),
        "trap_oracle_none_count": sum(
            1 for header in opcode_headers if header["trap_oracle"] == "none"
        ),
        "raw_direct_opcode_compare_count": len(raw_opcode_headers),
        "vm_data_refs": collect_vm_data_refs(function.body),
        "vm_data_ref_mentions": collect_vm_data_ref_mentions(function.body),
    }


def primary_tag_for_function(function: FunctionIR) -> str:
    if function.name.startswith("__obf_vm_i_"):
        return function.name.removeprefix("__obf_vm_")
    tags = collect_tags_from_refs(function.body)
    return tags[0] if tags else ""


def entry_thunk_shape(function: FunctionIR) -> str:
    combined = function.body + "\n" + function.attrs
    for shape, marker in ENTRY_THUNK_SHAPE_MARKERS.items():
        if marker in combined:
            return shape
    if len(parse_blocks(function.body)) > 1:
        return "split"
    if HIDDEN_TOKEN_CALL_PATTERN.search(function.body):
        return "direct"
    return "unknown"


def entry_thunk_direct_impl_calls(function: FunctionIR, implementation_names: set[str]) -> list[str]:
    return sorted(
        {
            match.group("impl")
            for match in HIDDEN_TOKEN_CALL_PATTERN.finditer(function.body)
            if match.group("impl") in implementation_names
        }
    )


def entry_thunk_impl_pointer_refs(function: FunctionIR, implementation_names: set[str]) -> list[str]:
    return extract_function_pointer_refs(function, implementation_names)


def entry_thunk_impl_calls(function: FunctionIR, implementation_names: set[str]) -> list[str]:
    direct_calls = entry_thunk_direct_impl_calls(function, implementation_names)
    if direct_calls:
        return direct_calls
    return entry_thunk_impl_pointer_refs(function, implementation_names)


def thunk_mapping_reason(shape: str) -> str:
    # pr29 indirect/decoy shapes get distinct mapping reasons
    if shape == "indirect":
        return "indirect_thunked"
    if shape in {"decoy", "decoy_indirect", "decoy_split"}:
        return "decoy_thunked"
    return "thunked" if shape == "direct" else "polymorphic_thunked"


def summarize_entry_thunk(
    function: FunctionIR, implementation_names: set[str]
) -> dict[str, Any]:
    direct_implementation_calls = entry_thunk_direct_impl_calls(function, implementation_names)
    implementation_pointer_refs = entry_thunk_impl_pointer_refs(function, implementation_names)
    implementation_calls = direct_implementation_calls or implementation_pointer_refs
    shape = entry_thunk_shape(function)
    return {
        "direct_implementation_call_count": len(direct_implementation_calls),
        "direct_implementation_calls": direct_implementation_calls,
        "function": function.name,
        "implementation_pointer_refs": implementation_pointer_refs,
        "implementation_calls": implementation_calls,
        "indirect_target_call_count": int(
            bool(implementation_pointer_refs) and has_indirect_hidden_token_call(function)
        ),
        "line_range": [function.start_line, function.end_line],
        "mapped_implementation": implementation_calls[0] if implementation_calls else "",
        "shape": shape,
        "split_target_call_count": int(shape == "decoy_split"),
    }


def count_shared_suffix_correlations(symbols_by_role: dict[str, list[str]]) -> int:
    implementation_tags = {
        symbol.removeprefix("__obf_vm_")
        for symbol in symbols_by_role.get("vm_impl", [])
    }
    if not implementation_tags:
        return 0
    correlations = 0
    for role in ("vm_bytecode", "vm_retkey"):
        for symbol in symbols_by_role.get(role, []):
            tag = tag_from_symbol_name(symbol)
            if tag in implementation_tags:
                correlations += 1
    return correlations


def extract_function_pointer_refs(function: FunctionIR, candidate_names: set[str]) -> list[str]:
    return sorted(
        {
            match.group("name")
            for match in FUNCTION_PTR_REF_PATTERN.finditer(function.body)
            if match.group("name") in candidate_names
        }
    )


def find_signature_impl_matches(
    function: FunctionIR, implementation_functions: dict[str, FunctionIR]
) -> list[str]:
    wrapper_signature = parse_function_signature(function)
    matches: list[str] = []
    for impl_name, implementation in implementation_functions.items():
        impl_signature = parse_function_signature(implementation)
        if impl_signature.return_type != wrapper_signature.return_type:
            continue
        if impl_signature.arg_types == wrapper_signature.arg_types + ("i64",):
            matches.append(impl_name)
    return sorted(matches)


def has_indirect_hidden_token_call(function: FunctionIR) -> bool:
    return bool(INDIRECT_HIDDEN_TOKEN_CALL_PATTERN.search(function.body))


def is_wrapper_candidate(
    function: FunctionIR, implementation_functions: dict[str, FunctionIR]
) -> bool:
    if is_vm_function(function):
        return False
    if ".obf.wrapper" in function.body:
        return True
    if not has_indirect_hidden_token_call(function):
        return False
    return bool(find_signature_impl_matches(function, implementation_functions))


def is_callsite_rewrite_candidate(
    function: FunctionIR,
    implementation_functions: dict[str, FunctionIR],
    implementation_names: set[str],
    entry_thunk_names: set[str] | None = None,
) -> bool:
    if entry_thunk_names is None:
        entry_thunk_names = set()
    if is_vm_function(function) or is_wrapper_candidate(function, implementation_functions):
        return False
    body = function.body
    return (
        (".obf.call" in body or ".obf.indirect" in body or has_indirect_hidden_token_call(function))
        and "inttoptr" in body
        and bool(
            extract_function_pointer_refs(function, implementation_names)
            or extract_function_pointer_refs(function, entry_thunk_names)
            or collect_vm_data_refs(body)
        )
    )


def summarize_wrapper(
    function: FunctionIR,
    implementation_by_tag: dict[str, str],
    implementation_functions: dict[str, FunctionIR],
    implementation_names: set[str],
    entry_thunk_functions: dict[str, FunctionIR] | None = None,
    entry_thunk_names: set[str] | None = None,
    entry_thunk_impl_by_name: dict[str, str] | None = None,
    entry_thunk_shape_by_name: dict[str, str] | None = None,
    entry_thunks_by_impl: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    if entry_thunk_functions is None:
        entry_thunk_functions = {}
    if entry_thunk_names is None:
        entry_thunk_names = set()
    if entry_thunk_impl_by_name is None:
        entry_thunk_impl_by_name = {}
    if entry_thunk_shape_by_name is None:
        entry_thunk_shape_by_name = {}
    if entry_thunks_by_impl is None:
        entry_thunks_by_impl = {}
    refs = collect_vm_data_refs(function.body)
    tags = collect_tags_from_refs(function.body)
    implementation_pointer_refs = extract_function_pointer_refs(function, implementation_names)
    thunk_pointer_refs = extract_function_pointer_refs(function, entry_thunk_names)
    signature_impl_matches = find_signature_impl_matches(function, implementation_functions)
    direct_impl_calls = sorted(
        {
            match.group("name")
            for match in DIRECT_CALL_PATTERN.finditer(function.body)
            if match.group("name") in implementation_names
        }
    )
    mapped_impl = ""
    mapped_entry_thunk = ""
    mapping_reason = "unmapped"
    if direct_impl_calls:
        mapped_impl = direct_impl_calls[0]
        mapping_reason = "direct_call"
    elif implementation_pointer_refs:
        mapped_impl = implementation_pointer_refs[0]
        mapping_reason = "implementation_pointer"
    # thunk chain detection: wrapper → thunk → impl (checked before tag fallback)
    if not mapped_impl and thunk_pointer_refs:
        for thunk_ref in thunk_pointer_refs:
            thunk_impl = entry_thunk_impl_by_name.get(thunk_ref, "")
            if thunk_impl in implementation_names:
                mapped_impl = thunk_impl
                mapped_entry_thunk = thunk_ref
                mapping_reason = thunk_mapping_reason(
                    entry_thunk_shape_by_name.get(thunk_ref, "unknown")
                )
                break
    if not mapped_impl:
        for tag in tags:
            candidate = implementation_by_tag.get(tag)
            if candidate is not None:
                mapped_impl = candidate
                mapping_reason = "tag_correlated"
                break
    if not mapped_impl and len(signature_impl_matches) == 1:
        signature_impl = signature_impl_matches[0]
        candidate_thunks = entry_thunks_by_impl.get(signature_impl, [])
        if candidate_thunks and has_indirect_hidden_token_call(function):
            mapped_impl = signature_impl
            mapped_entry_thunk = candidate_thunks[0]
            mapping_reason = thunk_mapping_reason(
                entry_thunk_shape_by_name.get(mapped_entry_thunk, "unknown")
            )
        else:
            mapped_impl = signature_impl
            mapping_reason = "indirect"
    target_cache_refs = sorted(ref for ref in refs if ref.startswith("__obf_vm_t_"))
    target_seed_refs = sorted(ref for ref in refs if ref.startswith("__obf_vm_s_"))
    key_refs = sorted(ref for ref in refs if ref.startswith("__obf_vm_k_"))
    retkey_refs = sorted(ref for ref in refs if ref.startswith("__obf_vm_retkey_"))
    resolver_shape = "local_decode" if target_seed_refs and not target_cache_refs else "cached_target"
    if not target_seed_refs and not target_cache_refs:
        resolver_shape = "unknown"
    if implementation_pointer_refs and not target_cache_refs:
        resolver_shape = "local_decode_obfuscated"
    elif GLOBAL_I64_STORE_PATTERN.search(function.body) and signature_impl_matches:
        resolver_shape = "cached_target_obfuscated"
    return {
        "direct_impl_calls": direct_impl_calls,
        "function": function.name,
        "implementation_pointer_refs": implementation_pointer_refs,
        "key_refs": key_refs,
        "line_range": [function.start_line, function.end_line],
        "mapped_entry_thunk": mapped_entry_thunk,
        "mapped_implementation": mapped_impl,
        "mapping_reason": mapping_reason,
        "resolver_shape": resolver_shape,
        "retkey_refs": retkey_refs,
        "signature_impl_matches": signature_impl_matches,
        "tags": tags,
        "target_cache_refs": target_cache_refs,
        "target_seed_refs": target_seed_refs,
        "thunk_refs": thunk_pointer_refs,
        "vm_data_refs": refs,
    }


def summarize_callsite_rewrite(
    function: FunctionIR,
    implementation_by_tag: dict[str, str],
    implementation_names: set[str],
    entry_thunk_functions: dict[str, FunctionIR] | None = None,
    entry_thunk_names: set[str] | None = None,
    entry_thunk_impl_by_name: dict[str, str] | None = None,
    entry_thunk_shape_by_name: dict[str, str] | None = None,
) -> dict[str, Any]:
    if entry_thunk_functions is None:
        entry_thunk_functions = {}
    if entry_thunk_names is None:
        entry_thunk_names = set()
    if entry_thunk_impl_by_name is None:
        entry_thunk_impl_by_name = {}
    if entry_thunk_shape_by_name is None:
        entry_thunk_shape_by_name = {}
    refs = collect_vm_data_refs(function.body)
    tags = collect_tags_from_refs(function.body)
    implementation_pointer_refs = extract_function_pointer_refs(function, implementation_names)
    thunk_pointer_refs = extract_function_pointer_refs(function, entry_thunk_names)
    mapped = ""
    mapped_entry_thunk = ""
    mapping_reason = "unmapped"
    if implementation_pointer_refs:
        mapped = implementation_pointer_refs[0]
        mapping_reason = "implementation_pointer"
    else:
        for tag in tags:
            candidate = implementation_by_tag.get(tag)
            if candidate is not None:
                mapped = candidate
                mapping_reason = "tag_correlated"
                break
    # thunk chain detection: callsite → thunk → impl
    if not mapped and thunk_pointer_refs:
        for thunk_ref in thunk_pointer_refs:
            thunk_impl = entry_thunk_impl_by_name.get(thunk_ref, "")
            if thunk_impl in implementation_names:
                mapped = thunk_impl
                mapped_entry_thunk = thunk_ref
                mapping_reason = thunk_mapping_reason(
                    entry_thunk_shape_by_name.get(thunk_ref, "unknown")
                )
                break
    return {
        "function": function.name,
        "implementation_pointer_refs": implementation_pointer_refs,
        "line_range": [function.start_line, function.end_line],
        "mapped_entry_thunk": mapped_entry_thunk,
        "mapped_implementation": mapped,
        "mapping_reason": mapping_reason,
        "tags": tags,
        "thunk_refs": thunk_pointer_refs,
        "vm_data_refs": refs,
    }


def score_from_counts(metrics: dict[str, Any]) -> dict[str, int]:
    concentration_score = min(int(metrics["max_refs_to_single_vm_data"]) // 6, 36)
    confidence_penalty = {
        "single_blob": 12,
        "concentrated": 8,
        "sharded": 4,
        "sharded_with_decoys": 3,
        "scattered": 2,
        "scattered_with_decoys": 1,
        "low": 0,
    }.get(str(metrics.get("data_mapping_confidence", "low")), 0)
    return {
        "bytecode_data_refs": min(metrics["bytecode_data_ref_count"] * 4, 24),
        "data_ref_concentration": concentration_score + confidence_penalty,
        "dispatcher_blocks": min(metrics["dispatcher_block_count"] * 2, 24),
        "generated_symbol_roles": min(metrics["generated_symbol_role_count"] * 5, 45),
        "handler_candidates": min(metrics["direct_success_to_handler_count"] * 2, 36)
        + min(metrics["trampoline_to_handler_count"], 18),
        "mapped_wrappers": min(metrics["direct_wrapper_mapping_count"] * 14, 42)
        + min(metrics["tag_correlated_wrapper_mapping_count"] * 10, 30)
        + min(metrics["thunked_wrapper_mapping_count"] * 7, 21)
        + min(metrics["polymorphic_thunked_wrapper_mapping_count"] * 5, 15)
        + min(metrics["indirect_wrapper_mapping_count"] * 4, 12)
        # pr29 indirect-ptr and decoy-guarded thunks are harder to map — lower penalty
        + min(metrics["indirect_thunked_wrapper_mapping_count"] * 3, 9)
        + min(metrics["decoy_thunked_wrapper_mapping_count"] * 3, 9),
        "entry_thunks": min(metrics["entry_thunk_count"] * 2, 8),
        "raw_opcode_compares": min(metrics["raw_direct_opcode_compare_count"] * 3, 48),
        "physical_opcodes": min(metrics["physical_opcode_count"] * 2, 36),
        "program_counter_candidates": min(metrics["program_counter_candidate_count"] * 2, 24),
        "repeated_helper_shapes": min(metrics["repeated_helper_shape_count"] * 8, 24),
        "split_opcode_predicates": min(metrics["local_split_opcode_header_count"], 12)
        + min(metrics["nonlocal_split_opcode_header_count"], 6),
        "state_candidates": min(metrics["state_candidate_count"] * 2, 24),
        "transformed_opcode_compares": min(metrics["transformed_opcode_compare_count"], 24),
        "transformed_opcode_constants": min(metrics["transformed_opcode_constant_count"], 18),
        "vm_functions": min(metrics["vm_function_count"] * 8, 48),
        "vm_markers": min(metrics["vm_marker_count"], 36),
        "wrappers": min(metrics["wrapper_count"] * 12, 36),
    }


def build_helper_shape_groups(vm_function_summaries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[str]] = defaultdict(list)
    fingerprints: dict[str, dict[str, Any]] = {}
    for summary in vm_function_summaries:
        if summary["kind"] not in {"helper", "subhelper"}:
            continue
        fingerprint = {
            "alloca_count": summary["alloca_count"],
            "basic_block_count": summary["basic_block_count"],
            "dispatcher_block_count": summary["dispatcher_block_count"],
            "handler_block_candidate_count": summary["handler_block_candidate_count"],
            "indirectbr_count": summary["indirectbr_count"],
            "kind": summary["kind"],
            "opcode_compare_count": summary["opcode_compare_count"],
            "physical_opcode_count": len(summary["physical_opcodes"]),
            "split_opcode_header_count": summary["split_opcode_header_count"],
            "transformed_opcode_constant_count": len(summary["transformed_opcode_constants"]),
            "switch_count": summary["switch_count"],
            "trap_count": summary["trap_count"],
        }
        fingerprint_hash = stable_hash_json(fingerprint)
        grouped[fingerprint_hash].append(summary["function"])
        fingerprints[fingerprint_hash] = fingerprint

    groups = []
    for fingerprint_hash, functions in sorted(grouped.items()):
        if len(functions) <= 1:
            continue
        groups.append(
            {
                "count": len(functions),
                "fingerprint": fingerprints[fingerprint_hash],
                "fingerprint_hash": fingerprint_hash,
                "functions": sorted(functions),
            }
        )
    return groups


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


def summarize_entropy_fingerprint(
    functions: dict[str, FunctionIR], marker_counts: dict[str, int]
) -> dict[str, Any]:
    thunk_shape_counts: Counter[str] = Counter()
    accessor_shape_counts: Counter[str] = Counter()
    thunk_to_accessor: list[tuple[str, str]] = []

    for function in sorted(functions.values(), key=lambda item: item.name):
        accessor_names: list[str] = []
        for match in DIRECT_CALL_PATTERN.finditer(function.body):
            accessor_name = match.group("name")
            if not ENTROPY_ACCESSOR_PATTERN.fullmatch(accessor_name):
                continue
            accessor_names.append(accessor_name)
            accessor_shape_counts[accessor_name] += 1
            thunk_to_accessor.append((function.name, accessor_name))

        if not accessor_names:
            continue

        thunk_shape_counts[classify_entropy_thunk_shape(function.body)] += 1

    entropy_thunk_count = sum(thunk_shape_counts.values())
    entropy_reader_xref_count = sum(accessor_shape_counts.values())
    dominant_entropy_shape_count = max(accessor_shape_counts.values(), default=0)
    entropy_accessor_variant_count = len(accessor_shape_counts)

    entropy_fingerprint_confidence = "low"
    if entropy_reader_xref_count:
        if entropy_accessor_variant_count <= 1:
            entropy_fingerprint_confidence = "single_shape"
        elif dominant_entropy_shape_count * 10 >= entropy_reader_xref_count * 7:
            entropy_fingerprint_confidence = "few_shapes"
        else:
            entropy_fingerprint_confidence = "polymorphic"

    return {
        "entropy_accessor_count": entropy_reader_xref_count,
        "entropy_accessor_variant_count": entropy_accessor_variant_count,
        "entropy_accessor_shape_counts": dict(sorted(accessor_shape_counts.items())),
        "dominant_entropy_shape_count": dominant_entropy_shape_count,
        "entropy_reader_xref_count": entropy_reader_xref_count,
        "entropy_thunk_count": entropy_thunk_count,
        "entropy_thunk_shape_counts": dict(sorted(thunk_shape_counts.items())),
        "entropy_fingerprint_confidence": entropy_fingerprint_confidence,
        "entropy_thunk_to_accessor": [
            {"thunk": thunk_name, "accessor": accessor_name}
            for thunk_name, accessor_name in thunk_to_accessor
        ],
        "entropy_marker_counts": {
            key: value
            for key, value in marker_counts.items()
            if key.startswith("entropy.thunk.") and value
        },
    }


def build_findings(
    benchmark: str,
    wrappers: list[dict[str, Any]],
    callsites: list[dict[str, Any]],
    vm_function_summaries: list[dict[str, Any]],
    symbol_counts: dict[str, int],
    metrics: dict[str, int],
    strict: bool,
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if metrics["vm_function_count"] == 0:
        findings.append(
            {
                "check": "vm_implementation_recovery",
                "detail": "no vm implementation-like functions were recovered from the IR",
                "severity": "fail" if strict else "warn",
            }
        )
    else:
        findings.append(
            {
                "check": "vm_implementation_recovery",
                "detail": f"recovered {metrics['vm_function_count']} vm implementation/helper function(s)",
                "severity": "info",
            }
        )

    if metrics["wrapper_count"]:
        findings.append(
            {
                "check": "wrapper_recovery",
                "detail": (
                    f"identified {metrics['wrapper_count']} interface wrapper(s), "
                    f"{metrics['mapped_wrapper_count']} mapped "
                    f"(direct={metrics['direct_wrapper_mapping_count']}, "
                    f"thunked={metrics['thunked_wrapper_mapping_count']}, "
                    f"polymorphic={metrics['polymorphic_thunked_wrapper_mapping_count']}, "
                    f"tag_correlated={metrics['tag_correlated_wrapper_mapping_count']}, "
                    f"indirect={metrics['indirect_wrapper_mapping_count']})"
                ),
                "severity": "info",
            }
        )
    else:
        findings.append(
            {
                "check": "wrapper_recovery",
                "detail": "no interface wrappers were recovered by marker or signature",
                "severity": "warn",
            }
        )

    if metrics["opcode_compare_count"]:
        findings.append(
            {
                "check": "opcode_recovery",
                "detail": (
                    f"recovered {metrics['raw_direct_opcode_compare_count']} raw i8 opcode compare(s), "
                    f"{metrics['physical_opcode_count']} raw physical opcode constant(s), "
                    f"{metrics['transformed_opcode_compare_count']} one-shot transformed opcode compare(s), "
                    f"and {metrics['split_opcode_header_count']} split opcode predicate header(s) "
                    f"({metrics['local_split_opcode_header_count']} local complete, "
                    f"{metrics['nonlocal_split_opcode_header_count']} non-local)"
                ),
                "severity": "warn",
            }
        )

    if metrics["raw_direct_opcode_compare_count"]:
        findings.append(
            {
                "check": "direct_i8_opcode_recovery",
                "detail": "direct icmp eq i8 opcode comparisons remain recoverable",
                "severity": "warn",
            }
        )

    if metrics["transformed_opcode_compare_count"] and not metrics["raw_direct_opcode_compare_count"]:
        findings.append(
            {
                "check": "opcode_recovery_confidence",
                "detail": "opcode headers use transformed integer compares; raw physical opcode confidence decreased",
                "severity": "info",
            }
        )

    if metrics["local_split_opcode_header_count"] and not metrics["raw_direct_opcode_compare_count"]:
        findings.append(
            {
                "check": "opcode_recovery_confidence",
                "detail": "opcode headers use split transformed predicates; direct constant confidence is partial",
                "severity": "info",
            }
        )

    if metrics["nonlocal_split_opcode_header_count"] and not metrics["raw_direct_opcode_compare_count"]:
        findings.append(
            {
                "check": "predicate_locality_confidence",
                "detail": (
                    "opcode predicate material crosses blocks; recovery is limited to "
                    f"{metrics['nonlocal_split_fragment_count']} non-local fragment store(s) and "
                    f"{metrics['nonlocal_split_opcode_header_count']} reload-bearing header(s)"
                ),
                "severity": "info",
            }
        )

    if metrics["handler_mapped_opcode_header_count"]:
        findings.append(
            {
                "check": "handler_mapping_confidence",
                "detail": (
                    f"direct success-to-handler: {metrics['direct_success_to_handler_count']}; "
                    f"success-to-trampoline: {metrics['success_to_trampoline_count']}; "
                    f"trampoline-to-handler: {metrics['trampoline_to_handler_count']}; "
                    f"routed: {metrics['routed_success_count']}; "
                    f"decoy ambiguous: {metrics['decoy_route_block_count']}"
                ),
                "severity": "info",
            }
        )

    if metrics["trap_oracle_direct_count"] or metrics["trap_oracle_indirect_count"]:
        findings.append(
            {
                "check": "trap_oracle_confidence",
                "detail": (
                    f"opcode headers with direct trap target: {metrics['trap_oracle_direct_count']}; "
                    f"with shared/indirect failure target: {metrics['trap_oracle_indirect_count']}"
                ),
                "severity": "info" if metrics["trap_oracle_direct_count"] == 0 else "warn",
            }
        )

    leaked_roles = sorted(role for role, count in symbol_counts.items() if count)
    if leaked_roles:
        findings.append(
            {
                "check": "generated_symbol_leakage",
                "detail": "generated symbol roles visible in IR: " + ",".join(leaked_roles),
                "severity": "warn",
            }
        )

    if metrics["bytecode_data_ref_count"]:
        findings.append(
            {
                "check": "bytecode_data_references",
                "detail": (
                    f"recovered {metrics['vm_data_ref_count']} vm data ref(s) across "
                    f"{metrics['unique_vm_data_ref_count']} unique symbol(s); "
                    f"max single-symbol refs={metrics['max_refs_to_single_vm_data']}; "
                    f"concentration={metrics['vm_data_ref_concentration']}; "
                    f"anchors={metrics['bytecode_anchor_count']}; "
                    f"shards={metrics['bytecode_shard_count']}; "
                    f"decoys={metrics['bytecode_decoy_count']}; "
                    f"confidence={metrics['bytecode_recovery_confidence']}"
                ),
                "severity": "warn"
                if metrics["data_mapping_confidence"] in {"single_blob", "concentrated"}
                else "info",
            }
        )

    if metrics["entropy_thunk_count"]:
        findings.append(
            {
                "check": "entropy_accessor_fingerprint",
                "detail": (
                    f"entropy thunks={metrics['entropy_thunk_count']}; "
                    f"accessor xrefs={metrics['entropy_reader_xref_count']}; "
                    f"variants={metrics['entropy_accessor_variant_count']}; "
                    f"dominant_shape={metrics['dominant_entropy_shape_count']}; "
                    f"confidence={metrics['entropy_fingerprint_confidence']}"
                ),
                "severity": "warn"
                if metrics["entropy_fingerprint_confidence"] in {"single_shape", "few_shapes"}
                else "info",
            }
        )

    expected_wrappers = STRONG_VM_EXPECTED_WRAPPERS.get(benchmark, ())
    wrappers_by_name = {wrapper["function"]: wrapper for wrapper in wrappers}
    for expected_wrapper in expected_wrappers:
        wrapper = wrappers_by_name.get(expected_wrapper)
        if wrapper is None:
            findings.append(
                {
                    "check": "strong_vm_local_decode",
                    "detail": f"expected strong_vm wrapper {expected_wrapper} was not identified",
                    "severity": "warn",
                }
            )
            continue
        if not str(wrapper["resolver_shape"]).startswith("local_decode"):
            findings.append(
                {
                    "check": "strong_vm_local_decode",
                    "detail": f"expected strong_vm wrapper {expected_wrapper} uses resolver shape {wrapper['resolver_shape']}",
                    "severity": "warn",
                }
            )
        else:
            findings.append(
                {
                    "check": "strong_vm_local_decode",
                    "detail": f"expected strong_vm wrapper {expected_wrapper} uses local target decode without a cached target global",
                    "severity": "info",
                }
            )

    if callsites:
        mapped_callsites = sum(1 for callsite in callsites if callsite["mapped_implementation"])
        findings.append(
            {
                "check": "callsite_rewrite_recovery",
                "detail": f"identified {len(callsites)} rewritten callsite host function(s), {mapped_callsites} mapped by tag or implementation pointer",
                "severity": "info",
            }
        )

    if vm_function_summaries:
        largest = max(summary["instruction_proxy_count"] for summary in vm_function_summaries)
        findings.append(
            {
                "check": "vm_shape_recovery",
                "detail": f"largest recovered vm-like function has {largest} non-empty IR instruction line(s)",
                "severity": "info",
            }
        )
    return sorted(findings, key=lambda item: (item["severity"], item["check"], item["detail"]))


def analyze_ir(
    benchmark: str,
    ir_text: str,
    ir_path_display: str,
    strict: bool,
) -> dict[str, Any]:
    functions = parse_functions(ir_text)
    vm_functions = sorted(
        [function for function in functions.values() if is_vm_function(function)],
        key=lambda function: function.name,
    )
    entry_thunk_functions = {
        function.name: function
        for function in vm_functions
        if classify_vm_function(function) == "entry_thunk"
    }
    entry_thunk_names = set(entry_thunk_functions)
    vm_function_summaries = [
        summarize_vm_function(function)
        for function in vm_functions
        if classify_vm_function(function) != "entry_thunk"
    ]
    implementation_functions = {
        function.name: function
        for function in vm_functions
        if classify_vm_function(function) == "implementation"
    }
    implementation_names = set(implementation_functions)
    entry_thunk_summaries = [
        summarize_entry_thunk(function, implementation_names)
        for function in sorted(entry_thunk_functions.values(), key=lambda item: item.name)
    ]
    entry_thunk_shape_counts = dict(
        sorted(Counter(summary["shape"] for summary in entry_thunk_summaries).items())
    )
    entry_thunk_impl_by_name = {
        summary["function"]: summary["mapped_implementation"]
        for summary in entry_thunk_summaries
        if summary["mapped_implementation"]
    }
    entry_thunk_shape_by_name = {
        summary["function"]: summary["shape"] for summary in entry_thunk_summaries
    }
    entry_thunks_by_impl: dict[str, list[str]] = defaultdict(list)
    for summary in entry_thunk_summaries:
        if summary["mapped_implementation"]:
            entry_thunks_by_impl[summary["mapped_implementation"]].append(summary["function"])
    entry_thunks_by_impl = {
        implementation: sorted(thunks)
        for implementation, thunks in sorted(entry_thunks_by_impl.items())
    }
    implementation_by_tag = {
        summary["tag"]: summary["function"]
        for summary in vm_function_summaries
        if summary["tag"] and summary["kind"] == "implementation"
    }
    wrappers = [
        summarize_wrapper(
            function,
            implementation_by_tag,
            implementation_functions,
            implementation_names,
            entry_thunk_functions,
            entry_thunk_names,
            entry_thunk_impl_by_name,
            entry_thunk_shape_by_name,
            entry_thunks_by_impl,
        )
        for function in sorted(functions.values(), key=lambda item: item.name)
        if is_wrapper_candidate(function, implementation_functions)
    ]
    callsites = [
        summarize_callsite_rewrite(
            function,
            implementation_by_tag,
            implementation_names,
            entry_thunk_functions,
            entry_thunk_names,
            entry_thunk_impl_by_name,
            entry_thunk_shape_by_name,
        )
        for function in sorted(functions.values(), key=lambda item: item.name)
        if is_callsite_rewrite_candidate(
            function, implementation_functions, implementation_names, entry_thunk_names
        )
    ]
    wrapper_to_implementation = {
        wrapper["function"]: wrapper["mapped_implementation"]
        for wrapper in wrappers
        if wrapper["mapped_implementation"]
    }
    symbols_by_role = collect_symbols_by_role(ir_text)
    symbol_counts = {role: len(symbols) for role, symbols in symbols_by_role.items()}
    shared_suffix_correlation_count = count_shared_suffix_correlations(symbols_by_role)
    marker_counts = count_markers(ir_text)
    nonzero_marker_counts = {key: value for key, value in marker_counts.items() if value}
    helper_shape_groups = build_helper_shape_groups(vm_function_summaries)
    entropy_fingerprint = summarize_entropy_fingerprint(functions, marker_counts)
    global_definitions = sorted(set(GLOBAL_DEFINITION_PATTERN.findall(ir_text)))
    physical_opcodes = sorted(
        {
            opcode
            for summary in vm_function_summaries
            for opcode in summary["physical_opcodes"]
        }
    )
    transformed_opcode_constants = sorted(
        {
            constant
            for summary in vm_function_summaries
            for constant in summary["transformed_opcode_constants"]
        }
    )
    split_opcode_immediates = sorted(
        {
            immediate
            for summary in vm_function_summaries
            for immediate in summary["split_opcode_immediates"]
        }
    )
    vm_data_ref_occurrences = Counter(
        ref for summary in vm_function_summaries for ref in summary["vm_data_ref_mentions"]
    )
    bytecode_ref_occurrences = Counter(
        ref
        for summary in vm_function_summaries
        for ref in summary["vm_data_ref_mentions"]
        if ref.startswith("__obf_vm_bc_")
    )
    bytecode_data_refs = sorted(
        {
            ref
            for summary in vm_function_summaries
            for ref in summary["vm_data_refs"]
        }
    )
    bytecode_global_defs = sorted(
        name for name in global_definitions if name.startswith("__obf_vm_bc_")
    )
    vm_data_ref_count = sum(vm_data_ref_occurrences.values())
    unique_vm_data_ref_count = len(vm_data_ref_occurrences)
    max_refs_to_single_vm_data = max(vm_data_ref_occurrences.values(), default=0)
    vm_data_ref_concentration = (
        round(max_refs_to_single_vm_data / vm_data_ref_count, 4) if vm_data_ref_count else 0.0
    )
    bytecode_ref_count = sum(bytecode_ref_occurrences.values())
    bytecode_anchor_count = len(bytecode_ref_occurrences)
    bytecode_shard_count = bytecode_anchor_count
    bytecode_global_count = len(bytecode_global_defs)
    # count decoys explicitly by name pattern (_d<hex> suffix) so that decoys
    # which receive actual reads (pr27.5 behavior) are still detected correctly.
    bytecode_named_decoy_count = len(
        {name for name in bytecode_global_defs if re.search(r"_d[0-9A-Fa-f]+$", name)}
    )
    bytecode_decoy_count = max(
        bytecode_named_decoy_count, max(0, bytecode_global_count - bytecode_anchor_count)
    )
    bytecode_real_anchor_count = bytecode_anchor_count - min(
        bytecode_named_decoy_count, bytecode_anchor_count
    )

    if bytecode_anchor_count <= 1 and max_refs_to_single_vm_data:
        if max_refs_to_single_vm_data >= 96:
            data_mapping_confidence = "single_blob"
        else:
            data_mapping_confidence = "concentrated"
    elif bytecode_anchor_count >= 2:
        if vm_data_ref_concentration >= 0.6:
            data_mapping_confidence = "sharded"
        elif vm_data_ref_concentration >= 0.35:
            data_mapping_confidence = "sharded"
        else:
            data_mapping_confidence = "scattered"
    else:
        data_mapping_confidence = "low"

    # upgrade confidence label when decoys are present (harder to distinguish
    # real anchors from decoys at binary analysis level).
    if bytecode_decoy_count > 0 and data_mapping_confidence in {"sharded", "scattered"}:
        if data_mapping_confidence == "scattered":
            bytecode_recovery_confidence = "scattered_with_decoys"
        else:
            bytecode_recovery_confidence = "sharded_with_decoys"
    else:
        bytecode_recovery_confidence = data_mapping_confidence
    route_family_counts = Counter(
        family
        for summary in vm_function_summaries
        for family, count in summary["route_family_counts"].items()
        for _ in range(count)
    )
    metrics = {
        "bytecode_anchor_count": bytecode_anchor_count,
        "bytecode_real_anchor_count": bytecode_real_anchor_count,
        "bytecode_decoy_count": bytecode_decoy_count,
        "bytecode_data_ref_count": len(bytecode_data_refs),
        "bytecode_global_count": bytecode_global_count,
        "bytecode_recovery_confidence": bytecode_recovery_confidence,
        "bytecode_ref_count": bytecode_ref_count,
        "bytecode_shard_count": bytecode_shard_count,
        "callsite_rewrite_count": len(callsites),
        "data_mapping_confidence": data_mapping_confidence,
        "direct_callsite_mapping_count": sum(
            1
            for callsite in callsites
            if callsite["mapping_reason"] in ("direct_call", "implementation_pointer")
        ),
        "dispatcher_block_count": sum(
            summary["dispatcher_block_count"] for summary in vm_function_summaries
        ),
        "generated_symbol_count": sum(symbol_counts.values()),
        "generated_symbol_role_count": sum(1 for count in symbol_counts.values() if count),
        "handler_candidate_count": sum(
            summary["handler_block_candidate_count"] for summary in vm_function_summaries
        ),
        "handler_mapped_opcode_header_count": sum(
            summary["handler_mapped_opcode_header_count"] for summary in vm_function_summaries
        ),
        "direct_success_to_handler_count": sum(
            summary["direct_success_to_handler_count"] for summary in vm_function_summaries
        ),
        "success_to_trampoline_count": sum(
            summary["success_to_trampoline_count"] for summary in vm_function_summaries
        ),
        "trampoline_to_handler_count": sum(
            summary["trampoline_to_handler_count"] for summary in vm_function_summaries
        ),
        "routed_success_count": sum(
            summary["routed_success_count"] for summary in vm_function_summaries
        ),
        "decoy_route_block_count": sum(
            summary["decoy_route_block_count"] for summary in vm_function_summaries
        ),
        "shared_route_block_count": sum(
            summary["shared_route_block_count"] for summary in vm_function_summaries
        ),
        "mapped_wrapper_count": len(wrapper_to_implementation),
        "direct_wrapper_mapping_count": sum(
            1
            for w in wrappers
            if w["mapped_implementation"]
            and w["mapping_reason"] in ("direct_call", "implementation_pointer")
        ),
        "entry_thunk_count": len(entry_thunk_functions),
        "entry_thunk_shape_counts": entry_thunk_shape_counts,
        "entropy_accessor_count": entropy_fingerprint["entropy_accessor_count"],
        "entropy_accessor_variant_count": entropy_fingerprint["entropy_accessor_variant_count"],
        "entropy_accessor_shape_counts": entropy_fingerprint["entropy_accessor_shape_counts"],
        "dominant_entropy_shape_count": entropy_fingerprint["dominant_entropy_shape_count"],
        "entropy_fingerprint_confidence": entropy_fingerprint["entropy_fingerprint_confidence"],
        "entropy_reader_xref_count": entropy_fingerprint["entropy_reader_xref_count"],
        "entropy_thunk_count": entropy_fingerprint["entropy_thunk_count"],
        "entropy_thunk_shape_counts": entropy_fingerprint["entropy_thunk_shape_counts"],
        "indirect_wrapper_mapping_count": sum(
            1 for w in wrappers if w["mapping_reason"] == "indirect"
        ),
        "polymorphic_thunked_wrapper_mapping_count": sum(
            1 for w in wrappers if w["mapping_reason"] == "polymorphic_thunked"
        ),
        "shared_suffix_correlation_count": shared_suffix_correlation_count,
        "tag_correlated_wrapper_mapping_count": sum(
            1 for w in wrappers if w["mapping_reason"] == "tag_correlated"
        ),
        "thunked_wrapper_mapping_count": sum(
            1 for w in wrappers if w["mapping_reason"] == "thunked"
        ),
        "thunked_callsite_mapping_count": sum(
            1
            for callsite in callsites
            if callsite["mapping_reason"]
            in ("thunked", "polymorphic_thunked", "indirect_thunked", "decoy_thunked")
        ),
        # pr29 router opacity: indirect-ptr thunks and decoy-guarded thunks
        "indirect_thunked_wrapper_mapping_count": sum(
            1 for w in wrappers if w["mapping_reason"] == "indirect_thunked"
        ),
        "decoy_thunked_wrapper_mapping_count": sum(
            1 for w in wrappers if w["mapping_reason"] == "decoy_thunked"
        ),
        "router_direct_target_count": sum(
            1 for summary in entry_thunk_summaries if summary["direct_implementation_call_count"]
        ),
        "router_indirect_target_count": sum(
            1 for summary in entry_thunk_summaries if summary["indirect_target_call_count"]
        ),
        "router_decoy_target_count": sum(
            1 for summary in entry_thunk_summaries if summary["shape"].startswith("decoy")
        ),
        "decoy_guarded_direct_call_count": sum(
            summary["direct_implementation_call_count"]
            for summary in entry_thunk_summaries
            if summary["shape"].startswith("decoy")
        ),
        "decoy_guarded_indirect_call_count": sum(
            summary["indirect_target_call_count"]
            for summary in entry_thunk_summaries
            if summary["shape"].startswith("decoy")
        ),
        "decoy_guarded_split_call_count": sum(
            summary["split_target_call_count"]
            for summary in entry_thunk_summaries
            if summary["shape"].startswith("decoy")
        ),
        "unmapped_wrapper_count": sum(1 for w in wrappers if not w["mapped_implementation"]),
        "opcode_compare_count": sum(
            summary["opcode_compare_count"] for summary in vm_function_summaries
        ),
        "physical_opcode_count": len(physical_opcodes),
        "local_split_opcode_header_count": sum(
            summary["local_split_opcode_header_count"] for summary in vm_function_summaries
        ),
        "nonlocal_split_fragment_count": sum(
            summary["nonlocal_split_fragment_count"] for summary in vm_function_summaries
        ),
        "nonlocal_split_opcode_header_count": sum(
            summary["nonlocal_split_opcode_header_count"] for summary in vm_function_summaries
        ),
        "nonlocal_split_reload_count": sum(
            summary["nonlocal_split_reload_count"] for summary in vm_function_summaries
        ),
        "program_counter_candidate_count": sum(
            summary["program_counter_candidate_count"] for summary in vm_function_summaries
        ),
        "raw_direct_opcode_compare_count": sum(
            summary["raw_direct_opcode_compare_count"] for summary in vm_function_summaries
        ),
        "repeated_helper_shape_count": len(helper_shape_groups),
        "split_opcode_compare_count": sum(
            summary["split_opcode_compare_count"] for summary in vm_function_summaries
        ),
        "split_opcode_header_count": sum(
            summary["split_opcode_header_count"] for summary in vm_function_summaries
        ),
        "split_opcode_immediate_count": len(split_opcode_immediates),
        "state_candidate_count": sum(
            summary["state_candidate_count"] for summary in vm_function_summaries
        ),
        "transformed_opcode_compare_count": sum(
            summary["transformed_opcode_compare_count"] for summary in vm_function_summaries
        ),
        "transformed_opcode_constant_count": len(transformed_opcode_constants),
        "unique_vm_data_ref_count": unique_vm_data_ref_count,
        "vm_data_ref_concentration": vm_data_ref_concentration,
        "vm_data_ref_count": vm_data_ref_count,
        "trap_oracle_direct_count": sum(
            summary["trap_oracle_direct_count"] for summary in vm_function_summaries
        ),
        "trap_oracle_indirect_count": sum(
            summary["trap_oracle_indirect_count"] for summary in vm_function_summaries
        ),
        "trap_oracle_none_count": sum(
            summary["trap_oracle_none_count"] for summary in vm_function_summaries
        ),
        "vm_function_count": len(vm_function_summaries),
        "vm_marker_count": sum(nonzero_marker_counts.values()),
        "wrapper_count": len(wrappers),
        "max_refs_to_single_vm_data": max_refs_to_single_vm_data,
    }
    opcode_recovery_confidence = "none"
    if metrics["raw_direct_opcode_compare_count"]:
        opcode_recovery_confidence = "raw_physical"
    elif metrics["transformed_opcode_compare_count"]:
        opcode_recovery_confidence = "transformed"
    elif metrics["local_split_opcode_header_count"]:
        opcode_recovery_confidence = "split_partial"
    elif metrics["nonlocal_split_opcode_header_count"] or metrics["nonlocal_split_fragment_count"]:
        opcode_recovery_confidence = "non_local_partial"
    predicate_locality_confidence = "none"
    if metrics["local_split_opcode_header_count"]:
        predicate_locality_confidence = "local_complete"
    elif metrics["nonlocal_split_opcode_header_count"] or metrics["nonlocal_split_fragment_count"]:
        predicate_locality_confidence = "non_local"
    handler_mapping_confidence = "none"
    if metrics["direct_success_to_handler_count"]:
        handler_mapping_confidence = "branch_target"
    elif metrics["decoy_route_block_count"]:
        handler_mapping_confidence = "decoy_ambiguous"
    elif metrics["trampoline_to_handler_count"]:
        handler_mapping_confidence = "trampoline"
    elif metrics["routed_success_count"]:
        handler_mapping_confidence = "routed"
    elif metrics["opcode_compare_count"]:
        handler_mapping_confidence = "low"
    direct_count = metrics["direct_wrapper_mapping_count"]
    thunked_count = metrics["thunked_wrapper_mapping_count"]
    polymorphic_count = metrics["polymorphic_thunked_wrapper_mapping_count"]
    tag_correlated_count = metrics["tag_correlated_wrapper_mapping_count"]
    indirect_count = metrics["indirect_wrapper_mapping_count"]
    # pr29 router opacity: indirect-ptr and decoy-guarded thunk families
    indirect_thunked_count = metrics["indirect_thunked_wrapper_mapping_count"]
    decoy_thunked_count = metrics["decoy_thunked_wrapper_mapping_count"]
    mapped_count = metrics["mapped_wrapper_count"]
    thunk_family_count = thunked_count + polymorphic_count + indirect_thunked_count + decoy_thunked_count
    opaque_thunked_count = polymorphic_count + indirect_thunked_count + decoy_thunked_count
    if direct_count and thunk_family_count:
        wrapper_mapping_confidence = "partial_thunked"
    elif direct_count:
        wrapper_mapping_confidence = "direct"
    elif thunked_count and not opaque_thunked_count:
        wrapper_mapping_confidence = "thunked"
    elif thunk_family_count:
        wrapper_mapping_confidence = (
            "polymorphic_thunked"
            if thunk_family_count == mapped_count
            else "partial_thunked"
        )
    elif tag_correlated_count:
        wrapper_mapping_confidence = "tag_correlated"
    elif indirect_count:
        wrapper_mapping_confidence = "indirect"
    else:
        wrapper_mapping_confidence = "none"
    decoy_direct_count = metrics["decoy_guarded_direct_call_count"]
    decoy_indirect_count = metrics["decoy_guarded_indirect_call_count"]
    decoy_split_count = metrics["decoy_guarded_split_call_count"]
    router_mapping_confidence = "none"
    if decoy_direct_count and (decoy_indirect_count or decoy_split_count):
        router_mapping_confidence = "mixed"
    elif decoy_direct_count:
        router_mapping_confidence = "direct_with_decoys"
    elif decoy_split_count and decoy_indirect_count:
        router_mapping_confidence = "mixed"
    elif decoy_split_count:
        router_mapping_confidence = "split_with_decoys"
    elif decoy_indirect_count:
        router_mapping_confidence = "indirect_with_decoys"
    elif metrics["router_direct_target_count"] and metrics["router_indirect_target_count"]:
        router_mapping_confidence = "mixed"
    elif metrics["router_indirect_target_count"]:
        router_mapping_confidence = "indirect"
    elif metrics["router_direct_target_count"]:
        router_mapping_confidence = "direct"
    trap_oracle_confidence = "none"
    if metrics["trap_oracle_direct_count"]:
        trap_oracle_confidence = "direct"
    elif metrics["trap_oracle_indirect_count"]:
        trap_oracle_confidence = "indirect"
    score_breakdown = score_from_counts(metrics)
    findings = build_findings(
        benchmark,
        wrappers,
        callsites,
        vm_function_summaries,
        symbol_counts,
        metrics,
        strict,
    )
    return {
        "benchmark": benchmark,
        "callsite_rewrites": callsites,
        "entry_thunks": entry_thunk_summaries,
        "entropy_fingerprint": entropy_fingerprint,
        "findings": findings,
        "global_definitions": global_definitions,
        "ir_path": ir_path_display,
        "marker_counts": nonzero_marker_counts,
        "metrics": metrics,
        "handler_mapping_confidence": handler_mapping_confidence,
        "data_mapping_confidence": data_mapping_confidence,
        "bytecode_recovery_confidence": bytecode_recovery_confidence,
        "opcode_recovery_confidence": opcode_recovery_confidence,
        "predicate_locality_confidence": predicate_locality_confidence,
        "physical_opcodes": physical_opcodes,
        "present": True,
        "recovery_score": sum(score_breakdown.values()),
        "repeated_helper_shapes": helper_shape_groups,
        "router_mapping_confidence": router_mapping_confidence,
        "score_breakdown": score_breakdown,
        "route_family_counts": dict(sorted(route_family_counts.items())),
        "symbols_by_role": symbols_by_role,
        "split_opcode_immediates": split_opcode_immediates,
        "trap_oracle_confidence": trap_oracle_confidence,
        "transformed_opcode_constants": transformed_opcode_constants,
        "vm_data_refs": bytecode_data_refs,
        "vm_functions": vm_function_summaries,
        "wrapper_mapping_confidence": wrapper_mapping_confidence,
        "wrapper_to_implementation": wrapper_to_implementation,
        "wrappers": wrappers,
    }


def missing_result(benchmark: str, ir_path_display: str, strict: bool) -> dict[str, Any]:
    return {
        "benchmark": benchmark,
        "callsite_rewrites": [],
        "findings": [
            {
                "check": "ir_discovery",
                "detail": f"missing obfuscated IR file {ir_path_display}",
                "severity": "fail" if strict else "warn",
            }
        ],
        "global_definitions": [],
        "ir_path": ir_path_display,
        "marker_counts": {},
        "metrics": {},
        "handler_mapping_confidence": "none",
        "router_mapping_confidence": "none",
        "opcode_recovery_confidence": "none",
        "predicate_locality_confidence": "none",
        "physical_opcodes": [],
        "present": False,
        "recovery_score": 0,
        "repeated_helper_shapes": [],
        "route_family_counts": {},
        "score_breakdown": {},
        "symbols_by_role": {},
        "split_opcode_immediates": [],
        "trap_oracle_confidence": "none",
        "transformed_opcode_constants": [],
        "vm_data_refs": [],
        "vm_functions": [],
        "wrapper_to_implementation": {},
        "wrappers": [],
    }


def parse_error_result(
    benchmark: str, ir_path_display: str, error: Exception, strict: bool
) -> dict[str, Any]:
    return {
        "benchmark": benchmark,
        "callsite_rewrites": [],
        "findings": [
            {
                "check": "ir_parse",
                "detail": str(error),
                "severity": "fail" if strict else "warn",
            }
        ],
        "global_definitions": [],
        "ir_path": ir_path_display,
        "marker_counts": {},
        "metrics": {},
        "router_mapping_confidence": "none",
        "opcode_recovery_confidence": "none",
        "physical_opcodes": [],
        "present": True,
        "recovery_score": 0,
        "repeated_helper_shapes": [],
        "score_breakdown": {},
        "symbols_by_role": {},
        "split_opcode_immediates": [],
        "trap_oracle_confidence": "none",
        "transformed_opcode_constants": [],
        "vm_data_refs": [],
        "vm_functions": [],
        "wrapper_to_implementation": {},
        "wrappers": [],
    }


def discover_ir_path(benchmarks_dir: pathlib.Path, benchmark: str) -> pathlib.Path | None:
    expected = benchmarks_dir / benchmark / f"{benchmark}.obfuscated.ll"
    if expected.is_file():
        return expected
    benchmark_dir = benchmarks_dir / benchmark
    if benchmark_dir.is_dir():
        matches = sorted(path for path in benchmark_dir.glob("*.obfuscated.ll") if path.is_file())
        if matches:
            return matches[0]
    return None


def relative_display(path: pathlib.Path, root: pathlib.Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def analyze_benchmark(
    benchmarks_dir: pathlib.Path, benchmark: str, strict: bool
) -> dict[str, Any]:
    ir_path = discover_ir_path(benchmarks_dir, benchmark)
    if ir_path is None:
        display = f"{benchmark}/{benchmark}.obfuscated.ll"
        return missing_result(benchmark, display, strict)
    display = relative_display(ir_path, benchmarks_dir)
    try:
        ir_text = ir_path.read_text(encoding="utf-8")
        return analyze_ir(benchmark, ir_text, display, strict)
    except Exception as error:  # noqa: BLE001
        return parse_error_result(benchmark, display, error, strict)


def apply_score_threshold(results: list[dict[str, Any]], threshold: int | None) -> None:
    if threshold is None:
        return
    for result in results:
        if not result.get("present"):
            continue
        score = int(result.get("recovery_score", 0))
        if score <= threshold:
            continue
        result["findings"].append(
            {
                "check": "recovery_score_threshold",
                "detail": f"recovery score {score} exceeds threshold {threshold}",
                "severity": "fail",
            }
        )
        result["findings"] = sorted(
            result["findings"], key=lambda item: (item["severity"], item["check"], item["detail"])
        )


def build_payload(
    requested_benchmarks: list[str],
    results: list[dict[str, Any]],
    benchmarks_dir: str,
    threshold: int | None,
) -> dict[str, Any]:
    failures = sum(
        1
        for result in results
        for finding in result["findings"]
        if finding["severity"] == "fail"
    )
    warnings = sum(
        1
        for result in results
        for finding in result["findings"]
        if finding["severity"] == "warn"
    )
    analyzed_results = [result for result in results if result.get("present")]
    return {
        "benchmarks": results,
        "schema_version": SCHEMA_VERSION,
        "summary": {
            "benchmarks_analyzed": len(analyzed_results),
            "benchmarks_dir": benchmarks_dir,
            "benchmarks_missing": [result["benchmark"] for result in results if not result.get("present")],
            "benchmarks_requested": requested_benchmarks,
            "fail_max_recovery_score": threshold,
            "failures": failures,
            "max_benchmark_recovery_score": max(
                (int(result.get("recovery_score", 0)) for result in results), default=0
            ),
            "status": "fail" if failures else "pass",
            "total_recovery_score": sum(int(result.get("recovery_score", 0)) for result in results),
            "warnings": warnings,
        },
        "tool": "obf-re-harness",
    }


def print_report(payload: dict[str, Any], verbose: bool) -> None:
    for result in payload["benchmarks"]:
        metrics = result.get("metrics", {})
        print(
            f"[{result['benchmark']}] score={result.get('recovery_score', 0)} "
            f"vm_functions={metrics.get('vm_function_count', 0)} "
            f"wrappers={metrics.get('wrapper_count', 0)} "
            f"mapped_wrappers={metrics.get('mapped_wrapper_count', 0)} "
            f"raw_opcodes={metrics.get('physical_opcode_count', 0)} "
            f"full_transformed={metrics.get('transformed_opcode_constant_count', 0)} "
            f"split_headers={metrics.get('split_opcode_header_count', 0)} "
            f"local_split={metrics.get('local_split_opcode_header_count', 0)} "
            f"nonlocal_split={metrics.get('nonlocal_split_opcode_header_count', 0)} "
            f"confidence={result.get('opcode_recovery_confidence', 'none')} "
            f"locality={result.get('predicate_locality_confidence', 'none')} "
            f"vm_data_refs={metrics.get('vm_data_ref_count', 0)} "
            f"vm_data_unique={metrics.get('unique_vm_data_ref_count', 0)} "
            f"vm_data_max={metrics.get('max_refs_to_single_vm_data', 0)} "
            f"vm_data_conc={metrics.get('vm_data_ref_concentration', 0.0)} "
            f"bytecode_anchors={metrics.get('bytecode_anchor_count', 0)} "
            f"bytecode_shards={metrics.get('bytecode_shard_count', 0)} "
            f"bytecode_decoys={metrics.get('bytecode_decoy_count', 0)} "
            f"bytecode_conf={result.get('bytecode_recovery_confidence', 'none')} "
            f"data_map={result.get('data_mapping_confidence', 'none')} "
            f"handler_map={result.get('handler_mapping_confidence', 'none')} "
            f"direct_handlers={metrics.get('direct_success_to_handler_count', 0)} "
            f"trampolines={metrics.get('success_to_trampoline_count', 0)} "
            f"wrapper_map={result.get('wrapper_mapping_confidence', 'none')} "
            f"direct_wrappers={metrics.get('direct_wrapper_mapping_count', 0)} "
            f"thunked_wrappers={metrics.get('thunked_wrapper_mapping_count', 0)} "
            f"poly_wrappers={metrics.get('polymorphic_thunked_wrapper_mapping_count', 0)} "
            f"tag_wrappers={metrics.get('tag_correlated_wrapper_mapping_count', 0)} "
            f"trap_oracle={result.get('trap_oracle_confidence', 'none')} "
            f"indirect_thunked={metrics.get('indirect_thunked_wrapper_mapping_count', 0)} "
            f"decoy_thunked={metrics.get('decoy_thunked_wrapper_mapping_count', 0)}"
        )
        if verbose:
            for finding in result["findings"]:
                print(f"[{finding['severity']}] {result['benchmark']} {finding['check']}: {finding['detail']}")
    summary = payload["summary"]
    print("summary:")
    print(f"  benchmarks analyzed: {summary['benchmarks_analyzed']}")
    print(f"  total recovery score: {summary['total_recovery_score']}")
    print(f"  failures: {summary['failures']}")
    print(f"  warnings: {summary['warnings']}")


def write_payload(path: pathlib.Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "score how much vm structure can be recovered from obfuscated llvm ir. "
            "higher scores mean more structure was recovered by the harness."
        )
    )
    parser.add_argument("--benchmarks-dir", type=pathlib.Path)
    parser.add_argument("--json-out", required=True, type=pathlib.Path)
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--benchmarks", default=",".join(DEFAULT_BENCHMARKS))
    parser.add_argument("--fail-max-recovery-score", type=int)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if not args.self_test and args.benchmarks_dir is None:
        parser.error("--benchmarks-dir is required unless --self-test is used")
    if args.fail_max_recovery_score is not None and args.fail_max_recovery_score < 0:
        parser.error("--fail-max-recovery-score must be non-negative")
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    requested = ["selftest"] if args.self_test else parse_csv(args.benchmarks)
    if args.self_test:
        results = [analyze_ir("selftest", SELF_TEST_IR, "<self-test>", args.strict)]
        benchmarks_dir_display = "<self-test>"
    else:
        benchmarks_dir = args.benchmarks_dir
        assert benchmarks_dir is not None
        benchmarks_dir_display = str(benchmarks_dir)
        if not benchmarks_dir.exists():
            results = [
                missing_result(benchmark, f"{benchmark}/{benchmark}.obfuscated.ll", args.strict)
                for benchmark in requested
            ]
            for result in results:
                result["findings"].append(
                    {
                        "check": "benchmarks_dir",
                        "detail": f"missing benchmarks directory {benchmarks_dir}",
                        "severity": "fail" if args.strict else "warn",
                    }
                )
        else:
            results = [analyze_benchmark(benchmarks_dir, benchmark, args.strict) for benchmark in requested]

    apply_score_threshold(results, args.fail_max_recovery_score)
    payload = build_payload(
        requested,
        sorted(results, key=lambda result: result["benchmark"]),
        benchmarks_dir_display,
        args.fail_max_recovery_score,
    )
    write_payload(args.json_out, payload)
    print_report(payload, args.verbose)
    print(f"json: {args.json_out}")
    return 1 if payload["summary"]["failures"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
