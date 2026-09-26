#!/usr/bin/env python3

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass


FUNCTION_HEADER = re.compile(r"^\s*(?P<address>[0-9A-Fa-f]+) <(?P<name>[^>]+)>:\s*$")
INSTRUCTION_LINE = re.compile(r"^\s*(?P<address>[0-9A-Fa-f]+):\s*(?P<body>.*?)\s*$")
DIRECT_TARGET = re.compile(r"^\s*(?:0x)?(?P<address>[0-9A-Fa-f]+)\b")


@dataclass(frozen=True)
class Branch:
    address: int
    mnemonic: str
    target: int
    conditional: bool
    line: str


class CheckFailure(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--llvm-objdump", required=True)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--function", required=True)
    return parser.parse_args()


def run_objdump(tool: str, binary: str) -> str:
    command = [tool, "--disassemble", "--no-show-raw-insn", "--print-imm-hex", binary]
    environment = dict(os.environ)
    environment["LANG"] = "C"
    environment["LC_ALL"] = "C"
    result = subprocess.run(command, check=False, capture_output=True, text=True, env=environment)
    if result.returncode != 0:
        raise CheckFailure(result.stderr.strip() or f"llvm-objdump failed with status {result.returncode}")
    return result.stdout


def collect_function_lines(disassembly: str, function_name: str) -> tuple[int, list[str]]:
    current_name = None
    current_address = None
    current_lines: list[str] = []
    for line in disassembly.splitlines():
        header = FUNCTION_HEADER.match(line)
        if header is not None:
            if current_name == function_name:
                return current_address, current_lines
            current_name = header.group("name")
            current_address = int(header.group("address"), 16)
            current_lines = []
            continue
        if current_name == function_name:
            current_lines.append(line)
    if current_name == function_name:
        return current_address, current_lines
    raise CheckFailure(f"missing function {function_name} in disassembly")


def parse_branches(function_lines: list[str], function_start: int) -> list[Branch]:
    branches: list[Branch] = []
    seen_instruction = False
    for line in function_lines:
        match = INSTRUCTION_LINE.match(line)
        if match is None:
            continue
        body = match.group("body").strip()
        if not body or body.startswith("."):
            continue
        seen_instruction = True
        pieces = body.split(None, 1)
        mnemonic = pieces[0].lower()
        if not mnemonic.startswith("j"):
            continue
        operands = pieces[1] if len(pieces) > 1 else ""
        if any(token in operands for token in ("*", "%", "(", ")")):
            continue
        target_match = DIRECT_TARGET.match(operands.split("#", 1)[0])
        if target_match is None:
            continue
        target = int(target_match.group("address"), 16)
        branches.append(
            Branch(
                address=int(match.group("address"), 16),
                mnemonic=mnemonic,
                target=target,
                conditional=mnemonic != "jmp",
                line=line.strip(),
            )
        )
    if not seen_instruction:
        raise CheckFailure(f"function {hex(function_start)} has no instructions")
    return branches


def require_dispatch_shape(branches: list[Branch], function_name: str) -> tuple[Branch, list[Branch]]:
    backward = sorted((branch for branch in branches if branch.target < branch.address), key=lambda branch: (branch.target, branch.address))
    if not backward:
        raise CheckFailure(
            f"{function_name} has no backward control-flow edge; expected a recurrent dispatcher loop"
        )
    for loop_edge in backward:
        forward_conditionals = [
            branch
            for branch in branches
            if branch.conditional and loop_edge.target <= branch.address < loop_edge.address and branch.target > branch.address
        ]
        distinct_targets = {branch.target for branch in forward_conditionals}
        if len(forward_conditionals) >= 2 and len(distinct_targets) >= 2:
            return loop_edge, forward_conditionals
    details = ", ".join(branch.line for branch in backward[:6])
    raise CheckFailure(
        f"{function_name} has backward edge(s) but no loop-closing region with multiple forward conditional dispatch edges: {details}"
    )


def main() -> int:
    arguments = parse_args()
    disassembly = run_objdump(arguments.llvm_objdump, arguments.binary)
    function_start, function_lines = collect_function_lines(disassembly, arguments.function)
    branches = parse_branches(function_lines, function_start)
    loop_edge, dispatch_branches = require_dispatch_shape(branches, arguments.function)
    distinct_targets = sorted({branch.target for branch in dispatch_branches})
    print(
        "NATIVE_DISPATCH: "
        f"function={arguments.function} "
        f"loop_edge=0x{loop_edge.address:x}->0x{loop_edge.target:x} "
        f"forward_conditionals={len(dispatch_branches)} "
        f"distinct_forward_targets={len(distinct_targets)}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CheckFailure as error:
        raise SystemExit(str(error))
