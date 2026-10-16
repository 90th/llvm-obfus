import argparse
from pathlib import Path
import re
import signal
import subprocess
import sys


def prepare(source, output):
    text = source.read_text()
    resolver = re.search(
        r"^define private i64 @__obf_vm_seed_resolve\([^\n]+\)[^\n]*\{\n(.*?)^\}",
        text, re.MULTILINE | re.DOTALL)
    if resolver is None:
        raise AssertionError("producer did not emit the shared VM seed resolver")
    keys = {int(value) & ((1 << 64) - 1) for value in
            re.findall(r"i64 (-?\d+), label", resolver.group(1))}
    if not keys:
        raise AssertionError("producer did not emit a permitted resolver key")
    invalid = 0
    while invalid in keys:
        invalid += 1
    main = re.compile(r"^define [^\n]*i32 @main\([^\n]*\)[^\n]*\{\n.*?^\}",
                      re.MULTILINE | re.DOTALL)
    replacement = ("define i32 @main() {\n"
                   f"  %result = call i64 @__obf_vm_seed_resolve(i64 {invalid}, i64 0)\n"
                   "  ret i32 0\n}")
    text, count = main.subn(lambda match: replacement, text)
    if count != 1:
        raise AssertionError("fixture must have exactly one main function")
    output.write_text(text)


def check(source, command):
    completed = subprocess.run([*command, str(source)], capture_output=True,
                               text=True, timeout=30)
    if sys.platform == "win32":
        trapped = (completed.returncode & 0xFFFFFFFF) in (0xC000001D, 0x80000003)
    else:
        trapped = completed.returncode in (-signal.SIGILL, -signal.SIGTRAP)
    if not trapped or completed.stdout:
        raise AssertionError("invalid resolver key must execute a native trap, not return, "
                             "segfault, or fail LLVM parsing/loading:\n"
                             f"exit={completed.returncode}\n{completed.stdout}\n{completed.stderr}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("prepare", "check"))
    parser.add_argument("source", type=Path)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.action == "prepare":
        if len(args.arguments) != 1:
            parser.error("prepare requires one output path")
        prepare(args.source, Path(args.arguments[0]))
    else:
        command = args.arguments[1:] if args.arguments[:1] == ["--"] else args.arguments
        if not command:
            parser.error("check requires an lli command")
        check(args.source, command)


if __name__ == "__main__":
    main()
