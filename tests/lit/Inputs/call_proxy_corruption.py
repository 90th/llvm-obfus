"""Corrupt defined fields in a valid context and require an explicit trap."""

import argparse
import json
import os
from pathlib import Path
import re
import resource
import signal
import subprocess


FIELDS = (
    ("schema", 0, "i32"), ("phase", 1, "i32"), ("owner", 2, "i64"),
    ("site", 3, "i64"), ("route", 4, "i64"), ("descriptor", 5, "i32"),
    ("step", 6, "i32"), ("node", 7, "i64"), ("entropy", 8, "i64"),
    ("continuation", 9, "i64"), ("root", 10, "i64"), ("token", 11, "i64"),
    ("admitted_target", 12, "ptr"), ("encoded_target", 13, "i64"),
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--wrapper", required=True)
    parser.add_argument("--clang", required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--runtime", required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    for key in ("OBF_CONFIG", "OBF_ENABLE", "OBF_SEED", "OBF_LTO_MODE"):
        env.pop(key, None)
    env.update(TMPDIR=str(work), TEMP=str(work), TMP=str(work))

    def run(command, expected=0):
        result = subprocess.run([str(x) for x in command], env=env, capture_output=True,
                                text=True, timeout=120)
        with (work / "commands.jsonl").open("a") as log:
            log.write(json.dumps({"command": [str(x) for x in command], "exit": result.returncode,
                                  "stdout": result.stdout, "stderr": result.stderr}) + "\n")
        if result.returncode != expected:
            raise AssertionError(f"exit {result.returncode}, expected {expected}: {command!r}\n"
                                 f"{result.stdout}\n{result.stderr}")

    config = work / "policy.yaml"
    config.write_text("seed: 424242\ndefault_level: none\ntargets:\n"
                      "  - match: proxy_corruption\n    level: light\n"
                      "mba:\n  depth: 0\ncall_proxy:\n  enabled: true\n"
                      "  min_hops: 2\n  max_hops: 2\n")
    output = work / "output.ll"
    run([args.wrapper, f"--obf-config={config}", "-O2", "-x", "ir", "-S", "-emit-llvm",
         args.source.resolve(), "-o", output])
    text = output.read_text()
    functions = list(re.finditer(r"^define[^\n]*@[^\n]*\([^\n]*\)[^\n]*\{\n.*?^}",
                                 text, re.MULTILINE | re.DOTALL))
    owner = next(match for match in functions if "@proxy_corruption(" in match.group(0))
    first = next(match for match in functions if "@llvm.returnaddress" in match.group(0))
    terminal = next(match for match in functions
                    if re.search(r"call i64 %", match.group(0)) and "@llvm.returnaddress" not in match.group(0))
    owner_text, first_text, terminal_text = owner.group(0), first.group(0), terminal.group(0)
    entry = re.search(r"^.*notail call[^\n]*$", owner_text, re.MULTILINE)
    transfer = re.search(r"^.*musttail call[^\n]*$", first_text, re.MULTILINE)
    if entry is None or transfer is None:
        raise AssertionError("fixture did not emit the selected ordinary route")
    context = re.search(r"ptr (%[-\w.]+)\)", entry.group(0)).group(1)
    context_type = re.search(re.escape(context) + r" = alloca (\{[^\n]*?\}),", owner_text).group(1)
    hop_context = re.search(r"ptr (%[-\w.]+)\)", first_text.splitlines()[0]).group(1)

    def executable(name, body, trap):
        ir = work / (name + ".ll")
        ir.write_text(body)
        binary = work / name
        run([args.clang, "-O0", "-x", "ir", ir, "-x", "none", args.runtime, "-o", binary])
        run([binary], -signal.SIGILL if trap else 0)

    executable("valid", text, False)
    for name, index, value_type in FIELDS:
        mutation = (f"  %corrupt.field = getelementptr {context_type}, ptr {hop_context}, i32 0, i32 {index}\n"
                    f"  %corrupt.old = load {value_type}, ptr %corrupt.field\n")
        if value_type == "ptr":
            mutation += ("  %corrupt.bits = ptrtoint ptr %corrupt.old to i64\n"
                         "  %corrupt.flipped = xor i64 %corrupt.bits, 1\n"
                         "  %corrupt.new = inttoptr i64 %corrupt.flipped to ptr\n")
        else:
            mutation += f"  %corrupt.new = xor {value_type} %corrupt.old, 1\n"
        mutation += f"  store {value_type} %corrupt.new, ptr %corrupt.field\n"
        changed = first_text[:transfer.start()] + mutation + first_text[transfer.start():]
        executable("active-" + name, text.replace(first_text, changed, 1), True)
    terminal_name = re.search(r"@([^ (]+)\(", terminal_text).group(1)
    next_name = re.search(r"@([^ (]+)\(", transfer.group(0)).group(1)
    skipped = transfer.group(0).replace("@" + next_name + "(", "@" + terminal_name + "(")
    executable("skipped-hop", text.replace(first_text,
               first_text[:transfer.start()] + skipped + first_text[transfer.end():], 1), True)
    entry_name = re.search(r"@([^ (]+)\(", entry.group(0)).group(1)
    wrong_entry = entry.group(0).replace("@" + entry_name + "(", "@" + next_name + "(")
    executable("wrong-entry", text.replace(owner_text,
               owner_text[:entry.start()] + wrong_entry + owner_text[entry.end():], 1), True)
    replay_args = re.search(r"@[^ (]+\((.*)\)", entry.group(0)).group(1)
    replay = f"  %corrupt.replay = notail call i64 @{terminal_name}({replay_args})\n"
    replay_owner = owner_text[:entry.end()] + "\n" + replay + owner_text[entry.end():]
    executable("terminal-replay", text.replace(owner_text, replay_owner, 1), True)
    print("PASS valid route, fourteen active-context field traps, skipped hop, wrong entry, terminal replay")


if __name__ == "__main__":
    main()
