#!/usr/bin/env python3

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True)
    parser.add_argument("--symbol", required=True)
    parser.add_argument("--runtime", choices=("present", "absent"), required=True)
    parser.add_argument("--forbid")
    parser.add_argument("--require")
    arguments = parser.parse_args()

    directory = Path(arguments.directory)
    candidates: list[tuple[Path, str]] = []
    marker = f"@{arguments.symbol}"
    for path in sorted(directory.rglob("*.ll")):
        text = path.read_text(encoding="utf-8", errors="replace")
        if marker in text:
            candidates.append((path, text))
    if len(candidates) != 1:
        print(
            f"expected one LLVM IR artifact for {arguments.symbol}, found "
            f"{[str(path) for path, _ in candidates]}",
            file=sys.stderr,
        )
        return 1

    path, text = candidates[0]
    has_runtime = re.search(r"@rt_core_[A-Za-z0-9_]+", text) is not None
    expected_runtime = arguments.runtime == "present"
    if has_runtime != expected_runtime:
        print(
            f"{path}: expected runtime {arguments.runtime}, got "
            f"{'present' if has_runtime else 'absent'}",
            file=sys.stderr,
        )
        return 1
    if arguments.require and arguments.require not in text:
        print(f"{path}: required plaintext {arguments.require!r} is absent", file=sys.stderr)
        return 1
    if arguments.forbid and arguments.forbid in text:
        print(f"{path}: forbidden plaintext {arguments.forbid!r} remains", file=sys.stderr)
        return 1

    print(f"artifact={path}")
    print(f"runtime={arguments.runtime}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
