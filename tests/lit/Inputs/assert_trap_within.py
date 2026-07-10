#!/usr/bin/env python3

import subprocess
import sys


if len(sys.argv) < 2:
    raise SystemExit("usage: assert_trap_within.py <command> [arg ...]")

try:
    result = subprocess.run(sys.argv[1:], timeout=2, check=False)
except subprocess.TimeoutExpired as error:
    raise SystemExit(f"child timed out after 2 seconds: {error}")

if result.returncode >= 0:
    raise SystemExit(f"child exited normally with status {result.returncode}; expected a signal trap")

raise SystemExit(0)
