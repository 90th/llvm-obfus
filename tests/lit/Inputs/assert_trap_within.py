#!/usr/bin/env python3

import signal
import subprocess
import sys


if len(sys.argv) < 2:
    raise SystemExit("usage: assert_trap_within.py <command> [arg ...]")

if sys.platform == "win32":
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32")
    kernel32.GetErrorMode.restype = ctypes.c_uint
    kernel32.SetErrorMode.argtypes = (ctypes.c_uint,)
    kernel32.SetErrorMode.restype = ctypes.c_uint
    previous_error_mode = kernel32.GetErrorMode()
    # Expected traps must not wait for Windows Error Reporting.
    kernel32.SetErrorMode(previous_error_mode | 0x0002)  # SEM_NOGPFAULTERRORBOX
else:
    import resource

    # Expected traps must not wait for core collection.
    _, hard_limit = resource.getrlimit(resource.RLIMIT_CORE)
    resource.setrlimit(resource.RLIMIT_CORE, (0, hard_limit))

try:
    result = subprocess.run(sys.argv[1:], timeout=2, check=False)
except subprocess.TimeoutExpired as error:
    raise SystemExit(f"child timed out after 2 seconds: {error}")
finally:
    if sys.platform == "win32":
        kernel32.SetErrorMode(previous_error_mode)

if sys.platform == "win32":
    trapped = (result.returncode & 0xFFFFFFFF) in (0xC000001D, 0x80000003)
else:
    trapped = result.returncode in (-signal.SIGILL, -signal.SIGTRAP)
if not trapped:
    raise SystemExit(f"child exited with status {result.returncode}; expected an illegal-instruction or breakpoint trap")

raise SystemExit(0)
