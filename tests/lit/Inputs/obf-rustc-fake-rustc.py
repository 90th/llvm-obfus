#!/usr/bin/env python3

import json
import os
import re
import signal
import sys
import time
from pathlib import Path


def expected_llvm_version() -> str:
    wrapper = os.environ.get("OBF_RUSTC_FAKE_WRAPPER")
    if wrapper:
        try:
            match = re.search(
                r'^LLVM_PACKAGE_VERSION = r"([^"]+)"$',
                Path(wrapper).read_text(encoding="utf-8"),
                re.MULTILINE,
            )
        except OSError:
            match = None
        if match is not None:
            return match.group(1)
    return "0.0"


def jobserver_fds_open() -> bool | None:
    if os.name != "posix":
        return None
    found_pair = False
    pattern = re.compile(r"(?:^|\s)--jobserver-(?:fds|auth)=(\d+),(\d+)(?=$|\s)")
    for variable in ("CARGO_MAKEFLAGS", "MAKEFLAGS"):
        for match in pattern.finditer(os.environ.get(variable, "")):
            found_pair = True
            try:
                os.fstat(int(match.group(1)))
                os.fstat(int(match.group(2)))
            except OSError:
                return False
    return True if found_pair else None


def record(arguments: list[str]) -> None:
    log_path = os.environ.get("OBF_RUSTC_FAKE_LOG")
    if not log_path:
        return
    row = {
        "args": arguments,
        "obf_config": os.environ.get("OBF_CONFIG"),
    }
    jobserver_open = jobserver_fds_open()
    if jobserver_open is not None:
        row["jobserver_fds_open"] = jobserver_open
    with Path(log_path).open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(row, sort_keys=True) + "\n")



def requested_signal(variable: str) -> int | None:
    value = os.environ.get(variable)
    return None if value is None else int(value)


def requested_output(arguments: list[str]) -> Path | None:
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "-o" and index + 1 < len(arguments):
            return Path(arguments[index + 1])
        if argument.startswith("-o") and len(argument) > 2:
            return Path(argument[2:])
        if argument == "--emit" and index + 1 < len(arguments):
            emit_value = arguments[index + 1]
            index += 2
        elif argument.startswith("--emit="):
            emit_value = argument.split("=", 1)[1]
            index += 1
        else:
            index += 1
            continue
        emit_parts = emit_value.split(",")
        if len(emit_parts) == 1 and "=" in emit_parts[0]:
            return Path(emit_parts[0].split("=", 1)[1])
    return None


def spawn_signal_descendant(signum: int, marker: Path) -> None:
    ready = marker.with_suffix(marker.suffix + ".ready")
    descendant = os.fork()
    if descendant == 0:
        def forwarded(received: int, _frame: object) -> None:
            marker.write_text(f"{received}\n", encoding="utf-8")
            os._exit(128 + received)

        signal.signal(signum, forwarded)
        ready.write_text("ready\n", encoding="utf-8")
        signal.pause()
        os._exit(98)

    deadline = time.monotonic() + 5
    while not ready.exists():
        if time.monotonic() >= deadline:
            raise RuntimeError("signal descendant did not become ready")
        time.sleep(0.01)


def signal_parent_and_wait(signum: int) -> None:
    marker = os.environ["OBF_RUSTC_FAKE_SIGNAL_MARKER"]
    descendant_marker = os.environ.get("OBF_RUSTC_FAKE_DESCENDANT_MARKER")
    if descendant_marker is not None:
        spawn_signal_descendant(signum, Path(descendant_marker))

    def forwarded(received: int, _frame: object) -> None:
        Path(marker).write_text(f"{received}\n", encoding="utf-8")
        raise SystemExit(128 + received)

    def timed_out(_received: int, _frame: object) -> None:
        raise SystemExit(99)

    signal.signal(signum, forwarded)
    signal.signal(signal.SIGALRM, timed_out)
    signal.alarm(5)
    os.kill(os.getppid(), signum)
    signal.pause()

def main() -> int:
    arguments = sys.argv[1:]
    record(arguments)
    if arguments in (["-vV"], ["-Vv"]):
        release = os.environ.get("OBF_RUSTC_FAKE_RELEASE", "1.99.0-nightly")
        llvm_version = os.environ.get("OBF_RUSTC_FAKE_LLVM", expected_llvm_version())
        print("rustc 1.99.0-nightly")
        print(f"release: {release}")
        print(f"LLVM version: {llvm_version}")
        probe_signal = requested_signal("OBF_RUSTC_FAKE_PROBE_SIGNAL")
        if probe_signal is not None:
            os.kill(os.getpid(), probe_signal)
        return int(os.environ.get("OBF_RUSTC_FAKE_PROBE_STATUS", "0"))
    if any(argument in {"--version", "-V", "-vV"} for argument in arguments):
        print("FAKE-QUERY-SENTINEL")
    else:
        print("FAKE-RUSTC-CHILD")
        output = requested_output(arguments)
        if output is not None:
            output.write_bytes(b"FAKE-RUSTC-OUTPUT\n")
        child_signal = requested_signal("OBF_RUSTC_FAKE_SIGNAL")
        if child_signal is not None:
            os.kill(os.getpid(), child_signal)
        parent_signal = requested_signal("OBF_RUSTC_FAKE_PARENT_SIGNAL")
        if parent_signal is not None:
            signal_parent_and_wait(parent_signal)
    return int(os.environ.get("OBF_RUSTC_FAKE_STATUS", "0"))


if __name__ == "__main__":
    raise SystemExit(main())
