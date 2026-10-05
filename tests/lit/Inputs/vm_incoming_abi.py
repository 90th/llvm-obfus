"""Check ordinary VM admission without executing undefined ABI mismatches."""

import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time

from report_contract import coverage_contract


CASE_NAMES = (
    "too_few", "surplus", "parameter_type", "return_type", "variadic_shape",
    "calling_convention", "extension_attribute", "matching_c", "matching_fast",
    "matching_extensions",
)
MISMATCH_CASES = frozenset(CASE_NAMES[:7])
RUNNABLE_CASES = frozenset({
    "surplus", "variadic_shape", "matching_c", "matching_fast", "matching_extensions",
})


def read_cases(path: Path) -> dict[str, str]:
    """Read standalone modules separated by exact column-zero case markers."""
    cases = {}
    name = None
    lines = []
    for line in path.read_text().splitlines(keepends=True):
        marker = re.fullmatch(r";--- ([a-z_]+)\r?\n?", line)
        if marker:
            if name is not None:
                cases[name] = "".join(lines).strip() + "\n"
            name = marker[1]
            if name not in CASE_NAMES or name in cases:
                raise ValueError(f"unknown or duplicate ABI case: {name}")
            lines = []
        elif name is not None:
            lines.append(line)
        elif line.strip() and not line.lstrip().startswith(";"):
            raise ValueError("module text appears before the first ABI case marker")
    if name is not None:
        cases[name] = "".join(lines).strip() + "\n"
    if tuple(cases) != CASE_NAMES or any(not text.strip() for text in cases.values()):
        raise ValueError(f"expected exactly the ten ordered ABI cases, got {tuple(cases)}")
    return cases


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def _remaining_cleanup_time(deadline, limit=None):
    remaining = max(0, deadline - time.monotonic())
    return remaining if limit is None else min(remaining, limit)


def _terminate_process_tree(process, deadline):
    failures = []
    if os.name != "nt":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as error:
            failures.append(f"cannot kill process group {process.pid}: {error}")
        return failures

    # Kill descendants while their launcher is still alive: killing the root
    # first loses the tree that taskkill needs to find the real compiler.
    system_root = os.environ.get("SystemRoot")
    if not system_root:
        return ["cannot locate native taskkill: SystemRoot is not set"]
    command = [
        str(Path(system_root) / "System32" / "taskkill.exe"),
        "/PID", str(process.pid), "/T", "/F",
    ]
    try:
        terminator = subprocess.Popen(
            command, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except OSError as error:
        return [f"cannot start native taskkill for {process.pid}: {error}"]
    try:
        status = terminator.wait(timeout=_remaining_cleanup_time(deadline, 3))
    except (subprocess.TimeoutExpired, OSError) as error:
        failures.append(f"taskkill did not finish terminating process tree {process.pid}: {error}")
        try:
            terminator.kill()
        except OSError as error:
            failures.append(f"cannot kill timed-out taskkill: {error}")
        try:
            terminator.wait(timeout=_remaining_cleanup_time(deadline, 1))
        except (subprocess.TimeoutExpired, OSError) as error:
            failures.append(f"cannot reap failed taskkill within cleanup deadline: {error}")
    else:
        if status != 0:
            failures.append(f"taskkill failed for process tree {process.pid}: exit {status}")
    return failures


def _captured_output(stream, *, snapshot=False):
    # A failed descendant may still be writing. Freeze the read size in that
    # case instead of chasing a growing file to EOF.
    size = os.fstat(stream.fileno()).st_size if snapshot else -1
    stream.seek(0)
    text = stream.read(size).decode("utf-8", errors="replace")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def run_process(command, *, cwd=None, env=None, timeout=30) -> subprocess.CompletedProcess[str]:
    """Capture a command without interpreting its exit status.

    File-backed output avoids inherited-pipe deadlocks, including during failed
    cleanup. The operation deadline is followed by at most five seconds for
    process-tree termination and root reaping. A clean cancellation raises
    TimeoutExpired with a finite UTF-8 partial-output snapshot; cleanup failure
    raises RuntimeError chained from that timeout, never a successful result.
    Normal completion reads the complete output, including JSON reports.
    """
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        process = subprocess.Popen(
            command, cwd=cwd, env=env, stdout=stdout_file, stderr=stderr_file,
            start_new_session=os.name != "nt",
        )
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as expired:
            deadline = time.monotonic() + 5
            failures = _terminate_process_tree(process, deadline)
            # This is only a root-reaping safeguard after tree cancellation.
            # Root-only termination must not hide a failed tree operation.
            try:
                process.kill()
            except ProcessLookupError:
                pass
            except OSError as error:
                failures.append(f"cannot kill launcher {process.pid}: {error}")
            try:
                process.wait(timeout=_remaining_cleanup_time(deadline))
            except (subprocess.TimeoutExpired, OSError) as error:
                failures.append(
                    f"cannot reap launcher {process.pid} within cleanup deadline: {error}"
                )
            expired.output = _captured_output(stdout_file, snapshot=True)
            expired.stderr = _captured_output(stderr_file, snapshot=True)
            if failures:
                raise RuntimeError(
                    f"timeout cleanup failed for {command!r}: {'; '.join(failures)}\n"
                    f"stdout:\n{expired.output}\nstderr:\n{expired.stderr}"
                ) from expired
            raise
        return subprocess.CompletedProcess(
            command, process.returncode,
            _captured_output(stdout_file), _captured_output(stderr_file),
        )


def run(command):
    env = os.environ.copy()
    # Include coverage and LTO switches: no inherited obfuscation policy may
    # affect input verification, another case, or either pipeline.
    for key in list(env):
        if key.upper().startswith("OBF_"):
            env.pop(key)
    result = run_process(command, env=env)
    if result.returncode != 0:
        raise RuntimeError(
            f"unexpected exit {result.returncode}: {command!r}\n"
            f"{result.stdout}\n{result.stderr}"
        )
    return result


def check_report(report, case):
    coverage_contract(report)
    require(report["capture"] == "enabled", f"{case}: compiler ledger was not captured")
    selected = [event for event in report["requested_policy"]
                if event["owner"] == "vm_target" and event["phase"] == "selected"]
    require(len(selected) == 1, f"{case}: target selection missing or duplicated")
    snapshot = selected[0]
    require(snapshot["target"] == "vm_target" and snapshot["scope"] == "function",
            f"{case}: selected policy lost the original target identity: {snapshot}")
    require(snapshot["policy"]["allow_vm"] is True and snapshot["policy"]["level"] == "vm",
            f"{case}: target lost VM eligibility or requested level: {snapshot}")
    incoming = [event for event in report["admission"]
                if event["mechanism"] == "vm_incoming_site"]
    if case in MISMATCH_CASES:
        require(len(incoming) == 1, f"{case}: incoming restriction missing or duplicated")
        event = incoming[0]
        require(
            event["owner"] == event["target"] == "vm_target"
            and event["scope"] == "whole_function" and event["status"] == "preserved"
            and event["count"] == 1,
            f"{case}: ABI-incompatible incoming call was not preserved: {event}",
        )
    else:
        require(not incoming, f"{case}: matching ABI acquired an incoming restriction")

    admitted = [event for event in report["admission"] if event["mechanism"] == "vm"]
    require(
        len(admitted) == 1 and admitted[0]["owner"] == admitted[0]["target"] == "vm_target"
        and admitted[0]["scope"] == "whole_function" and admitted[0]["status"] == "admitted"
        and admitted[0]["count"] == 1,
        f"{case}: target was not admitted with its one incoming site: {admitted}",
    )
    emitted = [event for event in report["emission"] if event["mechanism"] == "vm"]
    require(
        len(emitted) == 1 and emitted[0]["owner"] == emitted[0]["target"] == "vm_target"
        and emitted[0]["scope"] == "whole_function" and emitted[0]["status"] == "emitted"
        and emitted[0]["count"] > 0,
        f"{case}: preserved admission dropped actual whole-function VM emission: {emitted}",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", required=True, type=Path)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--plugin", required=True)
    parser.add_argument("--pipeline", required=True, choices=("obf-vm", "obf-safe-pipeline"))
    parser.add_argument("opt", nargs=argparse.REMAINDER,
                        help="opt command and launcher arguments, after --")
    args = parser.parse_args()
    opt = args.opt[1:] if args.opt[:1] == ["--"] else args.opt
    if not opt:
        parser.error("an opt command is required after --")

    # Lit supplies a unique %t root for each pipeline. Fail rather than reusing
    # stale reports or executable modules from an earlier invocation.
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=False)
    for case, source in read_cases(args.cases).items():
        require(bool(re.search(r"^define\b[^\n]*@main\(", source, re.MULTILINE))
                == (case in RUNNABLE_CASES),
                f"{case}: undefined ABI mismatch unexpectedly became executable")
        case_work = work / case
        case_work.mkdir()
        input_path = case_work / "input.ll"
        output_path = case_work / "output.ll"
        report_path = case_work / "coverage.json"
        config_path = case_work / "config.yaml"
        input_path.write_text(source)
        config_path.write_text(
            "seed: 9001\ndefault_level: none\ntargets:\n"
            "  - match: vm_target\n    level: vm\nmba:\n  depth: 2\n"
        )
        run([*opt, "-passes=verify", "-disable-output", str(input_path)])
        result = run([
            *opt, "-load-pass-plugin", args.plugin, f"--obf-config={config_path}",
            f"-passes=obf-coverage-start,{args.pipeline},verify,obf-coverage-report",
            "-S", str(input_path), "-o", str(output_path),
        ])
        report_path.write_text(result.stdout)
        check_report(json.loads(result.stdout), case)
        # Reparse the serialized output, not just the in-memory transform result.
        run([*opt, "-passes=verify", "-disable-output", str(output_path)])


if __name__ == "__main__":
    main()
