"""Check bounded ABI-runner cancellation using real socket-owning processes."""

import argparse
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

from vm_incoming_abi import run_process


HOST = "127.0.0.1"
OPERATION_TIMEOUT = 5
RUN_DEADLINE = 12
WORKER_DEADLINE = 15
CLEANUP_TIMEOUT = 5
# An interrupted controller must not leave a fixture alive indefinitely. This
# is longer than the watchdog, so natural fixture exit cannot pass the test.
FIXTURE_LIFETIME = 30
SCRIPT = Path(__file__).resolve()


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def new_socket():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Windows must not allow a second bind while the fixture is still alive.
    # Do not use SO_REUSEADDR: successful rebinding is the death witness.
    if sys.platform == "win32":
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    return listener


def command(mode, work, case):
    return [sys.executable, str(SCRIPT), "--mode", mode,
            "--work", str(work), "--case", case]


def fixture(work):
    stop = work / "stop"
    if stop.exists():
        return
    with new_socket() as listener:
        listener.bind((HOST, 0))
        listener.listen(1)
        marker = work / "ready.json"
        pending = work / "ready.pending"
        pending.write_text(json.dumps({"port": listener.getsockname()[1]}),
                           encoding="utf-8")
        pending.replace(marker)
        deadline = time.monotonic() + FIXTURE_LIFETIME
        # Keep stdout/stderr inherited from run_process open while blocked.
        # The stop file is solely an out-of-band failure-cleanup channel; no
        # connection is accepted, so TCP TIME_WAIT cannot affect rebinding.
        while not stop.exists() and time.monotonic() < deadline:
            time.sleep(0.05)


def launcher(work, case):
    if (work / "stop").exists():
        return 0
    # Mirror obf-opt: the launcher waits, and the real child inherits both
    # captured output handles. Killing only this launcher cannot drain them.
    child = subprocess.Popen(command("fixture", work, case))
    return child.wait()


def ready_port(work):
    marker = work / "ready.json"
    require(marker.is_file(), "fixture never published its ready marker")
    port = json.loads(marker.read_text(encoding="utf-8"))["port"]
    require(type(port) is int and 0 < port < 65536, "invalid fixture port")
    return port


def require_rebind(port, deadline):
    while True:
        try:
            with new_socket() as probe:
                probe.bind((HOST, port))
            return
        except OSError as error:
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"fixture port {port} is still bound after cancellation: {error}"
                ) from error
            time.sleep(0.05)


def worker(work, case):
    mode = "fixture" if case == "direct" else "launcher"
    started = time.monotonic()
    try:
        run_process(command(mode, work, case), cwd=work,
                    timeout=OPERATION_TIMEOUT)
    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - started
    else:
        raise AssertionError(f"{case}: expected subprocess.TimeoutExpired")
    require(elapsed < RUN_DEADLINE,
            f"{case}: run_process took {elapsed:.2f}s (limit {RUN_DEADLINE}s)")
    port = ready_port(work)
    # This assertion precedes every cleanup signal. It can succeed only if
    # run_process, not the controller, released the descendant's resource.
    require_rebind(port, time.monotonic() + 1)
    print(f"{case}: TimeoutExpired in {elapsed:.2f}s; child socket released")


def cleanup(work, process):
    deadline = time.monotonic() + CLEANUP_TIMEOUT
    errors = []
    try:
        (work / "stop").touch()
    except OSError as error:
        errors.append(f"could not signal fixture cleanup: {error}")
    if process is not None:
        try:
            # A broken nested runner is stuck draining inherited pipes. The
            # fixture's stop channel lets it unwind before we kill the worker.
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=max(0.001, deadline - time.monotonic()))
        except (OSError, subprocess.TimeoutExpired) as error:
            errors.append(f"could not reap regression worker: {error}")
    if (work / "ready.json").is_file():
        try:
            require_rebind(ready_port(work), deadline)
        except (AssertionError, OSError, ValueError, KeyError) as error:
            errors.append(f"fixture cleanup failed: {error}")
    require(not errors, "\n".join(errors))


def check_case(work, case):
    work.mkdir()
    log_path = work / "worker.log"
    process = None
    failures = []
    with log_path.open("w", encoding="utf-8") as log:
        try:
            # A file, not another captured pipe: even a broken runner cannot
            # make the controller block while collecting failure diagnostics.
            process = subprocess.Popen(command("worker", work, case),
                                       stdout=log, stderr=subprocess.STDOUT)
            try:
                process.wait(timeout=WORKER_DEADLINE)
            except subprocess.TimeoutExpired:
                failures.append(
                    f"{case}: worker exceeded {WORKER_DEADLINE}s watchdog; "
                    "run_process did not finish bounded cancellation"
                )
        finally:
            try:
                cleanup(work, process)
            except AssertionError as error:
                failures.append(str(error))
    output = log_path.read_text(encoding="utf-8", errors="replace")
    if process.returncode != 0:
        failures.append(f"{case}: worker exited with status {process.returncode}")
    require(not failures, "\n".join(failures) + "\n" + output)
    print(output, end="")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--mode", choices=("controller", "worker", "fixture", "launcher"),
                        default="controller")
    parser.add_argument("--case", choices=("direct", "nested"), default="direct")
    args = parser.parse_args()
    work = args.work.resolve()
    if args.mode == "fixture":
        fixture(work)
    elif args.mode == "launcher":
        return launcher(work, args.case)
    elif args.mode == "worker":
        worker(work, args.case)
    else:
        work.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="abi-timeout-", dir=work) as root:
            root = Path(root)
            for case in ("direct", "nested"):
                check_case(root / case, case)
    return 0


if __name__ == "__main__":
    sys.exit(main())
