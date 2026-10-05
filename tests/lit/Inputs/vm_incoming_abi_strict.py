import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import tempfile

from report_contract import coverage_contract
from vm_incoming_abi import read_cases, run_process


TARGET = "vm_target"
MISMATCH_CASES = (
    "too_few", "surplus", "parameter_type", "return_type", "variadic_shape",
    "calling_convention", "extension_attribute",
)
MATCHING_CASES = ("matching_c", "matching_fast", "matching_extensions")
POLICIES = (
    ("strong_vm-standard", "strong_vm", "standard"),
    ("vm-fortress", "vm", "fortress"),
    ("vm-lab", "vm", "lab"),
)
PIPELINES = ("obf-vm", "obf-safe-pipeline")
VM_ROLES = {
    "public_wrapper", "regional_wrapper", "vm_implementation", "vm_entry_thunk",
    "generated_vm_helper",
}
TIMEOUT = 30


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def isolated_environment(report=None):
    environment = os.environ.copy()
    for key in tuple(environment):
        name = key.upper()
        if name in {"OBF_CONFIG", "OBF_ENABLE", "OBF_SEED", "OBF_COVERAGE_REPORT"} or name.startswith("OBF_LTO_"):
            del environment[key]
    if report is not None:
        environment["OBF_COVERAGE_REPORT"] = str(report)
    return environment


@contextmanager
def suppress_crash_collection():
    # Preserve process status and diagnostics; suppress only OS crash collection.
    if os.name == "nt":
        import ctypes

        kernel32 = ctypes.WinDLL("kernel32")
        kernel32.GetErrorMode.argtypes = ()
        kernel32.GetErrorMode.restype = ctypes.c_uint
        kernel32.SetErrorMode.argtypes = (ctypes.c_uint,)
        kernel32.SetErrorMode.restype = ctypes.c_uint
        previous = kernel32.GetErrorMode()
        kernel32.SetErrorMode(previous | 0x0002)  # SEM_NOGPFAULTERRORBOX
        try:
            yield
        finally:
            kernel32.SetErrorMode(previous)
    else:
        import resource

        previous = resource.getrlimit(resource.RLIMIT_CORE)
        resource.setrlimit(resource.RLIMIT_CORE, (0, previous[1]))
        try:
            yield
        finally:
            resource.setrlimit(resource.RLIMIT_CORE, previous)


def run(command, folder, label, *, report=None, expected_rejection=False):
    command = [str(argument) for argument in command]
    options = {
        "cwd": folder,
        "env": isolated_environment(report),
        "timeout": TIMEOUT,
    }
    if expected_rejection:
        with suppress_crash_collection():
            result = run_process(command, **options)
    else:
        result = run_process(command, **options)
    (folder / f"{label}.stdout").write_text(result.stdout, encoding="utf-8")
    (folder / f"{label}.stderr").write_text(result.stderr, encoding="utf-8")
    (folder / f"{label}.result.json").write_text(
        json.dumps({"command": command, "returncode": result.returncode}) + "\n",
        encoding="utf-8",
    )
    if not expected_rejection:
        require(result.returncode == 0,
                f"{folder}: {label} failed with {result.returncode}\n{result.stderr}")
    return result


def require_boundary_rejection(result, folder):
    require(result.returncode != 0,
            f"{folder}: expected opt rejection, got success\n{result.stderr}")
    require("vm strict boundary violation" in result.stderr,
            f"{folder}: compiler failure was not a deliberate strict VM boundary rejection\n{result.stderr}")


def load_report(path, level):
    require(path.is_file(), f"missing strict ABI coverage report: {path}")
    report = coverage_contract(json.loads(path.read_text(encoding="utf-8")))
    require(report["capture"] == "enabled", f"coverage capture disabled: {path}")
    selected = [event for event in report["requested_policy"]
                if event["owner"] == TARGET and event["phase"] == "selected"]
    require(len(selected) == 1, f"missing/duplicated selected policy for {TARGET}: {path}")
    snapshot = selected[0]
    require(snapshot["target"] == TARGET and snapshot["scope"] == "function",
            f"selected policy lost original target identity: {path}")
    require(snapshot["policy"]["allow_vm"] is True and snapshot["policy"]["level"] == level,
            f"strict ABI test lost VM eligibility or requested level: {path}")
    return report


def target_events(report, stage, mechanism):
    return [event for event in report[stage]
            if event["mechanism"] == mechanism
            and (event["owner"] == TARGET or event["target"] == TARGET)]


def require_target_event(event, status, folder):
    require(event["owner"] == TARGET and event["target"] == TARGET
            and event["scope"] == "whole_function" and event["status"] == status,
            f"{folder}: wrong target, scope, or {status} outcome: {event}")


def check_rejection(report, folder):
    incoming = target_events(report, "admission", "vm_incoming_site")
    require(len(incoming) == 1, f"{folder}: missing/duplicated incoming ABI rejection")
    event = incoming[0]
    require_target_event(event, "rejected", folder)
    require(event["count"] == 1, f"{folder}: incoming ABI rejection must describe one call")
    require(not target_events(report, "admission", "vm"),
            f"{folder}: strict incoming rejection occurred after VM binding admission")
    require(not target_events(report, "emission", "vm"),
            f"{folder}: ABI-rejected target reached VM emission")
    require(not any(role["role"] in VM_ROLES
                    and (role["owner"] == TARGET or role["target"] == TARGET)
                    for role in report["roles"]),
            f"{folder}: ABI-rejected target claims generated VM roles")


def check_matching(report, folder):
    require(not target_events(report, "admission", "vm_incoming_site"),
            f"{folder}: compatible incoming call was classified as restricted")
    admission = target_events(report, "admission", "vm")
    require(len(admission) == 1, f"{folder}: missing/duplicated compatible VM admission")
    require_target_event(admission[0], "admitted", folder)
    require(admission[0]["count"] == 1,
            f"{folder}: compatible admission must include the one incoming call")
    emission = target_events(report, "emission", "vm")
    require(len(emission) == 1, f"{folder}: missing/duplicated compatible VM emission")
    require_target_event(emission[0], "emitted", folder)
    require(emission[0]["count"] > 0, f"{folder}: compatible target emitted no VM instructions")


def write_policy(path, level, profile):
    path.write_text(
        f"profile: {profile}\n"
        "seed: 9001\n"
        "default_level: none\n"
        "targets:\n"
        f"  - match: {TARGET}\n"
        f"    level: {level}\n"
        "vm:\n"
        "  max_mba_depth: 0\n"
        "security:\n"
        "  fail_on_public_obf_symbol: true\n",
        encoding="utf-8",
    )


def main():
    parser = argparse.ArgumentParser(description="Strict incoming VM ABI regression matrix")
    parser.add_argument("--cases", required=True, type=Path)
    parser.add_argument("--plugin", required=True, type=Path)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("opt", nargs=argparse.REMAINDER,
                        help="expanded opt launcher argv after --")
    args = parser.parse_args()
    opt = args.opt[1:] if args.opt[:1] == ["--"] else args.opt
    if not opt:
        parser.error("the expanded opt command is required after --")
    cases = read_cases(args.cases)
    names = MISMATCH_CASES + MATCHING_CASES
    require(set(cases) == set(names), "strict ABI fixture must contain exactly the ten agreed cases")
    plugin = args.plugin.resolve()
    parent = args.work.resolve()
    parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="vm-incoming-abi-strict-", dir=parent))
    sources = {}
    # Verify every source before running any transform: a verifier failure must
    # never satisfy an expected strict-boundary rejection.
    for name in names:
        folder = work / "inputs" / name
        folder.mkdir(parents=True)
        source = folder / "input.ll"
        source.write_text(cases[name], encoding="utf-8")
        sources[name] = source
        run([*opt, "-passes=verify", "-disable-output", source], folder, "verify-input")
    for policy, level, profile in POLICIES:
        for pipeline in PIPELINES:
            for name in names:
                folder = work / policy / pipeline / name
                folder.mkdir(parents=True)
                config = folder / "policy.yaml"
                report_path = folder / "coverage.json"
                write_policy(config, level, profile)
                mismatch = name in MISMATCH_CASES
                result = run(
                    [*opt, "-load-pass-plugin", plugin, f"--obf-config={config}",
                     f"-passes={pipeline},verify", "-S", sources[name], "-o", folder / "output.ll"],
                    folder, "transform", report=report_path, expected_rejection=mismatch,
                )
                if mismatch:
                    require_boundary_rejection(result, folder)
                report = load_report(report_path, level)
                if mismatch:
                    check_rejection(report, folder)
                else:
                    check_matching(report, folder)
                    run([*opt, "-passes=verify", "-disable-output", folder / "output.ll"],
                        folder, "verify-output")
    # This matrix never executes the ABI-incompatible modules.
    print(f"Strict incoming VM ABI matrix: 10 verified inputs, 42 ABI rejections, "
          f"18 compatible verified VM emissions; evidence: {work}")


if __name__ == "__main__":
    main()
