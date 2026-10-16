"""Exercise proxy results, effects, bounded tail recursion, and runtime isolation."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

EXPECTED = ""


def run(command, work, *, env=None):
    child_env = os.environ.copy()
    for key in ("OBF_CONFIG", "OBF_ENABLE", "OBF_SEED", "OBF_LTO_MODE", "OBF_LTO_INPUTS_VALIDATED"):
        child_env.pop(key, None)
    child_env.update(TMPDIR=str(work), TEMP=str(work), TMP=str(work))
    if env:
        child_env.update(env)
    result = subprocess.run(command, env=child_env, capture_output=True, text=True, timeout=300)
    with (work / "commands.jsonl").open("a") as log:
        log.write(json.dumps({"command": [str(x) for x in command], "exit": result.returncode,
                              "stdout": result.stdout, "stderr": result.stderr}) + "\n")
    if result.returncode:
        raise RuntimeError(f"exit {result.returncode}: {command!r}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def policy(path, level, hops, owners=None):
    if owners is None:
        owners = (
            ("proxy_scalar", "proxy_aggregate", "proxy_fp", "proxy_throw",
             "proxy_reentry", "proxy_tail", "proxy_tail_peer", "proxy_loop")
            if level == "light" else ("proxy_vm_target",)
        )
    targets = "".join(f"  - match: {owner}\n    level: {level}\n" for owner in owners)
    path.write_text(
        "frontend: rust\nseed: 424242\ndefault_level: none\ntargets:\n" + targets +
        "mba:\n  depth: 0\nvm:\n  max_mba_depth: 0\n"
        "security:\n  strip_release_markers: true\n  fail_on_public_obf_symbol: true\n"
        "call_proxy:\n  enabled: true\n"
        f"  min_hops: {hops}\n  max_hops: {hops}\n"
        "  mode_policy: mixed\n  coverage_policy: required\n"
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--wrapper", required=True)
    parser.add_argument("--clang", required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--level", choices=("light", "vm", "strong_vm"), default="light")
    parser.add_argument("--hops", type=int, default=2)
    parser.add_argument("--lto", choices=("none", "full", "thin"), default="none")
    parser.add_argument("--cet", action="store_true")
    parser.add_argument("--cfg", action="store_true")
    parser.add_argument("--shared", action="store_true")
    parser.add_argument("--readobj", default="llvm-readobj")
    args = parser.parse_args()
    args.wrapper = str(Path(args.wrapper).resolve())
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    source = args.source.resolve()
    flags = ["-std=c++17", "-O2", "-fno-optimize-sibling-calls"]
    if os.name != "nt":
        flags += ["-pthread", "-fPIE", "-pie"]
    else:
        flags += ["-fms-runtime-lib=dll"]
    if args.cet:
        flags += ["-fcf-protection=full", "-fno-omit-frame-pointer"]
    if args.cfg:
        flags += ["-Xclang", "-cfguard", "-Wl,/guard:cf"]
    extension = ".exe" if os.name == "nt" else ""
    control = work / ("control" + extension)
    run([args.clang, "--driver-mode=g++", *flags, str(source), "-o", str(control)], work)
    if run([str(control)], work) != EXPECTED:
        raise AssertionError("native control result or side effects changed")
    config = work / "policy.yaml"
    policy(config, args.level, args.hops)
    suffix = (".dll" if os.name == "nt" else ".so") if args.shared else extension
    protected = work / ("protected" + suffix)
    protected_flags = list(flags)
    if args.shared:
        protected_flags = [flag for flag in flags if flag not in ("-fPIE", "-pie")]
        protected_flags += ["-shared"]
        protected_flags += ["-Wl,/EXPORT:main"] if os.name == "nt" else ["-fPIC"]
    lto = [] if args.lto == "none" else [f"-flto={args.lto}"]
    report = work / "coverage.json"
    run([args.wrapper, f"--obf-config={config}",
         *protected_flags, *lto, str(source), "-o", str(protected)], work,
        env={"OBF_COVERAGE_REPORT": str(report)})
    execution = [str(protected)]
    if args.shared:
        loader = (
            "import ctypes,sys; from _ctypes import "
            + ("FreeLibrary" if os.name == "nt" else "dlclose")
            + " as close; lib=ctypes.CDLL(sys.argv[1]); "
            "lib.main.argtypes=[]; lib.main.restype=ctypes.c_int; "
            "result=lib.main(); close(lib._handle); sys.exit(result)"
        )
        execution = [sys.executable, "-c", loader, str(protected)]
    if run(execution, work) != EXPECTED:
        raise AssertionError("proxy result, side effect, or runtime transition changed")
    if os.name != "nt":
        dynamic = run([args.readobj, "--dynamic-table", str(protected)], work)
        if "TEXTREL" in dynamic:
            raise AssertionError("proxy image contains a text relocation")
    data = json.loads(report.read_text())
    emitted = [event for event in data["emission"]
               if event["mechanism"] == "call_proxy" and event["status"] == "emitted"]
    if not emitted:
        raise AssertionError("runtime equivalence without observed proxy emission is not coverage")
    if args.level != "light":
        if not any(event["mechanism"] == "vm" and event["status"] == "emitted"
                   for event in data["emission"]):
            raise AssertionError("VM proxy case did not virtualize its target")
    print(f"PASS actual-plugin {args.level} hops={args.hops} lto={args.lto} cet={args.cet} cfg={args.cfg}")


if __name__ == "__main__":
    main()
