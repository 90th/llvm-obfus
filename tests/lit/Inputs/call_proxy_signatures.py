"""Qualify vector, FastCC, direct aggregate, and nonzero-sret forwarding."""

import argparse
import json
import os
from pathlib import Path

from call_proxy_runtime import policy, run


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--wrapper", required=True)
    parser.add_argument("--clang", required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--runtime")
    args = parser.parse_args()
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    extension = ".exe" if os.name == "nt" else ""
    source = str(args.source.resolve())
    if os.name == "nt":
        # MSVC passes this input aggregate by pointer. Explicit byval has a
        # separate rejection fixture for the LLVM Win64 tail-lowering defect.
        native_source = work / "windows-signatures.ll"
        native_source.write_text(
            args.source.read_text().replace("ptr byval(%Big) align 8", "ptr")
            .replace("@main(", "@signature_entry("))
        source = str(native_source)
    flags = ["-O2", "-x", "ir"]
    if os.name == "nt":
        flags += ["-fms-runtime-lib=dll"]
    control = work / ("control" + extension)
    driver = work / "driver.c"
    if os.name == "nt":
        if not args.runtime:
            parser.error("Windows ABI qualification needs --runtime")
        driver.write_text("int signature_entry(void);\nint main(void) { return signature_entry(); }\n")
        control_object = work / "control.obj"
        run([args.clang, *flags, "-c", source, "-o", str(control_object)], work)
        run([args.clang, "-O2", "-fms-runtime-lib=dll", str(driver), str(control_object),
             "-o", str(control)], work)
    else:
        run([args.clang, *flags, source, "-o", str(control)], work)
    run([str(control)], work)
    config = work / "policy.yaml"
    selected = (
        {"proxy_pair", "proxy_nonzero_sret"} if os.name == "nt" else
        {"proxy_vector", "proxy_fast", "proxy_pair", "proxy_nonzero_sret"}
    )
    selected.add("proxy_fast_scalar")
    policy(config, "light", 2, sorted(selected))
    report = work / "coverage.json"
    protected = work / ("protected" + extension)
    protected_object = work / "protected.obj"
    artifact = protected_object if os.name == "nt" else protected
    compile_only = ["-c"] if os.name == "nt" else []
    run([args.wrapper, f"--obf-config={config}", *flags, *compile_only, source, "-o", str(artifact)], work,
        env={"OBF_COVERAGE_REPORT": str(report)})
    if os.name == "nt":
        run([args.clang, "-O2", "-fms-runtime-lib=dll", str(driver), str(protected_object),
             args.runtime, "-o", str(protected)], work)
    run([str(protected)], work)
    data = json.loads(report.read_text())
    emitted = {event["owner"] for event in data["emission"]
               if event["mechanism"] == "call_proxy" and event["status"] == "emitted"}
    if not selected.issubset(emitted):
        raise AssertionError(f"runtime checks lack emitted proxy coverage: {selected - emitted}")
    aggregate_input = "pointer" if os.name == "nt" else "byval"
    vectors = "raw-vector-control" if os.name == "nt" else "C/vector FastCC/vector"
    print(f"PASS native proxy {vectors} direct-aggregate nonzero-sret/{aggregate_input}")


if __name__ == "__main__":
    main()
