#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import pathlib
import re
import subprocess
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class BenchmarkSpec:
    name: str
    argv: tuple[str, ...]


CORE_BENCHMARKS = (
    "license_demo",
    "config_demo",
    "vm_workflow_demo",
    "wpo_demo",
)

SPECS = {
    "license_demo": BenchmarkSpec("license_demo", ("delta-7",)),
    "config_demo": BenchmarkSpec("config_demo", ("safe",)),
    "vm_workflow_demo": BenchmarkSpec("vm_workflow_demo", ("guest-path",)),
    "wpo_demo": BenchmarkSpec("wpo_demo", ("fusion",)),
    "rust_demo": BenchmarkSpec("rust_demo", ("7",)),
    "zig_demo": BenchmarkSpec("zig_demo", ()),
    "tinygo_demo": BenchmarkSpec("tinygo_demo", ()),
}


class CheckError(RuntimeError):
    pass


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="run corpus benchmark baseline/obfuscated pairs")
    parser.add_argument("--benchmarks-dir", required=True, type=pathlib.Path)
    parser.add_argument("--runtime-prefix", required=True)
    parser.add_argument("--iterations", type=int, default=4096)
    parser.add_argument(
        "--benchmarks",
        default=",".join(CORE_BENCHMARKS),
        help="comma-separated benchmark names",
    )
    return parser.parse_args(argv)


def parse_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def require_file(path: pathlib.Path) -> None:
    if not path.is_file():
        raise CheckError(f"missing file: {path}")


def run_binary(path: pathlib.Path, argv: tuple[str, ...], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(path), *argv],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )


def parse_bench_line(name: str, text: str) -> tuple[int, int]:
    match = re.fullmatch(rf"BENCH {re.escape(name)} ns/op=(\d+(?:\.\d+)?) sink=(\d+)\n?", text)
    if match is None:
        raise CheckError(f"unexpected benchmark line for {name}: {text!r}")
    ns_per_iter = int(float(match.group(1)))
    sink = int(match.group(2))
    if ns_per_iter <= 0:
        raise CheckError(f"non-positive ns/op for {name}: {ns_per_iter}")
    return ns_per_iter, sink


def has_runtime_abi_marker(ir_text: str, runtime_prefix: str) -> bool:
    return re.search(
        rf"@{re.escape(runtime_prefix)}(?:ea|ep[0-4]|sd3|cpd3)\b",
        ir_text,
    ) is not None


def check_pair(benchmarks_dir: pathlib.Path, runtime_prefix: str, iterations: int, spec: BenchmarkSpec) -> None:
    output_dir = benchmarks_dir / spec.name
    baseline_ll = output_dir / f"{spec.name}.baseline.ll"
    obfuscated_ll = output_dir / f"{spec.name}.obfuscated.ll"
    baseline_bin = output_dir / f"{spec.name}.baseline"
    obfuscated_bin = output_dir / f"{spec.name}.obfuscated"

    for path in (baseline_ll, obfuscated_ll, baseline_bin, obfuscated_bin):
        require_file(path)

    baseline_ir = baseline_ll.read_text(encoding="utf-8")
    obfuscated_ir = obfuscated_ll.read_text(encoding="utf-8")
    if has_runtime_abi_marker(baseline_ir, runtime_prefix):
        raise CheckError(f"baseline IR unexpectedly contains runtime marker for {spec.name}")
    if not has_runtime_abi_marker(obfuscated_ir, runtime_prefix):
        raise CheckError(f"obfuscated IR is missing runtime marker for {spec.name}")
    if baseline_ir == obfuscated_ir:
        raise CheckError(f"baseline and obfuscated IR are identical for {spec.name}")

    default_env = os.environ.copy()
    default_env.pop("OBF_BENCH_ITERS", None)
    baseline = run_binary(baseline_bin, spec.argv, env=default_env)
    obfuscated = run_binary(obfuscated_bin, spec.argv, env=default_env)
    if (baseline.returncode, baseline.stdout, baseline.stderr) != (
        obfuscated.returncode,
        obfuscated.stdout,
        obfuscated.stderr,
    ):
        raise CheckError(
            f"behavior mismatch for {spec.name}: baseline rc/stdout/stderr "
            f"{(baseline.returncode, baseline.stdout, baseline.stderr)!r} != "
            f"{(obfuscated.returncode, obfuscated.stdout, obfuscated.stderr)!r}"
        )

    bench_env = os.environ.copy()
    bench_env["OBF_BENCH_ITERS"] = str(iterations)
    baseline_bench = run_binary(baseline_bin, spec.argv, env=bench_env)
    obfuscated_bench = run_binary(obfuscated_bin, spec.argv, env=bench_env)
    if baseline_bench.returncode != 0 or obfuscated_bench.returncode != 0:
        raise CheckError(
            f"benchmark mode failed for {spec.name}: baseline rc={baseline_bench.returncode}, "
            f"obfuscated rc={obfuscated_bench.returncode}"
        )
    _, baseline_sink = parse_bench_line(spec.name, baseline_bench.stdout)
    _, obfuscated_sink = parse_bench_line(spec.name, obfuscated_bench.stdout)
    if baseline_sink != obfuscated_sink:
        raise CheckError(
            f"benchmark sink mismatch for {spec.name}: baseline={baseline_sink}, obfuscated={obfuscated_sink}"
        )
    if baseline_bench.stderr != obfuscated_bench.stderr:
        raise CheckError(f"benchmark stderr mismatch for {spec.name}")

    print(f"[ok] {spec.name}: default rc={baseline.returncode}, bench sink={baseline_sink}")


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    failures: list[str] = []
    for name in parse_csv(args.benchmarks):
        spec = SPECS.get(name)
        if spec is None:
            failures.append(f"unknown benchmark: {name}")
            continue
        try:
            check_pair(args.benchmarks_dir, args.runtime_prefix, args.iterations, spec)
        except CheckError as error:
            failures.append(str(error))

    if failures:
        for failure in failures:
            print(f"[fail] {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
