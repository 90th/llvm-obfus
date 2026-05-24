#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shutil
import statistics
import subprocess
import sys
import textwrap
import time
from dataclasses import asdict, dataclass


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
BENCH_LINE_RE = re.compile(r"^BENCH string_decode_overhead\s+(?P<fields>.+)$")


@dataclass(frozen=True)
class Variant:
    name: str
    prefer_lazy_decode: bool
    authenticated_mode: bool


@dataclass
class MetricSummary:
    samples: list[float]
    median: float
    mean: float
    minimum: float
    maximum: float


@dataclass
class VariantReport:
    name: str
    strings: int
    bytes: int
    cold_total_ns: MetricSummary
    steady_ns_per_iter: MetricSummary
    startup_wall_ns: MetricSummary


VARIANTS = (
    Variant("lazy_plain", prefer_lazy_decode=True, authenticated_mode=False),
    Variant("lazy_auth", prefer_lazy_decode=True, authenticated_mode=True),
    Variant("ctor_plain", prefer_lazy_decode=False, authenticated_mode=False),
    Variant("ctor_auth", prefer_lazy_decode=False, authenticated_mode=True),
)


def summarize(samples: list[float]) -> MetricSummary:
    if not samples:
        raise ValueError("cannot summarize an empty sample set")
    return MetricSummary(
        samples=samples,
        median=statistics.median(samples),
        mean=statistics.fmean(samples),
        minimum=min(samples),
        maximum=max(samples),
    )


def find_tool(explicit: str | None, env_name: str, fallback: str) -> str:
    if explicit:
        return explicit
    env_value = os.environ.get(env_name)
    if env_value:
        return env_value
    found = shutil.which(fallback)
    if found:
        return found
    raise FileNotFoundError(f"failed to locate tool '{fallback}'")


def find_plugin(build_dir: pathlib.Path) -> pathlib.Path:
    direct = build_dir / "obf_plugin.so"
    if direct.exists():
        return direct
    matches = sorted(build_dir.glob("obf_plugin.*"))
    if matches:
        return matches[0]
    raise FileNotFoundError(f"failed to locate obf_plugin in {build_dir}")


def run_command(command: list[str], *, cwd: pathlib.Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        check=True,
        text=True,
        capture_output=True,
    )


def write_text(path: pathlib.Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def generate_secret_text(index: int, length: int) -> str:
    prefix = f"secret-{index:03d}-"
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    body_len = max(length - len(prefix), 1)
    body = "".join(alphabet[(index * 13 + offset * 7) % len(alphabet)] for offset in range(body_len))
    return prefix + body


def render_benchmark_source(secret_count: int, secret_len: int, default_iters: int) -> str:
    declarations: list[str] = []
    batch_lines: list[str] = []
    total_bytes = 0

    for index in range(secret_count):
        text = generate_secret_text(index, secret_len)
        name = f"kSecret{index:03d}"
        declarations.append(f'static const char {name}[] = "{text}";')
        batch_lines.append(
            f"  acc ^= touch_secret({name}, sizeof({name}) - 1u, acc ^ UINT64_C({0x9E3779B97F4A7C15 + index}));"
        )
        total_bytes += len(text)

    declarations_block = "\n".join(declarations)
    batch_block = "\n".join(batch_lines)

    return textwrap.dedent(
        f"""
        #include <stdint.h>
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>
        #include <time.h>

        #if defined(__clang__) || defined(__GNUC__)
        #define OBF_NOINLINE __attribute__((noinline))
        #else
        #define OBF_NOINLINE
        #endif

        enum {{
          kSecretCount = {secret_count},
          kSecretBytes = {total_bytes},
          kDefaultIters = {default_iters}
        }};

        static uint64_t now_ns(void) {{
          struct timespec ts;
          timespec_get(&ts, TIME_UTC);
          return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
        }}

        static uint64_t get_env_u64(const char *name, uint64_t fallback) {{
          const char *text = getenv(name);
          if (text == NULL || *text == '\0') {{
            return fallback;
          }}
          return strtoull(text, NULL, 10);
        }}

        static int env_enabled(const char *name) {{
          const char *text = getenv(name);
          return text != NULL && *text != '\0' && strcmp(text, "0") != 0;
        }}

        {declarations_block}

        static OBF_NOINLINE uint64_t touch_secret(const char *text, size_t len, uint64_t salt) {{
          const volatile unsigned char *bytes = (const volatile unsigned char *)text;
          uint64_t state = salt ^ (uint64_t)bytes[0];
          state = (state * UINT64_C(0x517cc1b727220a95)) ^ (uint64_t)bytes[len >> 1];
          state = (state * UINT64_C(0x9e3779b97f4a7c15)) ^ (uint64_t)bytes[len - 1u];
          return state ^ (uint64_t)len;
        }}

        static OBF_NOINLINE uint64_t run_secret_batch(void) {{
          uint64_t acc = UINT64_C(0x123456789abcdef0);
        {batch_block}
          return acc;
        }}

        int main(void) {{
          if (env_enabled("OBF_BENCH_STARTUP_ONLY")) {{
            return 0;
          }}

          const uint64_t iters = get_env_u64("OBF_BENCH_ITERS", (uint64_t)kDefaultIters);
          volatile uint64_t sink = 0;

          const uint64_t cold_start_ns = now_ns();
          sink ^= run_secret_batch();
          const uint64_t cold_end_ns = now_ns();

          const uint64_t steady_start_ns = now_ns();
          for (uint64_t index = 0; index < iters; ++index) {{
            sink ^= run_secret_batch();
          }}
          const uint64_t steady_end_ns = now_ns();

          const uint64_t cold_total_ns = cold_end_ns - cold_start_ns;
          const uint64_t steady_total_ns = steady_end_ns - steady_start_ns;
          const double steady_ns_per_iter = (double)steady_total_ns / (double)iters;

          printf(
              "BENCH string_decode_overhead strings=%u bytes=%u cold_total_ns=%llu steady_total_ns=%llu steady_ns_per_iter=%.2f sink=%llu\\n",
              (unsigned)kSecretCount,
              (unsigned)kSecretBytes,
              (unsigned long long)cold_total_ns,
              (unsigned long long)steady_total_ns,
              steady_ns_per_iter,
              (unsigned long long)sink);
          return 0;
        }}
        """
    ).strip() + "\n"


def render_config(variant: Variant, secret_count: int) -> str:
    authenticated = "true" if variant.authenticated_mode else "false"
    prefer_lazy = "true" if variant.prefer_lazy_decode else "false"
    max_strings = max(secret_count * 2, 256)
    return textwrap.dedent(
        f"""
        seed: 424242
        default_level: none
        overrides:
          - name: run_secret_batch
            level: light
        string_encoding:
          min_string_length: 8
          max_strings_per_module: {max_strings}
          prefer_lazy_decode: {prefer_lazy}
          allow_ctor_fallback: true
          authenticated_mode: {authenticated}
        """
    ).strip() + "\n"


def parse_bench_output(stdout: str) -> dict[str, float]:
    for line in stdout.splitlines():
        match = BENCH_LINE_RE.match(line.strip())
        if not match:
            continue
        fields: dict[str, float] = {}
        for chunk in match.group("fields").split():
            key, raw_value = chunk.split("=", 1)
            if key in {"strings", "bytes", "cold_total_ns", "steady_total_ns"}:
                fields[key] = float(int(raw_value))
            elif key == "steady_ns_per_iter":
                fields[key] = float(raw_value)
        return fields
    raise ValueError(f"failed to parse benchmark output:\n{stdout}")


def build_variant_ir(
    *,
    clang: str,
    opt: str,
    plugin: pathlib.Path,
    baseline_ll: pathlib.Path,
    config_path: pathlib.Path,
    output_ll: pathlib.Path,
    seed: int,
) -> None:
    run_command(
        [
            opt,
            "-load-pass-plugin",
            str(plugin),
            f"--obf-config={config_path}",
            f"--obf-seed={seed}",
            "-passes=obf-string-encode,obf-cfg-state-cleanup",
            "-S",
            str(baseline_ll),
            "-o",
            str(output_ll),
        ]
    )


def build_binary(
    *,
    clang: str,
    input_ll: pathlib.Path,
    output_bin: pathlib.Path,
    extra_objects: list[pathlib.Path],
) -> None:
    command = [clang, "-O2", str(input_ll), *[str(path) for path in extra_objects], "-o", str(output_bin)]
    run_command(command)


def build_inputs(
    *,
    work_dir: pathlib.Path,
    clang: str,
    opt: str,
    plugin: pathlib.Path,
    entropy_anchor: pathlib.Path,
    string_auth_runtime: pathlib.Path,
    secret_count: int,
    secret_len: int,
    default_iters: int,
    seed: int,
) -> dict[str, pathlib.Path]:
    source_path = work_dir / "string_decode_overhead.c"
    baseline_ll = work_dir / "string_decode_overhead.baseline.ll"
    baseline_bin = work_dir / "baseline"

    write_text(source_path, render_benchmark_source(secret_count, secret_len, default_iters))
    run_command(
        [clang, "-std=c17", "-O2", "-fno-inline", "-S", "-emit-llvm", str(source_path), "-o", str(baseline_ll)]
    )
    build_binary(clang=clang, input_ll=baseline_ll, output_bin=baseline_bin, extra_objects=[])

    outputs = {"baseline": baseline_bin}
    for variant in VARIANTS:
        config_path = work_dir / f"{variant.name}.yaml"
        output_ll = work_dir / f"{variant.name}.ll"
        output_bin = work_dir / variant.name
        write_text(config_path, render_config(variant, secret_count))
        build_variant_ir(
            clang=clang,
            opt=opt,
            plugin=plugin,
            baseline_ll=baseline_ll,
            config_path=config_path,
            output_ll=output_ll,
            seed=seed,
        )
        build_binary(
            clang=clang,
            input_ll=output_ll,
            output_bin=output_bin,
            extra_objects=[entropy_anchor, string_auth_runtime],
        )
        outputs[variant.name] = output_bin
    return outputs


def measure_internal(binary: pathlib.Path, iterations: int, samples: int) -> tuple[int, int, MetricSummary, MetricSummary]:
    cold_samples: list[float] = []
    steady_samples: list[float] = []
    strings = 0
    byte_count = 0

    for _ in range(samples):
        env = os.environ.copy()
        env["OBF_BENCH_ITERS"] = str(iterations)
        completed = subprocess.run(
            [str(binary)],
            check=True,
            text=True,
            capture_output=True,
            env=env,
        )
        metrics = parse_bench_output(completed.stdout)
        strings = int(metrics["strings"])
        byte_count = int(metrics["bytes"])
        cold_samples.append(metrics["cold_total_ns"])
        steady_samples.append(metrics["steady_ns_per_iter"])

    return strings, byte_count, summarize(cold_samples), summarize(steady_samples)


def measure_startup(binary: pathlib.Path, samples: int) -> MetricSummary:
    startup_samples: list[float] = []
    env = os.environ.copy()
    env["OBF_BENCH_STARTUP_ONLY"] = "1"
    env.pop("OBF_BENCH_ITERS", None)

    for _ in range(samples):
        start = time.perf_counter_ns()
        subprocess.run(
            [str(binary)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            env=env,
        )
        stop = time.perf_counter_ns()
        startup_samples.append(float(stop - start))

    return summarize(startup_samples)


def format_ns(value: float) -> str:
    if value >= 1_000_000.0:
        return f"{value / 1_000_000.0:.2f} ms"
    if value >= 1_000.0:
        return f"{value / 1_000.0:.2f} us"
    return f"{value:.2f} ns"


def safe_delta(lhs: float, rhs: float) -> float:
    return lhs - rhs


def safe_ratio(lhs: float, rhs: float) -> float:
    if rhs == 0.0:
        return 0.0
    return lhs / rhs


def print_report(reports: dict[str, VariantReport]) -> None:
    baseline = reports["baseline"]
    lazy_plain = reports["lazy_plain"]
    lazy_auth = reports["lazy_auth"]
    ctor_plain = reports["ctor_plain"]
    ctor_auth = reports["ctor_auth"]

    print("String auth decode overhead benchmark")
    print(f"  strings: {baseline.strings}")
    print(f"  protected bytes per batch: {baseline.bytes}")
    print()
    print("Steady-state batch cost (median)")
    for report in (baseline, lazy_plain, lazy_auth, ctor_plain, ctor_auth):
        print(f"  {report.name:>10}: {format_ns(report.steady_ns_per_iter.median)}")
    print()
    print("Cold first batch cost (median)")
    for report in (baseline, lazy_plain, lazy_auth):
        print(f"  {report.name:>10}: {format_ns(report.cold_total_ns.median)}")
    print()
    print("Process startup wall time (median)")
    for report in (baseline, ctor_plain, ctor_auth):
        print(f"  {report.name:>10}: {format_ns(report.startup_wall_ns.median)}")
    print()

    lazy_auth_vs_plain_cold = safe_delta(lazy_auth.cold_total_ns.median, lazy_plain.cold_total_ns.median)
    lazy_auth_vs_plain_steady = safe_delta(lazy_auth.steady_ns_per_iter.median, lazy_plain.steady_ns_per_iter.median)
    ctor_auth_vs_plain_startup = safe_delta(ctor_auth.startup_wall_ns.median, ctor_plain.startup_wall_ns.median)
    ctor_auth_vs_plain_steady = safe_delta(ctor_auth.steady_ns_per_iter.median, ctor_plain.steady_ns_per_iter.median)

    print("Derived deltas")
    print(
        "  lazy auth cold decode vs lazy plain: "
        f"{format_ns(lazy_auth_vs_plain_cold)} total, "
        f"{format_ns(lazy_auth_vs_plain_cold / lazy_auth.strings)} per string"
    )
    print(
        "  lazy auth steady-state vs lazy plain: "
        f"{format_ns(lazy_auth_vs_plain_steady)} per batch, "
        f"{safe_ratio(lazy_auth.steady_ns_per_iter.median, lazy_plain.steady_ns_per_iter.median):.2f}x"
    )
    print(
        "  ctor auth startup vs ctor plain: "
        f"{format_ns(ctor_auth_vs_plain_startup)} per process, "
        f"{format_ns(ctor_auth_vs_plain_startup / ctor_auth.strings)} per string"
    )
    print(
        "  ctor auth steady-state vs ctor plain: "
        f"{format_ns(ctor_auth_vs_plain_steady)} per batch"
    )


def to_json_ready(reports: dict[str, VariantReport], args: argparse.Namespace, work_dir: pathlib.Path) -> dict[str, object]:
    return {
        "build_dir": str(args.build_dir),
        "work_dir": str(work_dir),
        "iterations": args.iterations,
        "samples": args.samples,
        "startup_samples": args.startup_samples,
        "string_count": args.strings,
        "string_length": args.string_length,
        "variants": {name: asdict(report) for name, report in reports.items()},
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Measure authenticated string decode overhead")
    parser.add_argument("--build-dir", type=pathlib.Path, default=REPO_ROOT / "build")
    parser.add_argument("--iterations", type=int, default=50000)
    parser.add_argument("--samples", type=int, default=7)
    parser.add_argument("--startup-samples", type=int, default=25)
    parser.add_argument("--strings", type=int, default=64)
    parser.add_argument("--string-length", type=int, default=48)
    parser.add_argument("--seed", type=int, default=424242)
    parser.add_argument("--clang")
    parser.add_argument("--opt")
    parser.add_argument("--json-out", type=pathlib.Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    build_dir = args.build_dir.resolve()
    plugin = find_plugin(build_dir)
    entropy_anchor = build_dir / "obf_entropy_anchor.o"
    string_auth_runtime = build_dir / "obf_string_auth_runtime.o"
    if not entropy_anchor.exists():
        raise FileNotFoundError(f"missing entropy anchor object: {entropy_anchor}")
    if not string_auth_runtime.exists():
        raise FileNotFoundError(f"missing string auth runtime object: {string_auth_runtime}")

    clang = find_tool(args.clang, "OBF_CLANG", "clang")
    opt = find_tool(args.opt, "OBF_OPT", "opt")

    work_dir = build_dir / "string-auth-bench"
    work_dir.mkdir(parents=True, exist_ok=True)

    binaries = build_inputs(
        work_dir=work_dir,
        clang=clang,
        opt=opt,
        plugin=plugin,
        entropy_anchor=entropy_anchor,
        string_auth_runtime=string_auth_runtime,
        secret_count=args.strings,
        secret_len=args.string_length,
        default_iters=args.iterations,
        seed=args.seed,
    )

    reports: dict[str, VariantReport] = {}
    for name, binary in binaries.items():
        strings, byte_count, cold_total_ns, steady_ns_per_iter = measure_internal(
            binary, args.iterations, args.samples
        )
        startup_wall_ns = measure_startup(binary, args.startup_samples)
        reports[name] = VariantReport(
            name=name,
            strings=strings,
            bytes=byte_count,
            cold_total_ns=cold_total_ns,
            steady_ns_per_iter=steady_ns_per_iter,
            startup_wall_ns=startup_wall_ns,
        )

    print_report(reports)

    if args.json_out:
        write_text(args.json_out, json.dumps(to_json_ready(reports, args, work_dir), indent=2) + "\n")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as error:
        sys.stderr.write(error.stdout)
        sys.stderr.write(error.stderr)
        raise
