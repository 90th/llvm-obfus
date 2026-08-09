#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile


class BuildError(RuntimeError):
    pass


def run(argv: list[str], *, env: dict[str, str] | None = None, capture: bool = False) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        argv,
        check=False,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
        env=env,
    )
    if completed.returncode != 0:
        output = "" if completed.stdout is None else completed.stdout
        raise BuildError(f"command failed ({completed.returncode}): {' '.join(argv)}\n{output}")
    return completed


def parse_work_dir(output: str) -> pathlib.Path:
    matches = [line.removeprefix("WORK=").strip() for line in output.splitlines() if line.startswith("WORK=")]
    if len(matches) != 1:
        raise BuildError(f"expected one TinyGo WORK= line, got {len(matches)}")
    work = pathlib.Path(matches[0])
    if not work.is_absolute():
        raise BuildError(f"TinyGo WORK path is not absolute: {work}")
    if not work.is_dir():
        raise BuildError(f"TinyGo WORK path is missing: {work}")
    return work


def write_ll(opt: str, input_path: pathlib.Path, output_path: pathlib.Path) -> None:
    run([opt, "-S", str(input_path), "-o", str(output_path)])


def strip_binary(strip_tool: str, binary_path: pathlib.Path) -> None:
    run([strip_tool, "--strip-all", str(binary_path)])


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="build one TinyGo benchmark pair")
    parser.add_argument("--tinygo", required=True)
    parser.add_argument("--wrapper", required=True)
    parser.add_argument("--opt", required=True)
    parser.add_argument("--strip", required=True)
    parser.add_argument("--config", required=True, type=pathlib.Path)
    parser.add_argument("--source", required=True, type=pathlib.Path)
    parser.add_argument("--output-dir", required=True, type=pathlib.Path)
    parser.add_argument("--name", required=True)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    baseline_bin = output_dir / f"{args.name}.baseline"
    baseline_ll = output_dir / f"{args.name}.baseline.ll"
    obfuscated_bin = output_dir / f"{args.name}.obfuscated"
    obfuscated_ll = output_dir / f"{args.name}.obfuscated.ll"

    xdg_cache_home = output_dir / "tinygo-xdg-cache"
    xdg_cache_home.mkdir(parents=True, exist_ok=True)
    shared_env = os.environ.copy()
    shared_env["XDG_CACHE_HOME"] = str(xdg_cache_home)

    with tempfile.TemporaryDirectory(prefix=f"{args.name}.tinygo-build.", dir=output_dir) as scratch_name:
        scratch = pathlib.Path(scratch_name)
        baseline_bc = scratch / "baseline.bc"
        protected_bc = scratch / "protected.bc"

        baseline = run(
            [
                args.tinygo,
                "build",
                "-x",
                "-work",
                "-scheduler=none",
                "-gc=conservative",
                "-o",
                str(baseline_bin),
                str(args.source),
            ],
            env=shared_env,
            capture=True,
        )
        work_dir = parse_work_dir(baseline.stdout)
        try:
            main_bc = work_dir / "main.o"
            if not main_bc.is_file():
                raise BuildError(f"TinyGo retained main object is missing: {main_bc}")
            shutil.copyfile(main_bc, baseline_bc)
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)
        write_ll(args.opt, baseline_bc, baseline_ll)
        strip_binary(args.strip, baseline_bin)

        run(
            [
                args.wrapper,
                f"--obf-config={args.config}",
                f"--obf-save-bc={protected_bc}",
                "build",
                "-scheduler=none",
                "-gc=conservative",
                "-o",
                str(obfuscated_bin),
                str(args.source),
            ],
            env=shared_env,
        )
        if not protected_bc.is_file():
            raise BuildError(f"wrapper did not save protected bitcode: {protected_bc}")
        write_ll(args.opt, protected_bc, obfuscated_ll)
        strip_binary(args.strip, obfuscated_bin)

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except BuildError as error:
        print(f"build_tinygo_benchmark: {error}", file=sys.stderr)
        sys.exit(1)
