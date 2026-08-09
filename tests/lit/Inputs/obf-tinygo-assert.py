#!/usr/bin/env python3
"""Behavioral assertions for obf-bc and obf-tinygo lit drivers."""

from __future__ import annotations

import json
import os
import runpy
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path


def rows(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def output_argument(argv: list[str]) -> str:
    values: list[str] = []
    index = 0
    while index < len(argv):
        if argv[index] == "-o":
            values.append(argv[index + 1])
            index += 2
            continue
        if argv[index].startswith("-o="):
            values.append(argv[index].split("=", 1)[1])
        index += 1
    assert len(values) == 1, argv
    return values[0]


def require_elf(path: Path) -> None:
    assert path.read_bytes().startswith(b"\x7fELF"), path
    assert stat.S_IMODE(path.stat().st_mode) == 0o751, path

def require_mode(path: Path, expected: str) -> None:
    assert stat.S_IMODE(path.stat().st_mode) == int(expected, 8), path


def assert_clean(log: Path, temporary_root: Path | None = None) -> None:
    for row in rows(log):
        work = row.get("work")
        if work:
            assert not Path(str(work)).exists(), work
    if temporary_root is not None:
        assert not list(temporary_root.glob("obf-tinygo-*")), temporary_root


def assert_chain(record: dict[str, object], runtime: Path) -> None:
    protected = str(record["protected_bc"])
    lowered = str(record["llc_object"])
    llc_argv = [str(value) for value in record["llc_argv"]]
    relink_argv = [str(value) for value in record["relink_argv"]]
    assert protected in llc_argv, (protected, llc_argv)
    assert output_argument(llc_argv) == lowered, llc_argv
    assert f"-mcpu=" in " ".join(llc_argv), llc_argv
    assert f"-mattr=" in " ".join(llc_argv), llc_argv
    assert any(argument in {"-O0", "-O1", "-O2", "-O3"} for argument in llc_argv), llc_argv
    assert "-function-sections" in llc_argv, llc_argv
    assert "-data-sections" in llc_argv, llc_argv
    linker_name = Path(relink_argv[0]).name
    direct_linker = linker_name in {"ld.lld", "ld.lld-21"}
    zig_linker = linker_name == "zig" and relink_argv[1:2] == ["ld.lld"]
    assert direct_linker or zig_linker, relink_argv
    assert relink_argv.count("ld.lld") == (1 if zig_linker else 0), relink_argv
    object_index = relink_argv.index(lowered)
    assert relink_argv[object_index + 1] == str(runtime.resolve()), relink_argv


def assert_recorded_chain(log: Path, runtime: Path) -> None:
    prefix = "obf-tinygo: provenance "
    records = [
        json.loads(line[len(prefix) :])
        for line in log.read_text(encoding="utf-8").splitlines()
        if line.startswith(prefix)
    ]
    assert len(records) == 1, records
    assert_chain(records[0], runtime)


def assert_retained_work(log: Path, wrapper_log: Path, temporary_root: Path) -> None:
    works = {
        Path(str(row["work"]))
        for row in rows(log)
        if row.get("work")
    }
    output_lines = wrapper_log.read_text(encoding="utf-8").splitlines()
    obf_works = [Path(line.removeprefix("OBF_WORK=")) for line in output_lines if line.startswith("OBF_WORK=")]
    tinygo_work_paths = [
        Path(line.removeprefix("TINYGO_WORK="))
        for line in output_lines
        if line.startswith("TINYGO_WORK=")
    ]
    tinygo_works = set(tinygo_work_paths)
    assert len(works) == 2, works
    assert len(obf_works) == 1, obf_works
    assert len(tinygo_work_paths) == len(tinygo_works) == 2, tinygo_work_paths
    assert works == tinygo_works, (works, tinygo_works)
    assert obf_works[0].is_dir(), obf_works[0]
    assert obf_works[0].parent == temporary_root, (obf_works[0], temporary_root)
    assert stat.S_IMODE(obf_works[0].stat().st_mode) == 0o700, obf_works[0]
    for work in works:
        assert work.is_dir(), work
        shutil.rmtree(work)
    shutil.rmtree(obf_works[0])
    assert not list(temporary_root.glob("obf-tinygo-*")), temporary_root


def assert_provenance(log: Path, saved: Path, executable: Path, runtime: Path) -> None:
    by_role: dict[str, list[dict[str, object]]] = {}
    for row in rows(log):
        by_role.setdefault(str(row["role"]), []).append(row)
    builds = by_role["build"]
    assert len(builds) == 2
    build_argvs = [[str(value) for value in row["argv"]] for row in builds]
    build_outputs = [output_argument(argv) for argv in build_argvs]
    assert str(executable) not in build_outputs, build_outputs
    assert any(path.endswith(".bc") for path in build_outputs), build_outputs
    assert any(path.endswith("baseline.elf") for path in build_outputs), build_outputs
    retained = next(argv for argv in build_argvs if "-x" in argv)
    assert "-work" in retained, retained
    assert len(by_role["retained"]) == 1

    transform = by_role["transform"][-1]
    llc = by_role["llc"][-1]
    relink = by_role["relink"][-1]
    transform_argv = [str(value) for value in transform["argv"]]
    assert transform_argv[0] == "--obf-config", transform_argv
    pinned_config = Path(transform_argv[1])
    assert pinned_config.name.startswith("obf-tinygo-config-"), pinned_config
    assert not pinned_config.exists(), pinned_config
    llc_argv = [str(value) for value in llc["argv"]]
    relink_argv = [str(value) for value in relink["argv"]]
    protected = output_argument(transform_argv)
    lowered = output_argument(llc_argv)
    assert protected in llc_argv, (protected, llc_argv)
    object_index = relink_argv.index(lowered)
    assert relink_argv[object_index + 1] == str(runtime.resolve()), relink_argv
    relink_output = Path(output_argument(relink_argv))
    assert relink_output != executable
    assert relink_output.parent == executable.parent
    assert saved.read_bytes().endswith(b"FAKE-PROTECTED-BC\n")
    require_elf(executable)
    assert_clean(log)


def assert_wrapper_signal(
    wrapper: Path,
    config: Path,
    source: Path,
    output: Path,
    log: Path,
    temporary_root: Path,
    fake_tool: Path,
) -> None:
    temporary_root.mkdir(parents=True, exist_ok=True)
    log.unlink(missing_ok=True)
    output.write_text("preserved\n", encoding="utf-8")
    environment = os.environ.copy()
    environment.update(
        {
            "TMPDIR": str(temporary_root),
            "OBF_TINYGO_BIN": str(fake_tool),
            "OBF_BC_BIN": str(fake_tool),
            "OBF_LLC_BIN": str(fake_tool),
            "OBF_TINYGO_FAKE_MODE": "retained-pause",
            "OBF_TINYGO_FAKE_LOG": str(log),
        }
    )
    process = subprocess.Popen(
        [
            str(wrapper),
            f"--obf-config={config}",
            "build",
            "-scheduler=none",
            "-gc=conservative",
            "-o",
            str(output),
            str(source),
        ],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    retained_work: Path | None = None
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                raise AssertionError(
                    f"wrapper exited before signal: {process.returncode}\n{stdout}{stderr}"
                )
            if log.exists():
                retained = [row for row in rows(log) if row.get("role") == "retained"]
                if retained:
                    retained_work = Path(str(retained[-1]["work"]))
                    break
            time.sleep(0.01)
        assert retained_work is not None, "fake retained build did not start"

        process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == -signal.SIGTERM, (
            process.returncode,
            stdout,
            stderr,
        )
        assert output.read_text(encoding="utf-8") == "preserved\n"
        assert not retained_work.exists(), retained_work
        assert not list(temporary_root.glob("tinygo-fake-*")), temporary_root
        assert not list(temporary_root.glob("obf-tinygo-*")), temporary_root
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


def assert_obf_bc_signal_transaction(wrapper: Path, work: Path) -> None:
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    output = work / "output.bc"
    temporary = work / "temporary.bc"
    output.write_bytes(b"preserved output\n")
    temporary.write_bytes(b"replacement output\n")

    namespace = runpy.run_path(str(wrapper))
    signal_scope_type = namespace["_SignalScope"]
    interrupted_type = namespace["_Interrupted"]
    install_output = namespace["_install_output"]
    real_replace = os.replace
    queued = False

    def replace_with_pending_signal(source: object, destination: object) -> None:
        nonlocal queued
        if Path(source) == temporary and not queued:
            queued = True
            os.kill(os.getpid(), signal.SIGTERM)
        real_replace(source, destination)

    caught = False
    os.replace = replace_with_pending_signal
    try:
        with signal_scope_type() as signal_scope:
            try:
                install_output(temporary, output, signal_scope)
            except interrupted_type:
                caught = True
    finally:
        os.replace = real_replace

    assert queued and caught
    assert output.read_bytes() == b"preserved output\n"
    assert not list(work.glob(".obf-bc-*")), list(work.iterdir())


def main() -> int:
    command = sys.argv[1]
    if command == "clean":
        assert_clean(
            Path(sys.argv[2]), Path(sys.argv[3]) if len(sys.argv) == 4 else None
        )
    elif command == "provenance":
        assert_provenance(
            Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]), Path(sys.argv[5])
        )
    elif command == "chain":
        assert_recorded_chain(Path(sys.argv[2]), Path(sys.argv[3]))
    elif command == "work":
        assert_retained_work(Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]))
    elif command == "elf":
        require_elf(Path(sys.argv[2]))
    elif command == "save-mode":
        require_mode(Path(sys.argv[2]), sys.argv[3])
    elif command == "wrapper-signal":
        assert_wrapper_signal(
            Path(sys.argv[2]),
            Path(sys.argv[3]),
            Path(sys.argv[4]),
            Path(sys.argv[5]),
            Path(sys.argv[6]),
            Path(sys.argv[7]),
            Path(sys.argv[8]),
        )
    elif command == "obf-bc-signal":
        assert_obf_bc_signal_transaction(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        raise SystemExit(f"unknown assertion command: {command}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
