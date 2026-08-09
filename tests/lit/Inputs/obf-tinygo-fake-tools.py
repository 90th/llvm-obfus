#!/usr/bin/env python3
"""Table-driven fake TinyGo, obf-bc, and llc for wrapper contract tests."""

from __future__ import annotations

import json
import os
import platform
import shlex
import signal
import struct
import sys
import tempfile
from pathlib import Path


MODE = os.environ.get("OBF_TINYGO_FAKE_MODE", "ok")
LOG = os.environ.get("OBF_TINYGO_FAKE_LOG")


CASES = {
    "ok": {},
    "configured-lld": {"unqualified_linker": True},
    "bad-lld-tuple": {"unqualified_linker": True},
    "bad-captured-lld-tuple": {},
    "retained-pause": {"retained_pause": True},
    "direct-cgo": {},
    "duplicate-work": {"work_count": 2},
    "duplicate-link": {"link_count": 2},
    "response": {"link_extra": ["@response.rsp"]},
    "group": {"link_extra": ["--start-group"]},
    "library-before-main": {"before_main": ["pre-main.a"]},
    "duplicate-runtime": {"link_extra": ["/tmp/libobf_runtime.a"]},
    "duplicate-output": {},
    "duplicate-main": {},
    "duplicate-mcpu": {"link_extra": ["-mllvm", "-mcpu=generic"]},
    "duplicate-mattr": {"link_extra": ["-mllvm", "-mattr=+sse2"]},
    "empty-mcpu": {"mcpu": "-mcpu="},
    "empty-mattr": {"mattr": "-mattr="},
    "duplicate-lto": {"link_extra": ["--lto-O1"]},
    "bad-code-model": {"link_extra": ["-mllvm", "-code-model=not-a-model"]},
    "lower-non-elf": {"lower_non_elf": True},
    "relink-non-elf": {"relink_non_elf": True},
    "target-closure": {"link_extra": ["--target=x86_64-unknown-linux-gnu"]},
    "non-elf-closure": {"baseline_non_elf": True},
    "shared-output": {"link_extra": ["-shared"]},
    "pie-output": {"link_extra": ["-pie"]},
    "shared-alias-output": {"link_extra": ["-Bshareable"]},
    "shared-long-alias-output": {"link_extra": ["--Bshareable"]},
    "pic-output": {"link_extra": ["--pic-executable"]},
    "transform-fail": {"transform_status": 41},
    "lower-fail": {"lower_status": 42},
    "relink-fail": {"relink_status": 43},
    "transform-signal": {"transform_signal": signal.SIGTERM},
    "lower-signal": {"lower_signal": signal.SIGTERM},
    "relink-signal": {"relink_signal": signal.SIGTERM},
}


def case() -> dict[str, object]:
    try:
        return CASES[MODE]
    except KeyError:
        raise SystemExit(f"unknown fake TinyGo mode: {MODE}")


def record(role: str, argv: list[str], **extra: object) -> None:
    if not LOG:
        return
    row = {"role": role, "argv": argv, **extra}
    with Path(LOG).open("a", encoding="utf-8") as file:
        file.write(json.dumps(row, sort_keys=True) + "\n")


def elf_bytes(elf_type: int) -> bytes:
    machine_name = platform.machine().lower()
    machine, elf_class = {
        "x86_64": (62, 2),
        "amd64": (62, 2),
        "aarch64": (183, 2),
        "arm64": (183, 2),
        "armv5": (40, 1),
        "armv5l": (40, 1),
        "armv5tel": (40, 1),
        "armv7l": (40, 1),
        "armv6l": (40, 1),
        "arm": (40, 1),
        "armv6": (40, 1),
        "armv7": (40, 1),
        "armv8": (40, 1),
        "armv8l": (40, 1),
    }.get(machine_name, (62, 2))
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4] = elf_class
    header[5] = 1
    header[6] = 1
    struct.pack_into("<H", header, 16, elf_type)
    struct.pack_into("<H", header, 18, machine)
    return bytes(header)


def write_elf(path: str, elf_type: int) -> None:
    destination = Path(path)
    existed = destination.exists()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(elf_bytes(elf_type))
    if elf_type in {2, 3} and not existed:
        destination.chmod(0o751)


def tinygo_work_dir() -> Path:
    return Path(
        tempfile.mkdtemp(
            prefix="tinygo-fake-",
            dir=os.environ.get("TMPDIR") or "/tmp",
        )
    )


def output_path(argv: list[str]) -> str:
    matches: list[str] = []
    index = 0
    while index < len(argv):
        argument = argv[index]
        if argument == "-o":
            if index + 1 >= len(argv):
                raise SystemExit("fake tool received -o without a path")
            matches.append(argv[index + 1])
            index += 2
            continue
        if argument.startswith("-o="):
            matches.append(argument.split("=", 1)[1])
        index += 1
    if len(matches) != 1:
        raise SystemExit(f"fake tool expected one -o, got {matches!r}")
    return matches[0]


def list_packages(_argv: list[str]) -> int:
    print("go: downloading example.invalid/dependency v0.0.0", file=sys.stderr)
    packages: list[dict[str, object]] = [
        {
            "Dir": "/fake/dependency",
            "ImportPath": "example/dependency",
            "GoFiles": ["dependency.go"],
        },
        {
            "Dir": "/fake/main",
            "ImportPath": "command-line-arguments",
            "GoFiles": ["main.go"],
        },
    ]
    if MODE == "dependency-cgo":
        packages[0]["CgoFiles"] = ["dependency.go"]
        packages[0]["Imports"] = ["C"]
    elif MODE == "direct-cgo":
        packages[1]["CgoFiles"] = ["main.go"]
        packages[1]["Imports"] = ["C"]
    for package in packages:
        print(json.dumps(package, sort_keys=True))
    return 0


def build(argv: list[str]) -> int:
    output = output_path(argv)
    if output.endswith(".bc"):
        if MODE == "build-fail":
            record("build", argv)
            return 40
        work: Path | None = None
        if "-work" in argv:
            work = tinygo_work_dir()
            print(f"WORK={work}", file=sys.stderr)
        record("build", argv, **({} if work is None else {"work": str(work)}))
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        Path(output).write_bytes(b"BC\xc0\xdeFAKE-WHOLE-PROGRAM")
        return 0

    record("build", argv)
    configuration = case()
    work = tinygo_work_dir()
    main = work / "main.o"
    linker = work / "ld.lld"
    linker.symlink_to(Path(__file__).resolve())
    main.write_bytes(b"BC\xc0\xdeFAKE-RETAINED-MAIN")
    if configuration.get("baseline_non_elf"):
        Path(output).write_bytes(b"not an ELF executable")
    else:
        write_elf(output, 2)

    command = [
        "ld.lld" if configuration.get("unqualified_linker") else str(linker),
        "--gc-sections",
        "-L",
        str(work),
        "-o",
        str(work / "main"),
        *configuration.get("before_main", []),
        str(main),
        "compiler-rt/lib.a",
        "-mllvm",
        str(configuration.get("mcpu", "-mcpu=x86-64")),
        "-mllvm",
        str(configuration.get("mattr", "-mattr=+cmov,+sse2")),
        "--lto-O2",
        "--thinlto-cache-dir=" + str(work / "thinlto"),
        "-mllvm",
        "--rotation-max-header-size=0",
        *configuration.get("link_extra", []),
    ]
    if MODE == "duplicate-main":
        command.insert(command.index(str(main)) + 1, str(main))
    if MODE == "duplicate-output":
        command.extend(["-o", str(work / "second-output")])

    for _ in range(int(configuration.get("work_count", 1))):
        print(f"WORK={work}", file=sys.stderr)
    line = shlex.join(command)
    for _ in range(int(configuration.get("link_count", 1))):
        print(line, file=sys.stderr)
    print("ld.lld: warning: synthetic retained-link diagnostic", file=sys.stderr)
    record("retained", command, work=str(work), baseline=output)
    if configuration.get("retained_pause"):
        signal.pause()
    return 0


def transform(argv: list[str]) -> int:
    record("transform", argv)
    configuration = case()
    if "transform_signal" in configuration:
        os.kill(os.getpid(), int(configuration["transform_signal"]))
    if "transform_status" in configuration:
        return int(configuration["transform_status"])
    output = output_path(argv)
    input_bc = next(argument for argument in argv if argument.endswith(".bc") and argument != output)
    Path(output).write_bytes(Path(input_bc).read_bytes() + b"\nFAKE-PROTECTED-BC\n")
    return 0


def lower(argv: list[str]) -> int:
    record("llc", argv)
    configuration = case()
    if "lower_signal" in configuration:
        os.kill(os.getpid(), int(configuration["lower_signal"]))
    if "lower_status" in configuration:
        return int(configuration["lower_status"])
    if configuration.get("lower_non_elf"):
        Path(output_path(argv)).write_bytes(b"not an ELF object")
    else:
        write_elf(output_path(argv), 1)
    return 0


def relink(argv: list[str]) -> int:
    record("relink", argv)
    configuration = case()
    if "relink_signal" in configuration:
        os.kill(os.getpid(), int(configuration["relink_signal"]))
    if "relink_status" in configuration:
        return int(configuration["relink_status"])
    if configuration.get("relink_non_elf"):
        Path(output_path(argv)).write_bytes(b"not an ELF executable")
    else:
        write_elf(output_path(argv), 2)
    return 0


def main() -> int:
    argv = sys.argv[1:]
    if Path(sys.argv[0]).name == "ld.lld":
        if argv == ["--version"]:
            print("LLD 20.1.8" if MODE == "bad-captured-lld-tuple" else "LLD 21.1.8")
            return 0
        return relink(argv)
    if argv == ["fake-lld", "--version"]:
        print("LLD 20.1.8" if MODE == "bad-lld-tuple" else "LLD 21.1.8")
        return 0
    if argv and argv[0] == "fake-lld":
        return relink(argv[1:])
    if argv == ["version"]:
        if MODE == "bad-tinygo-tuple":
            print("tinygo version 0.40.9 linux/amd64 (using go version go1.24.0 and LLVM version 20.1.8)")
        elif MODE == "bad-go-tuple":
            print("tinygo version 0.41.1 linux/amd64 (using go version go1.27.0 and LLVM version 20.1.8)")
        else:
            print("tinygo version 0.41.1 linux/amd64 (using go version go1.24.0 and LLVM version 20.1.8)")
        return 0
    if argv == ["--version"]:
        print("LLVM version 20.1.8" if MODE == "bad-llc-tuple" else "LLVM version 21.1.8")
        return 0
    if not argv:
        raise SystemExit("fake tool requires a role")
    if argv[0] == "list":
        return list_packages(argv)
    if argv[0] == "build":
        return build(argv)
    if argv[0] == "ld.lld":
        raise AssertionError("wrapper invoked ld.lld as a TinyGo subcommand")
    if argv[0] == "--obf-config" or argv[0].startswith("--obf-config="):
        return transform(argv)
    return lower(argv)


if __name__ == "__main__":
    raise SystemExit(main())
