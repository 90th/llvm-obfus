"""Check C++ initialization, destruction, and actual ELF unload/reload transitions."""

import argparse
import copy
import json
import os
from pathlib import Path
import platform
import struct
import tempfile

from report_contract import coverage_contract
from self_checksum_elf_packaging import record_identity, sections
from vm_incoming_abi import run_process

FIXTURES = Path(__file__).resolve().parent
CXX_FLAGS = ("-std=c++17", "-fexceptions", "-fcxx-exceptions", "-fno-inline")
MODES = ("joined", "tls", "nodelete")
EH_OWNERS = ("lifetime_local_initialize", "lifetime_touch")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def semantic_outcomes(observations):
    result = copy.deepcopy(observations)
    for outcome in result.values():
        for generation in outcome["generations"]:
            # Loaders can release TLS-held mappings at different times. Each host
            # still requires final unmapping before the next true generation.
            generation["mappings"].pop("after_thread_exit", None)
    return result


def retention_metadata(image):
    data = image.read_bytes()
    unique = 0
    nodelete = False
    for section in sections(data).values():
        kind, offset, size, stride = section[1], section[4], section[5], section[9]
        if kind == 11:  # SHT_DYNSYM
            require(stride == 24 and size % stride == 0, "invalid dynamic symbol table")
            unique += sum(data[pos + 4] >> 4 == 10
                          for pos in range(offset, offset + size, stride))
        if kind == 6:  # SHT_DYNAMIC
            require(stride == 16 and size % stride == 0, "invalid dynamic table")
            for pos in range(offset, offset + size, stride):
                tag, value = struct.unpack_from("<qQ", data, pos)
                if tag == 0x6FFFFFFB:  # DT_FLAGS_1
                    nodelete |= bool(value & 0x8)  # DF_1_NODELETE
    require(unique == 0 and not nodelete,
            "ordinary fixture has non-TLS loader retention: GNU_UNIQUE or DF_1_NODELETE")
    return {"gnu_unique_symbols": unique, "df_1_nodelete": nodelete}


def policy(path, level):
    lines = ["seed: 8675309", "default_level: none", "targets:",
             "  - match: lifetime_vm", f"    level: {level}"]
    for owner in ("lifetime_text", "lifetime_step"):
        lines += [f"  - match: {owner}", "    level: strong"]
    # Exact target rules preserve frontend EH exclusions, as in cpp_elf_unwind.
    for owner in EH_OWNERS:
        lines += [f"  - match: {owner}", f"    level: {level}"]
    lines += ["vm:", "  max_mba_depth: 0", "string_encoding:",
              "  authenticated_mode: true", "  prefer_lazy_decode: true",
              "  allow_ctor_fallback: true", "  enable_ephemeral_slots: false",
              "self_checksum:", "  enabled: true", "  window_size: 16",
              "  max_sites: 1", "  seed: 991827", "security:",
              "  fail_on_public_obf_symbol: true"]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def check_report(path, level):
    report = coverage_contract(json.loads(path.read_text(encoding="utf-8")))
    require(report["capture"] == "enabled", "compiler ledger not captured")

    def emitted(owner, mechanism):
        return [event for event in report["emission"]
                if event["owner"] == owner and event["mechanism"] == mechanism
                and event["status"] == "emitted"]

    selected = [event["policy"] for event in report["requested_policy"]
                if event["owner"] == "lifetime_vm" and event["phase"] == "selected"]
    require(len(selected) == 1 and selected[0]["allow_vm"] and selected[0]["level"] == level,
            "VM leaf lost requested policy")
    require(any(event["scope"] == "whole_function" for event in emitted("lifetime_vm", "vm")),
            "lifecycle arithmetic leaf did not emit whole-function VM")
    require(any(event["count"] > 0 for event in emitted("lifetime_text", "string_encoding")),
            "lifecycle text did not emit authenticated encoding")
    require(any(event["count"] > 0 for event in emitted("lifetime_step", "self_checksum")),
            "lifecycle effect helper has no checksum sites")
    require(any(role["owner"] == "lifetime_text" and role["role"] == "string_decoder"
                and "authenticated_string_decode" in role["obligations"]
                for role in report["roles"]), "text helper lacks authenticated decoder")
    for owner in EH_OWNERS:
        choices = [event["policy"] for event in report["requested_policy"]
                   if event["owner"] == owner and event["phase"] == "selected"]
        require(len(choices) == 1 and not choices[0]["allow_vm"] and not emitted(owner, "vm"),
                f"local EH owner lost its native fallback: {owner}")
    require(any(event["mechanism"] == "security_gates" and event["status"] == "validated"
                for event in report["finalization"]), "security gates did not validate")
    return {"vm_leaf": "whole_function", "authenticated_text": True,
            "checksum_sites": sum(event["count"] for event in emitted("lifetime_step", "self_checksum")),
            "native_eh": list(EH_OWNERS)}


class Harness:
    def __init__(self, args):
        self.args = args
        args.work.mkdir(parents=True, exist_ok=True)
        self.work = Path(tempfile.mkdtemp(prefix="cpp-elf-lifetime-", dir=args.work)).resolve()
        self.raw = [args.clang, "--driver-mode=g++"]
        self.result = {"status": "running", "work": str(self.work), "rows": [],
                       "scope": "Linux x86-64 glibc native C++ shared-library lifetime"}
        self.save()
        print(f"CPP_ELF_LIFETIME_WORK {self.work}", flush=True)

    def save(self):
        (self.work / "result.json").write_text(json.dumps(self.result, indent=2) + "\n", encoding="utf-8")

    def run(self, command, *, report=None, native=False):
        command = [str(item) for item in command]
        environment = {key: value for key, value in os.environ.items()
                       if not key.upper().startswith("OBF_") and key not in
                       {"LD_PRELOAD", "LD_AUDIT", "LD_DEBUG", "LD_DEBUG_OUTPUT", "LD_LIBRARY_PATH"}}
        if report is not None:
            environment["OBF_COVERAGE_REPORT"] = str(report)
        try:
            result = run_process(command, cwd=self.work, env=environment,
                                 timeout=30 if native else 300)
        except Exception as error:
            with (self.work / "commands.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps({"command": command, "error": str(error)}) + "\n")
            raise
        with (self.work / "commands.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"command": command, "exit": result.returncode,
                                     "stdout": result.stdout, "stderr": result.stderr}) + "\n")
        require(result.returncode == 0,
                f"unexpected exit {result.returncode}: {command!r}\n{result.stdout}\n{result.stderr}")
        return result

    def native(self, host, image):
        observations = {}
        for mode in MODES:
            result = json.loads(self.run([host, image, mode], native=True).stdout)
            require(result.get("ok") is True and result.get("mode") == mode,
                    f"missing native lifetime checks: {result}")
            observations[mode] = result
        return observations

    def build(self, optimization, level=None):
        folder = self.work / f"o{optimization}-{level or 'raw'}"
        folder.mkdir()
        flags = [*CXX_FLAGS, f"-O{optimization}"]
        host = self.work / f"host-o{optimization}"
        if not host.exists():
            self.run([*self.raw, *flags, "-fuse-ld=lld", FIXTURES / "cpp-elf-lifetime-host.cpp",
                      "-rdynamic", "-pthread", "-ldl", "-o", host])
        obj = folder / "library.o"
        image = folder / "library.so"
        report = folder / "coverage.json" if level else None
        if level:
            config = folder / "policy.yaml"
            policy(config, level)
            driver = [self.args.wrapper, f"--obf-config={config}"]
            self.run([*driver, *flags, "-fPIC", "-c", FIXTURES / "cpp-elf-lifetime-library.cpp",
                      "-o", obj], report=report)
            compiler = check_report(report, level)
            objects = [obj]
        else:
            driver = self.raw
            self.run([*driver, *flags, "-fPIC", "-DRAW_CONTROL", "-c",
                      FIXTURES / "cpp-elf-lifetime-library.cpp", "-o", obj])
            oracle = folder / "oracle.o"
            self.run([*self.raw, *flags, "-fPIC", "-c", FIXTURES / "cpp-elf-lifetime-oracle.cpp",
                      "-o", oracle])
            objects = [obj, oracle]
            compiler = {"independent_oracle": True}
        self.run([*driver, *flags, "-shared", "-fuse-ld=lld", *objects, "-o", image])
        metadata = retention_metadata(image)
        checksum_records = 0
        if level:
            found, _ = record_identity(image.read_bytes(), 3)
            checksum_records = len(found)
            self.run([self.args.binder, image])
        observed = self.native(host, image)
        row = {"optimization": optimization, "level": level or "raw", "host": str(host),
               "image": str(image), "compiler_report": str(report) if report else None,
               "compiler": compiler, "retention_metadata": metadata,
               "bound_records": checksum_records, "native": observed}
        self.result["rows"].append(row)
        self.save()
        return observed

    def matrix(self):
        for optimization in self.args.optimization:
            baseline = self.build(optimization)
            for level in self.args.level:
                observed = self.build(optimization, level)
                require(semantic_outcomes(observed) == semantic_outcomes(baseline),
                        f"protected lifecycle outcomes differ from independent raw control: O{optimization} {level}")
                print(f"CPP_ELF_LIFETIME_PASS O{optimization} {level} joined tls nodelete", flush=True)
        self.result["status"] = "passed"
        self.save()
        print(f"CPP_ELF_LIFETIME_COMPLETE result={self.work / 'result.json'}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("wrapper", "clang", "binder"):
        parser.add_argument(f"--{option}", required=True)
    parser.add_argument("--work", type=Path, default=Path(tempfile.gettempdir()))
    parser.add_argument("--optimization", type=int, choices=(0, 2), action="append")
    parser.add_argument("--level", choices=("vm", "strong_vm"), action="append")
    args = parser.parse_args()
    require(platform.system() == "Linux" and platform.machine().lower() in ("x86_64", "amd64"),
            "native Linux x86-64 required")
    args.optimization = args.optimization or [0, 2]
    args.level = args.level or ["vm", "strong_vm"]
    harness = Harness(args)
    try:
        harness.matrix()
    except Exception as error:
        harness.result.update(status="failed", error=str(error))
        harness.save()
        raise


if __name__ == "__main__":
    main()
