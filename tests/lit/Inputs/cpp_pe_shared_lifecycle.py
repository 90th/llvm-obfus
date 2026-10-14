"""Check native Windows x64 C++ DLL lifetime, cleanup, and real unload/reload."""

import argparse
import copy
import json
import os
from pathlib import Path
import platform
import struct
import sys
import tempfile

from cpp_dll_abi import CXX_FLAGS
from report_contract import coverage_contract
from self_checksum_pe_tool import (
    MAGIC, RECORD_SIZE, OFF_FLAGS, OFF_FORMAT, OFF_DELTA, OFF_TARGET_KIND,
    OFF_SAMPLE_SIZE, OFF_SEED, OFF_EXPECTED, FORMAT_PE, TARGET_REL32,
    checksum, map_exec, parse as checksum_sections,
)
from vm_incoming_abi import run_process

FIXTURES = Path(__file__).resolve().parent
MODES = ("runtime", "tls", "fls", "worker", "termination", "failed_attach")
EH_OWNERS = ("lifetime_touch", "lifetime_seh")
EXPORTS = {
    "lifetime_touch", "lifetime_snapshot", "lifetime_fls_enter",
    "lifetime_fls_leave", "lifetime_shutdown", "lifetime_seh", "lifetime_worker",
}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def semantic_outcomes(observations):
    result = copy.deepcopy(observations)
    for outcome in result.values():
        for generation in outcome["generations"]:
            # Each native host checks exact thread ownership, including skipped
            # dormant-worker TLS at ExitProcess. Only OS-assigned IDs vary.
            for event in generation["events"]:
                event.pop("thread")
    return result


def policy(path, level):
    lines = ["seed: 8675309", "default_level: none", "targets:",
             "  - match: lifetime_vm", f"    level: {level}"]
    for owner in ("lifetime_text", "lifetime_step"):
        lines += [f"  - match: {owner}", "    level: strong"]
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
    require(path.is_file(), f"missing compiler ledger: {path}")
    report = coverage_contract(json.loads(path.read_text(encoding="utf-8")))
    require(report["capture"] == "enabled", "compiler ledger not captured")

    def selected(owner):
        choices = [event["policy"] for event in report["requested_policy"]
                   if event["owner"] == owner and event["phase"] == "selected"]
        require(len(choices) == 1, f"missing/ambiguous selected policy: {owner}")
        return choices[0]

    def emitted(owner, mechanism):
        return [event for event in report["emission"]
                if event["owner"] == owner and event["mechanism"] == mechanism
                and event["status"] == "emitted"]

    choice = selected("lifetime_vm")
    require(choice["allow_vm"] and choice["level"] == level,
            "lifecycle arithmetic leaf lost requested VM policy")
    require(any(event["owner"] == "lifetime_vm" and event["mechanism"] == "vm"
                and event["status"] == "admitted" and event["scope"] == "whole_function"
                for event in report["admission"]), "VM leaf was not admitted whole-function")
    require(any(event["scope"] == "whole_function"
                for event in emitted("lifetime_vm", "vm")),
            "lifecycle arithmetic leaf did not emit whole-function VM")
    for owner in ("lifetime_text", "lifetime_step"):
        require(selected(owner)["level"] == "strong", f"lost strong helper policy: {owner}")
    require(any(event["count"] > 0 for event in emitted("lifetime_text", "string_encoding")),
            "lifecycle text did not emit authenticated encoding")
    require(any(event["count"] > 0 for event in emitted("lifetime_step", "self_checksum")),
            "lifecycle effect helper has no checksum sites")
    require(any(role["owner"] == "lifetime_text" and role["role"] == "string_decoder"
                and "authenticated_string_decode" in role["obligations"]
                for role in report["roles"]), "text helper lacks authenticated decoder obligation")
    for owner in EH_OWNERS:
        choice = selected(owner)
        require(choice["level"] == "light" and not choice["allow_vm"] and
                choice["allow_constant_encoding"] and choice["allow_self_checksum"] and
                not emitted(owner, "vm"),
                f"local EH/SEH owner lost protected native fallback: {owner}")
        require(choice["source"] == "config_rule" and owner in choice["detail"] and
                f"risky features downgraded {level} to light" in choice["detail"],
                f"native fallback lost exact target policy identity: {owner}")
        require(any(event["count"] > 0 for event in emitted(owner, "constant_encoding")),
                f"native EH/SEH constants have no protection: {owner}")
        require(any(event["count"] > 0 for event in emitted(owner, "self_checksum")),
                f"native EH/SEH owner has no checksum sites: {owner}")
    require(any(event["mechanism"] == "security_gates" and event["status"] == "validated"
                for event in report["finalization"]), "compiler security gates did not validate")
    return {"vm_leaf": "whole_function", "authenticated_text": True,
            "checksum_sites": sum(event["count"]
                                  for event in emitted("lifetime_step", "self_checksum")),
            "native_eh_seh": list(EH_OWNERS)}


def pe_metadata(image):
    data = image.read_bytes()
    require(data[:2] == b"MZ" and len(data) >= 64, "not a PE image")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    require(data[pe:pe + 4] == b"PE\0\0", "bad PE signature")
    machine, count = struct.unpack_from("<HH", data, pe + 4)
    optional_size, characteristics = struct.unpack_from("<HH", data, pe + 20)
    optional = pe + 24
    require(machine == 0x8664 and characteristics & 0x2000,
            "fixture must be an AMD64 DLL")
    require(struct.unpack_from("<H", data, optional)[0] == 0x20B and optional_size >= 144,
            "fixture must have a PE32+ exception directory")
    sections = []
    for index in range(count):
        offset = optional + optional_size + index * 40
        name = data[offset:offset + 8].split(b"\0", 1)[0].decode("ascii")
        virtual_size, rva, raw_size, raw_offset = struct.unpack_from("<IIII", data, offset + 8)
        flags = struct.unpack_from("<I", data, offset + 36)[0]
        require(raw_offset + raw_size <= len(data), f"section exceeds file: {name}")
        sections.append((name, virtual_size, rva, raw_size, raw_offset, flags))

    def mapped(rva, size):
        found = [(raw_offset + rva - base, section)
                 for section in sections
                 for _, virtual_size, base, raw_size, raw_offset, _ in [section]
                 if base <= rva and rva - base + size <= min(virtual_size, raw_size)]
        require(len(found) == 1, f"RVA has no unique raw mapping: {rva:#x}+{size}")
        return found[0]

    require(struct.unpack_from("<I", data, optional + 108)[0] >= 4,
            "PE data directories omit unwind directory")
    unwind_rva, unwind_size = struct.unpack_from("<II", data, optional + 112 + 3 * 8)
    require(unwind_rva != 0 and unwind_size != 0 and unwind_size % 12 == 0,
            "missing or malformed exception directory")
    unwind_offset, pdata = mapped(unwind_rva, unwind_size)
    require(pdata[0] == ".pdata", "exception directory is not in .pdata")
    unwind_sections = set()
    for position in range(unwind_offset, unwind_offset + unwind_size, 12):
        begin, end, info = struct.unpack_from("<III", data, position)
        require(begin < end and info != 0, "invalid RUNTIME_FUNCTION range/pointer")
        _, code = mapped(begin, end - begin)
        require(code[5] & 0x20000000, "unwind entry does not cover executable code")
        offset, section = mapped(info, 4)
        require(section[0] in (".xdata", ".rdata"),
                "unwind pointer is not backed by .xdata or merged .rdata")
        require(data[offset] & 7 in (1, 2), "invalid AMD64 UNWIND_INFO version")
        code_bytes = (data[offset + 2] * 2 + 3) & ~3
        flags = data[offset] >> 3
        require(flags & ~7 == 0, "invalid AMD64 unwind flags")
        extra = 12 if flags & 4 else 4 if flags & 3 else 0
        mapped(info, 4 + code_bytes + extra)
        unwind_sections.add(section[0])

    export_rva, export_size = struct.unpack_from("<II", data, optional + 112)
    require(export_rva != 0 and export_size >= 40, "missing export directory")
    export_offset, _ = mapped(export_rva, 40)
    function_count, name_count, functions, names, ordinals = struct.unpack_from(
        "<IIIII", data, export_offset + 20)
    function_offset, _ = mapped(functions, function_count * 4)
    name_offset, _ = mapped(names, name_count * 4)
    ordinal_offset, _ = mapped(ordinals, name_count * 2)
    exports = set()
    for index in range(name_count):
        name_rva = struct.unpack_from("<I", data, name_offset + index * 4)[0]
        offset, section = mapped(name_rva, 1)
        end = data.find(b"\0", offset, section[4] + min(section[1], section[3]))
        require(end != -1, "unterminated export name")
        name = data[offset:end].decode("ascii")
        require(name not in exports, "duplicate named export")
        exports.add(name)
        ordinal = struct.unpack_from("<H", data, ordinal_offset + index * 2)[0]
        require(ordinal < function_count, "export ordinal exceeds function table")
        address = struct.unpack_from("<I", data, function_offset + ordinal * 4)[0]
        require(not export_rva <= address < export_rva + export_size,
                f"fixture export is a forwarder: {name}")
        _, target = mapped(address, 1)
        require(target[5] & 0x20000000, f"export has no executable body: {name}")
    require(exports == EXPORTS, f"exact public DLL exports differ: {sorted(exports)}")
    return {"machine": "AMD64", "format": "PE32+", "exports": sorted(exports),
            "unwind_entries": unwind_size // 12, "unwind_sections": sorted(unwind_sections)}


def bound_records(image):
    # Use the existing PE checksum inspector's record/mapping conventions, but
    # verify every fixture record rather than treating a printed first record as proof.
    data, sections, records = checksum_sections(image)
    count = 0
    for _, size, rva, raw_size, raw_offset, _ in records:
        require(size != 0 and size % RECORD_SIZE == 0 and size <= raw_size,
                "malformed checksum record section")
        for relative in range(0, size, RECORD_SIZE):
            offset = raw_offset + relative
            require(struct.unpack_from("<I", data, offset)[0] == MAGIC, "bad checksum record magic")
            require(struct.unpack_from("<I", data, offset + OFF_FLAGS)[0] == 3,
                    "checksum record is not enabled and bound")
            require(struct.unpack_from("<I", data, offset + OFF_FORMAT)[0] == FORMAT_PE and
                    struct.unpack_from("<I", data, offset + OFF_TARGET_KIND)[0] == TARGET_REL32,
                    "checksum record lost PE REL32 encoding")
            encoded = struct.unpack_from("<Q", data, offset + OFF_DELTA)[0]
            require(encoded >> 32 == 0, "PE checksum REL32 upper bits are nonzero")
            delta = struct.unpack("<i", struct.pack("<I", encoded))[0]
            sample_size = struct.unpack_from("<I", data, offset + OFF_SAMPLE_SIZE)[0]
            require(sample_size > 0, "empty bound checksum sample")
            sample = map_exec(data, sections, rva + relative + delta, sample_size)
            seed = struct.unpack_from("<Q", data, offset + OFF_SEED)[0]
            expected = struct.unpack_from("<Q", data, offset + OFF_EXPECTED)[0]
            require(expected == checksum(data[sample:sample + sample_size], seed),
                    "bound checksum does not match linked image bytes")
            count += 1
    require(count > 0, "protected fixture has no bound checksum records")
    return count


class Harness:
    def __init__(self, args):
        self.args = args
        args.work.mkdir(parents=True, exist_ok=True)
        self.work = Path(tempfile.mkdtemp(prefix="cpp-pe-lifetime-", dir=args.work)).resolve()
        self.raw = [args.clang, "--driver-mode=g++"]
        self.result = {"status": "running", "work": str(self.work), "rows": [],
                       "modes": args.mode,
                       "scope": "native Windows x64 C++ DLL lifetime and unload"}
        self.save()
        print(f"CPP_PE_LIFETIME_WORK {self.work}", flush=True)

    def save(self):
        (self.work / "result.json").write_text(json.dumps(self.result, indent=2) + "\n", encoding="utf-8")

    def run(self, command, *, report=None, native=False):
        command = [str(item) for item in command]
        environment = {key: value for key, value in os.environ.items()
                       if not key.upper().startswith("OBF_")}
        if report is not None:
            environment["OBF_COVERAGE_REPORT"] = str(report)
        try:
            result = run_process(command, cwd=self.work, env=environment,
                                 timeout=120 if native else 300)
        except Exception as error:
            with (self.work / "commands.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps({"command": command, "error": str(error),
                                         "report": str(report) if report else None}) + "\n")
            raise
        with (self.work / "commands.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"command": command, "exit": result.returncode,
                                     "stdout": result.stdout, "stderr": result.stderr,
                                     "report": str(report) if report else None}) + "\n")
        require(result.returncode == 0,
                f"unexpected exit {result.returncode}: {command!r}\n{result.stdout}\n{result.stderr}")
        return result

    def native(self, host, images):
        observations = {}
        for mode in self.args.mode:
            image = images["failed_attach" if mode == "failed_attach" else "ordinary"]
            result = json.loads(self.run([host, image, mode], native=True).stdout)
            require(result.get("ok") is True and result.get("mode") == mode and
                    len(result.get("generations", [])) == 3,
                    f"missing exact native lifetime checks: {result}")
            observations[mode] = result
        return observations

    def build(self, optimization, level=None):
        folder = self.work / f"o{optimization}-{level or 'raw'}"
        folder.mkdir()
        flags = [*CXX_FLAGS, f"-O{optimization}"]
        host = self.work / f"host-o{optimization}.exe"
        if not host.exists():
            self.run([*self.raw, *flags, "-fuse-ld=lld",
                      FIXTURES / "cpp-pe-lifetime-host.cpp", "-o", host])
        config = folder / "policy.yaml"
        if level:
            policy(config, level)
        images = {}
        metadata = {}
        compiler = {}
        reports = {}
        checksums = {}
        for attachment in ("ordinary", "failed_attach"):
            case = folder / attachment
            case.mkdir()
            obj = case / "library.obj"
            image = case / "lifetime.dll"
            definitions = ["-DFAIL_ATTACH"] if attachment == "failed_attach" else []
            report = case / "coverage.json" if level else None
            if level:
                driver = [self.args.wrapper, f"--obf-config={config}"]
                self.run([*driver, *flags, *definitions, "-c",
                          FIXTURES / "cpp-pe-lifetime-library.cpp", "-o", obj], report=report)
                compiler[attachment] = check_report(report, level)
                objects = [obj]
            else:
                driver = self.raw
                self.run([*driver, *flags, *definitions, "-DRAW_CONTROL", "-c",
                          FIXTURES / "cpp-pe-lifetime-library.cpp", "-o", obj])
                oracle = case / "oracle.obj"
                self.run([*self.raw, *flags, "-c", FIXTURES / "cpp-pe-lifetime-oracle.cpp",
                          "-o", oracle])
                objects = [obj, oracle]
                compiler[attachment] = {"independent_oracle": True}
            # Keep real shared CRT/DLL startup. No custom entry point or CRT bypass.
            self.run([*driver, *flags, "-shared", "-fuse-ld=lld", *objects, "-o", image])
            metadata[attachment] = pe_metadata(image)
            if level:
                self.run([self.args.binder, image])
                checksums[attachment] = bound_records(image)
                self.run([sys.executable, FIXTURES / "self_checksum_pe_tool.py", "inspect", image])
            else:
                checksums[attachment] = 0
            images[attachment] = image
            reports[attachment] = str(report) if report else None
        observed = self.native(host, images)
        self.result["rows"].append({"optimization": optimization, "level": level or "raw",
                                    "host": str(host), "images": {k: str(v) for k, v in images.items()},
                                    "compiler_reports": reports, "compiler": compiler,
                                    "pe_metadata": metadata, "bound_records": checksums,
                                    "native": observed})
        self.save()
        return observed

    def matrix(self):
        for optimization in self.args.optimization:
            baseline = self.build(optimization)
            for level in self.args.level:
                observed = self.build(optimization, level)
                require(semantic_outcomes(observed) == semantic_outcomes(baseline),
                        f"protected outcomes differ from independent raw control: O{optimization} {level}")
                print(f"CPP_PE_LIFETIME_PASS O{optimization} {level} {' '.join(self.args.mode)}", flush=True)
        self.result["status"] = "passed"
        self.save()
        print(f"CPP_PE_LIFETIME_COMPLETE result={self.work / 'result.json'}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("wrapper", "clang", "binder"):
        parser.add_argument(f"--{option}", required=True)
    parser.add_argument("--work", type=Path, default=Path(tempfile.gettempdir()))
    parser.add_argument("--optimization", type=int, choices=(0, 2), action="append")
    parser.add_argument("--level", choices=("vm", "strong_vm"), action="append")
    parser.add_argument("--mode", choices=MODES, action="append")
    args = parser.parse_args()
    require(os.name == "nt" and platform.machine().lower() in ("x86_64", "amd64"),
            "native Windows x64 required")
    args.optimization = args.optimization or [0, 2]
    args.level = args.level or ["vm", "strong_vm"]
    args.mode = args.mode or list(MODES)
    harness = Harness(args)
    try:
        harness.matrix()
    except BaseException as error:
        harness.result.update(status="failed", error=str(error))
        harness.save()
        raise


if __name__ == "__main__":
    main()
