"""Check copied native ELF images across stripping, debug splitting, and binding."""
import argparse
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import zlib

from self_checksum_elf_tool import RECORD_SIZE, checksum, parse_elf, records, u16, u64

FIXTURES = Path(__file__).resolve().parent
STABLE_MTIME = 1_600_000_000_123_456_789
OPERATIONS = ("copy", "strip-debug", "strip-unneeded", "strip-all", "debug-split")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def snapshot(path):
    info = path.stat()
    return path.read_bytes(), stat.S_IMODE(info.st_mode), info.st_mtime_ns


def stable_mtime(path):
    os.utime(path, ns=(STABLE_MTIME, STABLE_MTIME))


def sections(data):
    parse_elf(data)
    start, stride, count = u64(data, 40), u16(data, 58), u16(data, 60)
    table = [struct.unpack_from("<IIQQQQIIQQ", data, start + i * stride)
             for i in range(count)]
    names_section = table[u16(data, 62)]
    names = data[names_section[4]:names_section[4] + names_section[5]]
    return {names[s[0]:names.index(b"\0", s[0])].decode("ascii"): s for s in table}


def section_bytes(data, section):
    blob = data[section[4]:section[4] + section[5]]
    require(len(blob) == section[5], "truncated section contents")
    return blob


def debug_info(data):
    section = sections(data).get(".debug_info")
    require(section is not None and section[1] != 8 and section[5] > 0,
            "raw debug-bearing TU did not retain real .debug_info")
    blob = section_bytes(data, section)
    require(any(blob), ".debug_info contains no debug data")
    return blob


def debuglink(image, debug, original_debug):
    data = image.read_bytes()
    table = sections(data)
    require(".debug_info" not in table, "deployed image still contains .debug_info")
    require(".gnu_debuglink" in table, "missing .gnu_debuglink")
    link = section_bytes(data, table[".gnu_debuglink"])
    nul = link.find(b"\0")
    require(nul > 0, "missing debuglink filename")
    crc_offset = (nul + 4) & ~3
    require(link[:nul] == debug.name.encode() and crc_offset + 4 == len(link),
            "debuglink filename/layout mismatch")
    require(struct.unpack_from("<I", link, crc_offset)[0] ==
            (zlib.crc32(debug.read_bytes()) & 0xFFFFFFFF), "debuglink CRC mismatch")
    require(debug_info(debug.read_bytes()) == original_debug,
            "separate debug file changed or lost raw TU debug data")


def record_identity(data, flags):
    found = records(data)
    require(len(found) >= 1, "no recognized self-checksum records")
    identity = []
    for record in found:
        require(record["flags"] == flags, "unexpected self-checksum binding state")
        start, size = record["file_offset"], record["sample_size"]
        sample = data[start:start + size]
        require(size > 0 and len(sample) == size, "empty or truncated sampled code")
        actual = checksum(sample, record["seed"])
        require(record["expected"] == (actual if flags == 3 else 0),
                "record checksum does not match actual sampled code/binding state")
        metadata = bytearray(data[record["offset"]:record["offset"] + RECORD_SIZE])
        metadata[8:12] = bytes(4)
        metadata[64:72] = bytes(8)
        identity.append((record["target"], bytes(metadata), sample))
    return found, sorted(identity)


def expected_binding(data):
    found, _ = record_identity(data, 1)
    expected = bytearray(data)
    for record in found:
        off, start, size = record["offset"], record["file_offset"], record["sample_size"]
        struct.pack_into("<I", expected, off + 8, 3)
        struct.pack_into("<Q", expected, off + 64,
                         checksum(data[start:start + size], record["seed"]))
    return bytes(expected)


class Harness:
    def __init__(self, args):
        self.args = args
        self.work = args.work.resolve()
        self.work.mkdir(parents=True, exist_ok=True)
        self.env = {key: value for key, value in os.environ.items()
                    if not key.upper().startswith("OBF") and key not in
                    {"LD_PRELOAD", "LD_AUDIT", "LD_DEBUG", "LD_DEBUG_OUTPUT"}}

    def run(self, command, *, reject=False, native=False):
        command = [str(item) for item in command]
        result = subprocess.run(command, cwd=self.work, env=self.env,
                                stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, errors="replace", timeout=30 if native else 180)
        success = result.returncode > 0 if reject else result.returncode == 0
        require(success, f"exit={result.returncode}: {' '.join(command)}\n"
                f"{result.stdout[-2000:]}\n{result.stderr[-2000:]}")

    def native(self, image, loader):
        self.run([loader or image, image], native=True)

    def bind(self, image, flags):
        stable_mtime(image)
        before = snapshot(image)
        _, identity = record_identity(before[0], flags)
        self.run([self.args.binder, image])
        after = snapshot(image)
        require(record_identity(after[0], 3)[1] == identity,
                "binding changed record identity or sampled code")
        if flags == 1:
            require(after[0] == expected_binding(before[0]) and after[1] == before[1],
                    "binding changed bytes outside flags/checksum or changed mode")
        else:
            require(after == before, "BOUND validation changed bytes/mode/mtime")
        stable_mtime(image)
        before_repeat = snapshot(image)
        self.run([self.args.binder, image])
        require(snapshot(image) == before_repeat, "repeat bind changed bytes/mode/mtime")

    def build(self, kind):
        directory = self.work / kind / "pristine"
        directory.mkdir(parents=True, exist_ok=True)
        flags = ["-O2", "-g", "-std=c11", "-fno-lto",
                 {"exec": "-fno-pie", "pie": "-fPIE", "shared": "-fPIC"}[kind]]
        objects = {}
        for name in ("target", "oracle", "consumer", "debug"):
            if name == "debug" and kind != "shared":
                continue
            obj = directory / f"{name}.o"
            extra = ["-DUSE_DLOPEN=1"] if name == "consumer" and kind == "shared" else []
            self.run([self.args.clang, *flags, *extra, "-c",
                      FIXTURES / f"self-checksum-packaging-{name}.c", "-o", obj])
            objects[name] = obj
        protected = directory / "protected.o"
        policy = f"--obf-config={FIXTURES / 'self-checksum-packaging.yaml'}"
        self.run([self.args.wrapper, *flags, policy, "-c",
                  FIXTURES / "self-checksum-packaging-target.c", "-o", protected])
        link = [{"exec": "-no-pie", "pie": "-pie", "shared": "-shared"}[kind],
                "-Wl,--build-id=none"]
        extras = [objects["debug"]] if kind == "shared" else [objects["oracle"], objects["consumer"]]
        loader = None
        if kind == "shared":
            loader = directory / "consumer"
            self.run([self.args.clang, "-pie", "-Wl,--build-id=none", objects["consumer"],
                      objects["oracle"], "-ldl", "-o", loader])
        raw, unbound, bound = (directory / name for name in ("raw", "unbound", "bound"))
        self.run([self.args.clang, *link, objects["target"], *extras, "-o", raw])
        require(not parse_elf(raw.read_bytes())[0], "raw control unexpectedly has checksum records")
        self.run([self.args.clang, *link, protected, *extras, self.args.runtime, "-o", unbound])
        self.run([self.args.wrapper, *link, policy, protected, *extras, "-o", bound])
        unbound_records, identity = record_identity(unbound.read_bytes(), 1)
        require(len(unbound_records) >= 2, "late rejection fixture requires at least two sites")
        require(record_identity(bound.read_bytes(), 3)[1] == identity,
                "wrapper final binding changed record/sample identity")
        # The oracle/consumer provide raw debug in executables; the hidden raw
        # carrier supplies it in DSOs, without changing protected debug cleanup.
        for image in (raw, unbound, bound):
            debug_info(image.read_bytes())
        deployed_raw = self.work / kind / "raw-control" / ("image.so" if loader else "program")
        deployed_raw.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(raw, deployed_raw)
        deployed_loader = self.copy_loader(loader, deployed_raw.parent)
        self.native(deployed_raw, deployed_loader)
        return unbound, bound, loader

    def copy_loader(self, loader, directory):
        if loader is None:
            return None
        deployed = directory / "consumer"
        shutil.copy2(loader, deployed)
        require(snapshot(deployed) == snapshot(loader), "consumer deployment changed bytes/mode/mtime")
        return deployed

    def package(self, kind, source, loader, flags, operation):
        directory = self.work / kind / ("unbound" if flags == 1 else "bound") / operation
        staging, deployment = directory / "staging", directory / "deployed"
        staging.mkdir(parents=True, exist_ok=True)
        deployment.mkdir(parents=True, exist_ok=True)
        stage = staging / ("image.so" if loader else "program")
        shutil.copy2(source, stage)
        require(snapshot(stage) == snapshot(source), "pristine staging copy changed bytes/mode/mtime")
        identity = record_identity(source.read_bytes(), flags)[1]
        debug = None
        if operation == "debug-split":
            original_debug = debug_info(source.read_bytes())
            debug = stage.with_name(stage.name + ".debug")
            self.run([self.args.objcopy, "--only-keep-debug", stage, debug])
            self.run([self.args.objcopy, "--strip-debug", stage])
            self.run([self.args.objcopy, f"--add-gnu-debuglink={debug}", stage])
            debuglink(stage, debug, original_debug)
        elif operation != "copy":
            self.run([self.args.strip, f"--{operation}", stage])
            require(".debug_info" not in sections(stage.read_bytes()), "strip retained debug info")
        require(record_identity(stage.read_bytes(), flags)[1] == identity,
                f"{operation}: packaging changed record identity or sample contents")
        image = deployment / stage.name
        shutil.copy2(stage, image)
        require(snapshot(image) == snapshot(stage), "image deployment changed bytes/mode/mtime")
        deployed_loader = self.copy_loader(loader, deployment)
        if debug:
            deployed_debug = deployment / debug.name
            shutil.copy2(debug, deployed_debug)
            require(snapshot(debug) == snapshot(deployed_debug), "debug deployment changed file")
            debuglink(image, deployed_debug, original_debug)
        self.bind(image, flags)
        if debug:
            debuglink(image, deployed_debug, original_debug)
        self.native(image, deployed_loader)

    def negatives(self, kind, unbound, bound):
        directory = self.work / kind / "rejections"
        directory.mkdir(parents=True, exist_ok=True)
        for name, source in (("late-malformed", unbound), ("bound-sample-mismatch", bound)):
            image = directory / name
            shutil.copy2(source, image)
            data = bytearray(image.read_bytes())
            found = records(data)
            if name == "late-malformed":
                require(len(found) >= 2 and all(record["flags"] == 1 for record in found),
                        "late malformed fixture needs preceding valid UNBOUND records")
                # Earlier valid records need updates; rejection at the later
                # header must not publish those updates to the original file.
                require(expected_binding(data) != data, "UNBOUND fixture would not change")
                data[found[-1]["offset"]] ^= 1
            else:
                record = found[0]
                start, size = record["file_offset"], record["sample_size"]
                data[start] ^= 1
                require(checksum(data[start:start + size], record["seed"]) != record["expected"],
                        "sample mutation did not change the checksum")
            image.write_bytes(data)
            stable_mtime(image)
            before = snapshot(image)
            self.run([self.args.binder, image], reject=True)
            require(snapshot(image) == before, f"{name}: rejection changed bytes/mode/mtime")

    def check(self):
        for kind in ("exec", "pie", "shared"):
            unbound, bound, loader = self.build(kind)
            for flags, source in ((1, unbound), (3, bound)):
                for operation in OPERATIONS:
                    self.package(kind, source, loader, flags, operation)
            self.negatives(kind, unbound, bound)
        print("ELF packaging passed: 30 copied images, 512 exact returns/effects each, 6 preserved rejections")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("clang", "wrapper", "binder", "runtime", "strip", "objcopy"):
        parser.add_argument(f"--{option}", required=True)
    parser.add_argument("--work", type=Path, required=True)
    Harness(parser.parse_args()).check()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"ELF packaging failure: {error}"[-5000:], file=sys.stderr)
        sys.exit(1)
