"""Check Linux x86-64 authenticated copy-only DSO exchange and real unload.

Source ID 2 uses C++ function-local immutable storage. Cold means the first
application copy, after constructor decoding for ctor rows. Lazy cache
corruption is meaningful only after a successful copy. Other lazy fields and
all ctor fields are tested both cold and warm.

Each concurrent scenario starts a fresh host process and fresh producer loads.
The start barrier does not prove deterministic decoder overlap. Shutdown closes
host admission with reserved calls parked outside producer code, drains and
joins workers, clears callables, and proves mapping removal before consumption.
--only-concurrency runs the native concurrent matrix without corruption or
export-negative checks; compiler policy, source bindings, and VM ledgers remain
required. Exporter and protected consumer policies vary independently.

The default run includes both LLD and GNU BFD export profiles.
--only-export-isolation --linker lld (or bfd) runs one export profile.
Raw links use the same protected object and matching runtime as managed links.
ELF symbol tables, native maps, and bounded E9/EB routes establish each control.
Commands, ledgers, private data, and native observations stay under /var/tmp.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import struct
import tempfile

from report_contract import coverage_contract
from self_checksum_elf_packaging import sections
from vm_incoming_abi import run_process

FIXTURES = Path(__file__).resolve().parent
INCLUDE = FIXTURES.parents[2] / "include"
FLAGS = ("-std=c11", "-fno-inline", "-fno-vectorize", "-fno-slp-vectorize",
         "-fno-unroll-loops")
CXX_FLAGS = ("-x", "c++", "-std=c++17", *FLAGS[1:])
CXX_SOURCES = {"cross-dso-string-copy-producer.c", "cross-dso-string-copy-raw.c"}
TEXTS = ((b"amber producer A owns this copy\0", b"A: independent data 1847\0", b"\0"),
         (b"violet producer B has another payload\0", b"B: distinct data 9263\0", b"\0"))
MUTATIONS = ("cache", "tag", "ciphertext", "length", "version")
CONCURRENT_SCENARIOS = ("same-1", "same-2", "same-3",
                         "independent-sources", "independent-producers")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


class ElfData:
    """Read private data addresses from ELF64 symbols and native relocations."""

    def __init__(self, image, *, require_symbols=True):
        self.image = image
        self.data = image.read_bytes()
        self.named = sections(self.data)
        require(struct.unpack_from("<HH", self.data, 16) == (3, 62),
                f"expected a native x86-64 shared library: {image}")
        start = struct.unpack_from("<Q", self.data, 40)[0]
        stride, count = struct.unpack_from("<HH", self.data, 58)
        require(stride == 64, "unexpected ELF64 section header size")
        self.table = [struct.unpack_from("<IIQQQQIIQQ", self.data, start + index * stride)
                      for index in range(count)]
        self.symbols = []
        self.symbol_tables = {}
        self.dynamic_symbols = []
        for index, section in enumerate(self.table):
            if section[1] not in (2, 11):  # SHT_SYMTAB, SHT_DYNSYM
                continue
            require(section[9] == 24 and section[5] % 24 == 0,
                    "invalid ELF symbol table")
            strings = self.table[section[6]]
            names = self.data[strings[4]:strings[4] + strings[5]]
            symbols = []
            for position in range(section[4], section[4] + section[5], 24):
                name, info, other, owner, address, size = struct.unpack_from(
                    "<IBBHQQ", self.data, position)
                require(name < len(names), "invalid ELF symbol name offset")
                symbol = {"name": names[name:names.index(b"\0", name)].decode("utf-8"),
                          "binding": info >> 4, "type": info & 15, "section": owner,
                          "address": address, "size": size, "visibility": other & 3}
                symbols.append(symbol)
            self.symbol_tables[index] = symbols
            if section[1] == 2:
                self.symbols.extend(symbols)
            else:
                self.dynamic_symbols.extend(symbols)
        require(not require_symbols or self.symbols,
                "private ELF .symtab is required for data-only corruption")
        self.relocations = {}
        for section in self.table:
            if section[1] != 4:  # SHT_RELA
                continue
            require(section[9] == 24 and section[5] % 24 == 0,
                    "invalid ELF relocation table")
            symbols = self.symbol_tables[section[6]]
            for position in range(section[4], section[4] + section[5], 24):
                address, info, addend = struct.unpack_from("<QQq", self.data, position)
                kind, symbol = info & 0xFFFFFFFF, info >> 32
                if kind == 8:  # R_X86_64_RELATIVE
                    value = addend
                elif kind == 1:  # R_X86_64_64
                    require(symbol < len(symbols), "invalid relocation symbol")
                    value = symbols[symbol]["address"] + addend
                else:
                    continue
                require(address not in self.relocations, "duplicate native pointer relocation")
                self.relocations[address] = value

    def data_section(self, address, size):
        candidates = [section for section in self.table
                      if section[2] & 2 and not section[2] & 4 and  # ALLOC, not EXECINSTR
                      section[3] <= address and
                      address + size <= section[3] + section[5]]
        require(len(candidates) == 1, f"address is not bounded ELF data: {address:#x}")
        return candidates[0]

    def read(self, address, size):
        section = self.data_section(address, size)
        if section[1] == 8:  # SHT_NOBITS
            return bytes(size)
        start = section[4] + address - section[3]
        data = self.data[start:start + size]
        require(len(data) == size, "truncated ELF data")
        return data

    def pointer(self, address):
        value = self.relocations.get(address)
        if value is None:
            value = struct.unpack("<Q", self.read(address, 8))[0]
        require(value > 0, f"unresolved private data pointer: {address:#x}")
        return value

    def private_object(self, address, size):
        self.data_section(address, size)
        matches = [symbol for symbol in self.symbols
                   if symbol["type"] == 1 and symbol["binding"] == 0 and
                   symbol["address"] == address and symbol["size"] >= size]
        require(matches, f"data target is not a producer-private ELF object: {address:#x}")
        return min(matches, key=lambda symbol: symbol["size"])

    def bundle(self, text):
        # These offsets belong to the existing private runtime V3 layout. The
        # fixture does not add a production descriptor interface or callback.
        length = len(text)
        candidates = []
        for symbol in self.symbols:
            if symbol["type"] != 1 or symbol["binding"] != 0 or symbol["size"] != 168:
                continue
            blob = self.read(symbol["address"], 168)
            version, flags, actual = struct.unpack_from("<IIQ", blob)
            capacities = struct.unpack_from("<QQQ", blob, 80)
            if version == 3 and flags == 1 and actual == length and capacities == (length, length, 32):
                candidates.append((symbol, blob))
        require(len(candidates) == 1,
                f"expected one private V3 string descriptor of length {length}: {self.image}")
        descriptor, blob = candidates[0]
        address = descriptor["address"]
        destination_ref = self.pointer(address + 136)
        ciphertext_ref = self.pointer(address + 144)
        key_ref = self.pointer(address + 152)
        key = self.pointer(key_ref + 8)
        for reference in (destination_ref, ciphertext_ref, key_ref):
            self.private_object(reference, 16)
        key_symbol = self.private_object(key, 32)
        cache = self.pointer(destination_ref + 8)
        ciphertext = self.pointer(ciphertext_ref + 8)
        cache_symbol = self.private_object(cache, length)
        ciphertext_symbol = self.private_object(ciphertext, length)
        state = self.pointer(address + 160)
        self.private_object(state, 24)
        state_cookie, cold_status, completion = struct.unpack("<QQQ", self.read(state, 24))
        require(state_cookie == struct.unpack_from("<Q", blob, 72)[0] and cold_status == completion,
                "private V3 state cookie or initial completion differs")
        require(self.data_section(cache, length)[2] & 1,
                "decoded cache is not writable producer data")
        require(self.read(cache, length) == bytes(length),
                "protected source has plaintext in its on-disk cache")
        encrypted = self.read(ciphertext, length)
        require(length == 1 or encrypted != text, "protected source retained plaintext ciphertext")
        targets = {"cache": cache, "tag": address + 120, "ciphertext": ciphertext,
                   "length": address + 8, "version": address}
        originals = {mode: (text[0] if mode == "cache" else self.read(target, 1)[0])
                     for mode, target in targets.items()}
        return {"descriptor_symbol": descriptor["name"], "descriptor": address,
                "cache_symbol": cache_symbol["name"], "cache": cache,
                "ciphertext_symbol": ciphertext_symbol["name"], "ciphertext": ciphertext,
                "build_key_symbol": key_symbol["name"], "build_key": key,
                "state": state, "cold_status": cold_status,
                "build_key_sha256": hashlib.sha256(self.read(key, 32)).hexdigest(),
                "length": length, "module_id": struct.unpack_from("<Q", blob, 16)[0],
                "ciphertext_sha256": hashlib.sha256(encrypted).hexdigest(),
                "targets": targets, "originals": originals}

    def symbol(self, name):
        matches = [symbol for symbol in self.symbols
                   if symbol["name"] == name and symbol["section"] != 0]
        require(len(matches) == 1, f"private ELF symbol is not unique: {name}")
        return matches[0]

    def exports(self, expected):
        exports = {symbol["name"]: symbol for symbol in self.dynamic_symbols
                   if symbol["section"] != 0 and symbol["binding"] in (1, 2, 10) and
                   symbol["visibility"] in (0, 3)}
        require(set(exports) == set(expected), f"public ELF exports differ: {exports}")
        return {"machine": "x86-64", "format": "ELF64", "exports": exports}

    def private_runtime(self, names):
        require(not any(symbol["name"] in names for symbol in self.dynamic_symbols),
                "private runtime symbol survives in ELF .dynsym")
        symbols = [self.symbol(name) for name in names] if self.symbols else []
        require(all(symbol["binding"] == 0 or symbol["visibility"] in (1, 2)
                    for symbol in symbols), "runtime definition is not ELF-private")
        # GNU BFD can localize hidden definitions to LOCAL DEFAULT. Record the
        # actual fields. Do not require HIDDEN on an already-local definition.
        return {"dynsym_absent": True, "symtab": symbols}

    def object_functions(self, path, obj, linker):
        text = path.read_text(encoding="utf-8", errors="replace")
        owner = re.escape(str(obj))
        if linker == "lld":
            pattern = (rf"^\s*([0-9a-fA-F]+)\s+[0-9a-fA-F]+\s+"
                       rf"([0-9a-fA-F]+)\s+\d+\s+{owner}:\(\.text(?:\.[^)]*)?\)")
        else:
            pattern = (rf"^\s*\.text(?:\.\S+)?\s+0x([0-9a-fA-F]+)\s+"
                       rf"0x([0-9a-fA-F]+)\s+{owner}(?:\s|$)")
        ranges = [(int(match.group(1), 16), int(match.group(2), 16))
                  for match in re.finditer(pattern, text, re.MULTILINE)]
        require(ranges, "native map omits producer executable contributions")
        functions = [symbol for symbol in self.symbols
                     if symbol["type"] == 2 and symbol["binding"] == 0 and symbol["size"] > 0 and
                     any(start <= symbol["address"] and
                         symbol["address"] + symbol["size"] <= start + size
                         for start, size in ranges)]
        require(functions, "producer has no mapped private functions")
        return sorted(functions, key=lambda symbol: symbol["address"])

    def map_symbol_address(self, path, name, linker):
        text = path.read_text(encoding="utf-8", errors="replace")
        if linker == "lld":
            pattern = (rf"^\s*([0-9a-fA-F]+)\s+[0-9a-fA-F]+\s+"
                       rf"[0-9a-fA-F]+\s+\d+\s+{re.escape(name)}(?:\s|$)")
        else:
            pattern = rf"^\s*0x([0-9a-fA-F]+)\s+{re.escape(name)}(?:\s|$)"
        addresses = {int(match.group(1), 16)
                     for match in re.finditer(pattern, text, re.MULTILINE)}
        require(len(addresses) == 1 and
                (not self.symbols or addresses == {self.symbol(name)["address"]}),
                f"native map and ELF .symtab disagree for {name}: {addresses}")
        return addresses.pop()

    def thunk_route(self, address, target):
        path, opcodes, visited = [], [], set()
        current = address
        termination = "depth"
        for _ in range(64):
            if current in visited:
                termination = "cycle"
                break
            visited.add(current)
            path.append(current)
            if current == target:
                termination = "private-target"
                break
            sections_at = [section for section in self.table if section[2] & 2 and
                           section[3] <= current < section[3] + section[5]]
            if len(sections_at) != 1:
                termination = "unmapped"
                break
            section = sections_at[0]
            if not section[2] & 4:
                termination = "nonexecutable"
                break
            offset = section[4] + current - section[3]
            if section[1] == 8 or offset >= len(self.data):
                termination = "truncated"
                break
            opcode = self.data[offset]
            if opcode not in (0xE9, 0xEB):
                termination = "ordinary-body"
                break
            size = 5 if opcode == 0xE9 else 2
            if current + size > section[3] + section[5] or offset + size > len(self.data):
                termination = "truncated"
                break
            opcodes.append(f"{opcode:02x}")
            displacement = struct.unpack_from("<i" if size == 5 else "<b",
                                              self.data, offset + 1)[0]
            current += size + displacement
        else:
            if current == target:
                path.append(current)
                termination = "private-target"
        return {"exported_address": address, "endpoint_address": current,
                "address_path": path, "opcodes": opcodes,
                "hops": len(opcodes), "termination": termination}


def policy(path, owner, level, *, seed=8675309, strategy="lazy", debug=False,
           authenticated=True, limit=64, ephemeral=False, ctor=True,
           frontend="generic", budget=512):
    lines = [f"frontend: {frontend}", f"seed: {seed}", "default_level: none",
             f"debug_preserve_generated_names: {'true' if debug else 'false'}",
             "targets:", f"  - match: {owner}", f"    level: {level}",
             "vm:", f"  max_virtual_instructions: {budget}", "  max_mba_depth: 0",
             "string_encoding:", f"  authenticated_mode: {'true' if authenticated else 'false'}",
             f"  prefer_lazy_decode: {'true' if strategy == 'lazy' else 'false'}",
             f"  allow_ctor_fallback: {'true' if ctor else 'false'}",
             f"  enable_ephemeral_slots: {'true' if ephemeral else 'false'}",
             f"  max_strings_per_module: {limit}", "self_checksum:", "  enabled: false",
             "security:", "  fail_on_public_obf_symbol: true",
             f"  strip_release_markers: {'false' if frontend == 'generic' else 'true'}"]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def check_report(path, owner, level, *, producer=False):
    report = coverage_contract(json.loads(path.read_text(encoding="utf-8")))
    require(report["capture"] == "enabled", "compiler ledger not captured")
    selected = [event["policy"] for event in report["requested_policy"]
                if event["owner"] == owner and event["phase"] == "selected"]
    require(len(selected) == 1 and selected[0]["level"] == level,
            f"requested policy changed for {owner}")
    result = {"level": level}
    if producer:
        encoded = [event for event in report["emission"]
                   if event["owner"] == owner and event["mechanism"] == "string_encoding"
                   and event["status"] == "emitted"]
        require(encoded, "producer did not emit string encoding")
        decoders = {role["target"] for role in report["roles"]
                    if role["owner"] == owner and role["role"] == "string_decoder"
                    and "authenticated_string_decode" in role["obligations"]}
        require(len(decoders) >= 3,
                "producer sources lack independent authenticated decoder obligations")
        bindings = None
        for phase, status in (("emission", "generated"), ("emission", "bound"),
                              ("finalization", "validated")):
            events = [event for event in report[phase] if event["owner"] == owner
                      and event["mechanism"] == "string_copy_export" and event["status"] == status]
            actual = {}
            for event in events:
                match = re.search(r"(?:^|, )id=(\d+)(?:,|$)", event["reason"])
                require(match is not None, "source binding has no exact ID")
                source_id = int(match.group(1))
                require(source_id not in actual and event["count"] == 1,
                        "source binding repeats an ID or changes its count")
                actual[source_id] = event["target"]
            require(len(events) == 3 and set(actual) == {1, 2, 3},
                    f"copy-export ledger lost exact source binding at {phase}/{status}")
            if bindings is None:
                bindings = actual
                require("copy_primary" in bindings[1] and
                        "retain_local_source" in bindings[2] and "copy_secondary" in bindings[2] and
                        "copy_empty" in bindings[3],
                        "producer lost its file-local or C++ function-local source identities")
            require(actual == bindings, f"source identities changed at {phase}/{status}")
        result.update(authenticated_sources=3, decoder_roles=sorted(decoders),
                      source_ids=[1, 2, 3], source_bindings=bindings,
                      export_finalizer="validated")
    if not producer or level in ("vm", "strong_vm"):
        require(selected[0]["allow_vm"], "selected byte-reader or exporter lost VM eligibility")
        admitted = [event for event in report["admission"]
                    if event["owner"] == owner and event["mechanism"] == "vm"
                    and event["scope"] == "whole_function" and event["status"] == "admitted"]
        emitted = [event for event in report["emission"]
                   if event["owner"] == owner and event["mechanism"] == "vm"
                   and event["scope"] == "whole_function" and event["status"] == "emitted"
                   and event["count"] > 0]
        require(admitted and emitted, "selected function did not admit and emit whole-function VM")
        result["vm_exporter" if producer else "vm_consumer"] = "whole_function"
    require(any(event["mechanism"] == "security_gates" and event["status"] == "validated"
                for event in report["finalization"]), "compiler security gates did not validate")
    return result


def require_native_rejection(result):
    require(result.returncode == 2 and
            any(line.startswith("obf-native-link:") for line in result.stderr.splitlines()),
            "link rejection did not come from native ownership validation")


class Harness:
    def __init__(self, args):
        self.args = args
        require(args.work.resolve().is_relative_to(Path("/var/tmp")),
                "scratch and evidence must stay under /var/tmp")
        args.work.mkdir(parents=True, exist_ok=True)
        self.work = Path(tempfile.mkdtemp(prefix="cross-dso-string-copy-", dir=args.work)).resolve()
        tempfile.tempdir = str(self.work)
        self.raw = [args.clang]
        self.result = {"status": "running", "work": str(self.work), "rows": [],
                       "controls": [], "exporters": [], "concurrency": [], "rejections": [],
                       "scope": "native Linux x86-64 glibc copy-only DSO exchange",
                       "matrix": {"optimization": args.optimization, "level": args.level,
                                  "strategy": args.strategy, "tamper": args.tamper,
                                  "cold_authentication": not args.warm_only,
                                  "rejections": not args.skip_negatives and not args.only_concurrency,
                                  "only_export_isolation": args.only_export_isolation,
                                  "only_concurrency": args.only_concurrency,
                                  "export_linker_filter": args.linker}}
        self.producers = {}
        self.consumers = {}
        self._runtime_abi = None
        self.save()
        print(f"CROSS_DSO_STRING_COPY_WORK {self.work}", flush=True)

    def save(self):
        (self.work / "result.json").write_text(json.dumps(self.result, indent=2) + "\n", encoding="utf-8")

    def runtime_abi(self):
        if self._runtime_abi is None:
            headers = ([self.args.runtime_header] if self.args.runtime_header else
                       [Path(self.args.wrapper).parent /
                        "include/obf/support/runtime_abi_generated.h",
                        Path(self.args.wrapper).parent.parent /
                        "include/obf/support/runtime_abi_generated.h"])
            header = next((path.resolve() for path in headers if path.is_file()), None)
            require(header is not None, "runtime ABI header unavailable: pass --runtime-header")
            names = dict(re.findall(r'^#define\s+(OBF_RT_\w+_STR)\s+"([^"\r\n]+)"',
                                    header.read_text(encoding="utf-8"), re.MULTILINE))
            required = ("OBF_RT_ABI_PREFIX_STR", "OBF_RT_STRING_AUTH_DECODE_V3_STR",
                        "OBF_RT_ENTROPY_ANCHOR_STR", "OBF_RT_LOAD_ENTROPY_PAIR_STR",
                        "OBF_RT_LOAD_ENTROPY_PAIR_V1_STR", "OBF_RT_LOAD_ENTROPY_PAIR_V2_STR",
                        "OBF_RT_LOAD_ENTROPY_PAIR_V3_STR", "OBF_RT_LOAD_ENTROPY_PAIR_V4_STR",
                        "OBF_RT_SELF_CHECKSUM_REQUIRE_BOUND_STR")
            require(all(name in names for name in required),
                    "generated header omits a required native runtime symbol")
            runtime = (self.args.runtime or
                       Path(self.args.wrapper).parent / "libobf_runtime.a").resolve()
            require(runtime.is_file(), "matching runtime archive unavailable: pass --runtime")
            entropy = [names[name] for name in required[3:]]
            self._runtime_abi = (header, runtime, names, entropy)
        return self._runtime_abi

    def run(self, command, *, report=None, native=False, rejects=False):
        command = [str(value) for value in command]
        environment = {key: value for key, value in os.environ.items()
                       if not key.upper().startswith("OBF_") and not key.startswith("LD_")}
        environment.update(TMPDIR=str(self.work), TMP=str(self.work), TEMP=str(self.work))
        if report is not None:
            environment["OBF_COVERAGE_REPORT"] = str(report)
        record = {"command": command, "report": str(report) if report else None}
        try:
            result = run_process(command, cwd=self.work, env=environment,
                                 timeout=30 if native else 300)
            record.update(exit=result.returncode, stdout=result.stdout, stderr=result.stderr)
        except Exception as error:
            record.update(error=str(error), stdout=str(getattr(error, "output", "")),
                          stderr=str(getattr(error, "stderr", "")))
            raise
        finally:
            with (self.work / "commands.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(record) + "\n")
        require(result.returncode > 0 if rejects else result.returncode == 0,
                f"unexpected exit {result.returncode}: {command!r}\n{result.stdout}\n{result.stderr}")
        return result

    def native(self, *arguments):
        result = json.loads(self.run([self.host, *arguments], native=True).stdout)
        require(result.get("ok") is True, f"missing native outcome: {result}")
        return result

    def compile(self, folder, name, source, optimization, *, config=None, defines=(), report=False):
        obj = folder / f"{name}.o"
        ledger = folder / f"{name}-coverage.json" if report else None
        driver = [self.args.wrapper, f"--obf-config={config}"] if config else self.raw
        flags = CXX_FLAGS if source in CXX_SOURCES else FLAGS
        self.run([*driver, *flags, f"-O{optimization}", "-g", "-fPIC", "-I", INCLUDE,
                  *defines, "-c", FIXTURES / source, "-o", obj], report=ledger)
        return obj, ledger

    def shared(self, obj, config=None):
        image = obj.with_suffix(".so")
        driver = [self.args.wrapper, f"--obf-config={config}"] if config else self.raw
        self.run([*driver, "-shared", "-fuse-ld=lld", obj, "-o", image])
        require(image.is_file(), "shared link did not produce its output")
        return image

    def build_raw(self, optimization):
        folder = self.work / f"o{optimization}-raw"
        folder.mkdir()
        producers = []
        for variant in (1, 2):
            obj, _ = self.compile(folder, f"producer-{variant}", "cross-dso-string-copy-raw.c",
                                  optimization, defines=[f"-DCOPY_VARIANT={variant}"])
            producers.append(self.shared(obj))
        obj, _ = self.compile(folder, "consumer", "cross-dso-string-copy-consumer.c", optimization)
        consumer = self.shared(obj)
        obj, _ = self.compile(folder, "v2-only", "cross-dso-string-copy-raw.c", optimization,
                              defines=["-DCOPY_VARIANT=1", "-DCOPY_V2_ONLY"])
        incompatible = self.shared(obj)
        observed = self.native("semantics", *producers, consumer, incompatible)
        self.result["controls"].append({"optimization": optimization, "kind": "independent_raw",
                                        "producers": list(map(str, producers)),
                                        "consumer": str(consumer), "native": observed})
        self.save()
        return producers, consumer, incompatible, observed

    def build_consumer(self, optimization, level):
        key = (optimization, level)
        if key in self.consumers:
            return self.consumers[key]
        folder = self.work / f"o{optimization}-{level}-consumer"
        folder.mkdir()
        config = folder / "policy.yaml"
        policy(config, "exchange_read_bytes", level)
        obj, report = self.compile(folder, "consumer", "cross-dso-string-copy-consumer.c",
                                   optimization, config=config, report=True)
        compiler = check_report(report, "exchange_read_bytes", level)
        self.consumers[key] = (self.shared(obj, config),
                                {"report": str(report), "outcome": compiler})
        return self.consumers[key]

    def build_producers(self, optimization, strategy, raw_consumer, incompatible, baseline,
                        *, level="strong"):
        key = (optimization, strategy, level)
        if key in self.producers:
            return self.producers[key]
        folder = self.work / f"o{optimization}-{strategy}-{level}-producers"
        folder.mkdir()
        images, compilers, bundles = [], [], []
        for variant in (1, 2):
            config = folder / f"producer-{variant}.yaml"
            policy(config, "exchange_copy_v1", level, seed=8675309 + variant * 104729,
                   strategy=strategy, debug=level == "strong", ctor=strategy != "lazy")
            obj, report = self.compile(folder, f"producer-{variant}",
                                       "cross-dso-string-copy-producer.c", optimization,
                                       config=config, defines=[f"-DCOPY_VARIANT={variant}"], report=True)
            compiler = check_report(report, "exchange_copy_v1", level, producer=True)
            image = self.shared(obj, config)
            elf = ElfData(image)
            source_bundles = [elf.bundle(text) for text in TEXTS[variant - 1]]
            require(len({bundle["descriptor"] for bundle in source_bundles}) == 3 and
                    len({bundle["cache"] for bundle in source_bundles}) == 3 and
                    len({bundle["ciphertext"] for bundle in source_bundles}) == 3,
                    "producer source descriptors/cache/ciphertext alias each other")
            metadata = elf.exports({"exchange_copy_v1"})
            _, _, _, entropy = self.runtime_abi()
            metadata["entropy_symbols"] = elf.private_runtime(entropy)
            (folder / f"producer-{variant}-private-data.json").write_text(
                json.dumps(source_bundles, indent=2) + "\n", encoding="utf-8")
            images.append(image)
            compilers.append({"report": str(report), "outcome": compiler,
                              "elf_metadata": metadata})
            bundles.append(source_bundles)
        for source in range(3):
            require(bundles[0][source]["build_key_sha256"] !=
                    bundles[1][source]["build_key_sha256"],
                    "independent producer keys are identical")
            if source != 2:
                require(bundles[0][source]["ciphertext_sha256"] !=
                        bundles[1][source]["ciphertext_sha256"],
                        "independent producer nonempty ciphertext data are identical")
        observed = self.native("semantics", *images, raw_consumer, incompatible)
        require(observed == baseline, "protected producers differ from independent raw semantic oracle")
        self.result["controls"].append({"optimization": optimization, "strategy": strategy,
                                        "level": level,
                                        "kind": "protected_producers_raw_consumer", "native": observed})
        self.producers[key] = (images, compilers, bundles, observed)
        self.save()
        return self.producers[key]

    def concurrency(self, optimization, images, consumer, *, strategy="raw",
                    exporter_level="raw", consumer_level="raw", bundles=None,
                    producer_compilers=None, consumer_compiler=None):
        metadata = []
        if strategy != "raw":
            require(bundles is not None and len(bundles) == 2 and
                    all(len(sources) == 3 for sources in bundles),
                    "concurrent protected row lacks all six private source bundles")
            for sources in bundles:
                for bundle in sources:
                    metadata.extend(hex(bundle[name]) for name in ("cache", "state", "cold_status"))
        row = {"optimization": optimization, "exporter_level": exporter_level,
               "consumer_level": consumer_level, "strategy": strategy,
               "producers": list(map(str, images)), "consumer": str(consumer),
               "producer_compilers": producer_compilers,
               "consumer_compiler": consumer_compiler, "outcomes": []}
        self.result["concurrency"].append(row)
        self.save()
        for scenario in CONCURRENT_SCENARIOS:
            # A separate host invocation prevents a prior case warming this one.
            observed = self.native("concurrent", *images, consumer, strategy, scenario, *metadata)
            workers, rounds = observed.get("workers"), observed.get("warm_rounds")
            owner_copies = (2 if scenario.startswith("same-") else
                            3 if scenario == "independent-sources" else 6)
            require(observed["kind"] == "concurrency" and
                    observed["scenario"] == scenario and observed["strategy"] == strategy and
                    workers == 36 and rounds == 4 and
                    observed["barrier_started"] is True and
                    observed["cold_state_checked"] is (strategy == "lazy") and
                    observed["admitted"] == observed["completed"] == workers * (2 + 7 * rounds) and
                    observed["host_parked_at_close"] == workers and
                    observed["post_close_rejected"] == 3 and
                    observed["drained"] is True and observed["callables_cleared"] is True and
                    observed["unmapped"] == [True, True] and
                    observed["copies_after_unload"] == workers and
                    observed["owner_copies_after_unload"] == owner_copies and
                    observed["decoder_overlap_proven"] is False and
                    len(observed["statuses"]) == 4 and
                    all(count > 0 for count in observed["statuses"]) and
                    sum(observed["statuses"]) == observed["completed"],
                    f"missing concurrent admission, copy, or unload evidence: {observed}")
            row["outcomes"].append(observed)
            self.save()
        print(f"CROSS_DSO_STRING_COPY_CONCURRENCY_PASS O{optimization} "
              f"{exporter_level} {consumer_level} {strategy}", flush=True)

    def freshness(self, images, bundles, consumer, strategy, observations):
        for variant, (image, sources) in enumerate(zip(images, bundles), 1):
            for source_id, bundle in enumerate(sources, 1):
                for mode in self.args.tamper:
                    phases = [True]
                    if not self.args.warm_only and (strategy == "ctor" or mode != "cache"):
                        phases.append(False)
                    for warm in phases:
                        observed = self.native("tamper", image, consumer, variant, source_id,
                                               mode, int(warm), hex(bundle["targets"][mode]),
                                               bundle["originals"][mode], strategy, hex(bundle["cache"]),
                                               hex(bundle["state"]), hex(bundle["cold_status"]))
                        require(observed["kind"] == "tamper" and observed["mode"] == mode and
                                observed["warm"] is warm and observed["variant"] == variant and
                                observed["id"] == source_id and observed["ordinary_rejections"] == 5 and
                                observed["signal"] == 4 and observed["stage"] == 3 and
                                observed["required"] == bundle["length"] and
                                observed["destination_unchanged"] and observed["effect_unchanged"] and
                                observed["lazy_state_checked"] is (strategy == "lazy"),
                                "missing corruption or non-certification outcome")
                        observations.append(observed)
                        self.save()


    def export_rejection(self, ledger, code):
        require(ledger.is_file(), "rejected export has no compiler ledger")
        report = coverage_contract(json.loads(ledger.read_text(encoding="utf-8")))
        require(any(event["mechanism"] == "string_copy_export" and event["status"] == "rejected" and
                    event["reason"].partition(",")[0] == f"code={code}"
                    for event in report["finalization"]),
                f"export did not reject through the expected gate: {code}")

    def reject_build(self, folder, name, source, config, *, code, defines=(), extra=()):
        output = folder / f"{name}.o"
        ledger = folder / f"{name}-coverage.json"
        result = self.run([self.args.wrapper, f"--obf-config={config}", *FLAGS, "-O2", "-fPIC",
                           "-I", INCLUDE, *defines, *extra, "-c", FIXTURES / source, "-o", output],
                          report=ledger, rejects=True)
        require(not output.exists(), f"rejected object survived: {output}")
        if code == "strict_vm":
            report = coverage_contract(json.loads(ledger.read_text(encoding="utf-8")))
            require(any(event["mechanism"] == "vm" and event["owner"] == "exchange_copy_v1" and
                        event["status"] == "skipped" for event in report["admission"]) and
                    any(event["mechanism"] == "string_plaintext_gate" and
                        event["owner"] == "exchange_copy_v1" and event["status"] == "rejected"
                        for event in report["finalization"]),
                    "strict VM budget did not retain its admission and plaintext gates")
        else:
            self.export_rejection(ledger, code)
        self.result["rejections"].append({"case": name, "exit": result.returncode,
                                           "report": str(ledger), "gate": code, "output_absent": True})
        self.save()

    def negative_builds(self):
        folder = self.work / "rejections"
        folder.mkdir()
        base = folder / "strong.yaml"
        policy(base, "exchange_copy_v1", "strong")
        cases = (("mutable-source", 1, "source_kind"), ("duplicate-id", 2, "duplicate_id"),
                 ("embedded-nul", 3, "source_bytes"), ("incompatible-prototype", 4, "accessor_abi"),
                 ("existing-body", 5, "accessor_body"), ("external-source", 6, "source_kind"),
                 ("tls-source", 7, "source_kind"), ("padded-source", 8, "source_bytes"),
                 ("unversioned-accessor", 9, "annotation_syntax"), ("shared-source", 10, "source_uses"))
        for name, number, code in cases:
            # The raw compiler must accept the declaration syntax. A frontend
            # error is not evidence that the export validator rejected it.
            self.compile(folder, f"{name}-raw", "cross-dso-string-copy-invalid.c", 2,
                         defines=[f"-DCOPY_BAD_CASE={number}"])
            self.reject_build(folder, name, "cross-dso-string-copy-invalid.c", base,
                              code=code, defines=[f"-DCOPY_BAD_CASE={number}"])
        variants = (
            ("disabled-auth", {"authenticated": False}),
            ("disabled-auth-vm", {"level": "vm", "authenticated": False}),
            ("disabled-auth-strong-vm", {"level": "strong_vm", "authenticated": False}),
            ("encoding-limit", {"limit": 0}),
            ("unsupported-strategy", {"strategy": "ctor", "ctor": False}),
            ("inline-only-strategy", {"strategy": "ctor", "ctor": False, "ephemeral": True}),
            ("disabled-encoding", {"frontend": "tinygo", "limit": 0}),
            ("unselected-none-export", {"frontend": "rust", "owner": "exchange_anchor"}),
            ("strict-vm-budget", {"level": "strong_vm", "budget": 1}),
        )
        for name, options in variants:
            config = folder / f"{name}.yaml"
            options = dict(options)
            owner = options.pop("owner", "exchange_copy_v1")
            level = options.pop("level", "strong")
            policy(config, owner, level, **options)
            self.reject_build(folder, name, "cross-dso-string-copy-invalid.c", config,
                              code="strict_vm" if name == "strict-vm-budget" else "source_strategy",
                              defines=["-DCOPY_BAD_CASE=0"])
        lto = folder / "lto-export.so"
        lto_ledger = folder / "lto-export-coverage.json"
        result = self.run([self.args.wrapper, f"--obf-config={base}", *CXX_FLAGS, "-O2", "-flto",
                           "-fPIC", "-shared", "-fuse-ld=lld", "-I", INCLUDE,
                           "-DCOPY_VARIANT=1", FIXTURES / "cross-dso-string-copy-producer.c",
                           "-o", lto], report=lto_ledger, rejects=True)
        require(not lto.exists(), "rejected LTO export image survived")
        self.export_rejection(lto_ledger, "native_route")
        self.result["rejections"].append({"case": "lto-export", "exit": result.returncode,
                                           "gate": "native_route", "report": str(lto_ledger),
                                           "output_absent": True})
        self.static_boundaries(folder)
        self.export_boundaries(folder)
        self.save()

    def static_boundaries(self, folder):
        source = "cross-dso-string-copy-static.c"
        main, _ = self.compile(folder, "static-main", source, 2)
        provider, _ = self.compile(folder, "static-provider", source, 2,
                                   defines=["-DCOPY_STATIC_PROVIDER"])
        raw_reader, _ = self.compile(folder, "static-raw-reader", source, 2,
                                     defines=["-DCOPY_STATIC_READER"])
        raw_image = folder / "static-raw-control"
        self.run([*self.raw, "-fuse-ld=lld", main, raw_reader, provider, "-o", raw_image])
        self.run([raw_image], native=True)
        strict_config = folder / "static-strict.yaml"
        policy(strict_config, "exchange_static_read", "strong_vm")
        reader, report = self.compile(folder, "static-strict-reader", source, 2,
                                       config=strict_config, defines=["-DCOPY_STATIC_READER"], report=True)
        check_report(report, "exchange_static_read", "strong_vm")
        link_config = folder / "link-none.yaml"
        policy(link_config, "absent_owner", "none")
        strict_image = folder / "static-strict-rejected"
        result = self.run([self.args.wrapper, f"--obf-config={link_config}", "-fuse-ld=lld",
                           main, reader, provider, "-o", strict_image], rejects=True)
        require_native_rejection(result)
        require(not strict_image.exists(), "strict foreign-static rejection left an image")
        self.result["rejections"].append({"case": "strict-static-import", "exit": result.returncode,
                                           "raw_control_executed": True, "output_absent": True,
                                           "report": str(report)})
        shared_provider = self.shared(provider)
        dynamic_control = folder / "static-dso-raw-control"
        runtime_path = f"-Wl,-rpath,{folder}"
        self.run([*self.raw, "-fuse-ld=lld", main, raw_reader, shared_provider,
                  runtime_path, "-o", dynamic_control])
        self.run([dynamic_control], native=True)
        dynamic_rejected = folder / "static-dso-strict-rejected"
        result = self.run([self.args.wrapper, f"--obf-config={link_config}",
                           "-fuse-ld=lld", main, reader, shared_provider,
                           runtime_path, "-o", dynamic_rejected], rejects=True)
        require_native_rejection(result)
        require(not dynamic_rejected.exists(), "strict DSO static import left an image")
        self.result["rejections"].append({"case": "strict-static-dso-import",
                                           "exit": result.returncode,
                                           "raw_control_executed": True,
                                           "output_absent": True, "report": str(report)})
        numeric_provider, _ = self.compile(folder, "numeric-provider", source, 2,
                                           defines=["-DCOPY_STATIC_NUMERIC_PROVIDER"])
        declaration = {"version": 1, "providers": [{
            "path": numeric_provider.name,
            "sha256": hashlib.sha256(numeric_provider.read_bytes()).hexdigest(),
            "definitions": [{"symbol": "foreign_copy_text", "local": False,
                             "kind": "non_string", "targets": []}]}]}
        valid_manifest = folder / "numeric-manifest.json"
        valid_manifest.write_text(json.dumps(declaration, sort_keys=True) + "\n",
                                  encoding="utf-8")
        managed_control = folder / "manifest-managed-control"
        self.run([self.args.wrapper, f"--obf-config={link_config}",
                  f"--obf-native-provenance={valid_manifest}", "-fuse-ld=lld",
                  main, reader, numeric_provider, "-o", managed_control])
        self.run([managed_control], native=True)
        declaration["providers"][0]["definitions"][0]["kind"] = "protected"
        manifest = folder / "forbidden-protected-manifest.json"
        manifest.write_text(json.dumps(declaration, sort_keys=True) + "\n",
                            encoding="utf-8")
        manifest_image = folder / "manifest-rejected"
        result = self.run([self.args.wrapper, f"--obf-config={link_config}",
                           f"--obf-native-provenance={manifest}", "-fuse-ld=lld",
                           main, reader, numeric_provider, "-o", manifest_image], rejects=True)
        require_native_rejection(result)
        require(not manifest_image.exists(), "raw protected manifest rejection left an image")
        self.result["rejections"].append({"case": "raw-manifest-protected", "exit": result.returncode,
                                           "raw_control_executed": True, "managed_control_executed": True,
                                           "output_absent": True,
                                           "manifest": str(manifest)})

    def export_fixture(self, folder, name, number, public, target, *, hops=0):
        output = folder / f"{name}.o"
        self.run([*self.raw, "-x", "assembler-with-cpp", "-fPIC",
                  f"-DCOPY_EXPORT_CASE={number}", f"-DEXPORT_NAME={public}",
                  f"-DEXPORT_TARGET={target}", f"-DCOPY_THUNK_HOPS={hops}",
                  "-c", FIXTURES / "cross-dso-string-copy-exports.S", "-o", output])
        return output

    def export_boundaries(self, folder):
        root = folder / "exports"
        root.mkdir()
        config = root / "policy.yaml"
        policy(config, "exchange_copy_v1", "strong", debug=True)
        obj, ledger = self.compile(root, "private-producer", "cross-dso-string-copy-producer.c",
                                   2, config=config, defines=["-DCOPY_VARIANT=1"], report=True)
        compiler = check_report(ledger, "exchange_copy_v1", "strong", producer=True)
        header, runtime, names, entropy = self.runtime_abi()
        decoder = names["OBF_RT_STRING_AUTH_DECODE_V3_STR"]
        anchor = names["OBF_RT_ENTROPY_ANCHOR_STR"]
        prefix_export = names["OBF_RT_ABI_PREFIX_STR"] + "fixture_export"
        profiles = [self.args.linker] if self.args.only_export_isolation else ["lld", "bfd"]
        self.result["export_profiles"] = profiles
        self.result["export_runtime"] = {
            "header": str(header), "archive": str(runtime),
            "archive_sha256": hashlib.sha256(runtime.read_bytes()).hexdigest(),
            "protected_object": str(obj),
            "protected_object_sha256": hashlib.sha256(obj.read_bytes()).hexdigest(),
            "report": str(ledger), "compiler": compiler}
        self.save()
        cases = (
            ("runtime-export", 2, prefix_export, decoder, "private-target", 0, True, False),
            ("runtime-alias", 2, "decoder_alias", decoder, "private-target", 0, True, False),
            ("runtime-e9", 3, "decoder_alias", decoder, "private-target", 1, True, False),
            ("runtime-eb", 4, "decoder_alias", decoder, "private-target", 2, True, False),
            ("runtime-mixed-chain", 5, "decoder_alias", decoder, "private-target", 3, True, False),
            ("runtime-eb-backward", 13, "decoder_alias", decoder, "private-target", 3, True, False),
            ("runtime-32-hop", 14, "decoder_alias", decoder, "private-target", 32, True, False),
            ("runtime-33-hop-boundary", 14, "decoder_alias", decoder, "private-target", 33, False, False),
            ("entropy-data-alias", 6, "entropy_data_alias", anchor, "private-target", 0, True, False),
            ("runtime-alias-stripped", 2, "decoder_alias", decoder, "private-target", 0, True, True),
            ("runtime-e9-stripped", 3, "decoder_alias", decoder, "private-target", 1, True, True),
            ("ordinary-cycle", 7, "ordinary_jump", decoder, "cycle", 1, False, False),
            ("ordinary-out-of-bounds", 8, "ordinary_jump", decoder, "unmapped", 1, False, False),
            ("ordinary-data-target", 9, "ordinary_jump", decoder, "nonexecutable", 1, False, False),
            ("ordinary-truncated-jump", 10, "ordinary_jump", decoder, "truncated", 0, False, False),
        )
        for linker in profiles:
            case_folder = root / linker
            case_folder.mkdir()
            flags = ["-shared", f"-fuse-ld={linker}", "-Wl,--no-undefined"]
            legitimate = case_folder / "legitimate.so"
            legitimate_map = legitimate.with_suffix(".map")
            self.run([self.args.wrapper, f"--obf-config={config}", *flags, obj,
                      f"-Wl,-Map,{legitimate_map}", "-o", legitimate])
            elf = ElfData(legitimate)
            metadata = elf.exports({"exchange_copy_v1"})
            metadata["entropy_symbols"] = elf.private_runtime(entropy)
            bundles = [elf.bundle(text) for text in TEXTS[0]]
            require(len({bundle["descriptor"] for bundle in bundles}) == 3 and
                    len({bundle["cache"] for bundle in bundles}) == 3 and
                    len({bundle["ciphertext"] for bundle in bundles}) == 3,
                    "export control source bundles alias each other")
            for name in (decoder, anchor, *entropy):
                elf.map_symbol_address(legitimate_map, name, linker)
            self.result["controls"].append({
                "kind": "native-export-boundary-control", "linker": linker,
                "image": str(legitimate), "native_map": str(legitimate_map),
                "elf_metadata": metadata, "private_bundles": bundles})
            self.save()
            for name, number, public, target_symbol, termination, hops, rejects, stripped in cases:
                fixture = self.export_fixture(case_folder, name, number, public, target_symbol,
                                              hops=hops)
                options = ["-s"] if stripped else []
                if number in (2, 6):
                    # BFD propagates hidden visibility through symbolic aliases.
                    # Resolve a numeric alias from a raw link with the same inputs.
                    layout = case_folder / f"{name}-layout.so"
                    layout_map = layout.with_suffix(".map")
                    self.run([*self.raw, *flags, obj, fixture, runtime, *options,
                              f"-Wl,-Map,{layout_map}", "-o", layout])
                    layout_elf = ElfData(layout, require_symbols=not stripped)
                    address = layout_elf.map_symbol_address(layout_map, target_symbol, linker)
                    options += [f"-Wl,--defsym={public}={address:#x}"]
                control = case_folder / f"{name}-raw-control.so"
                control_map = control.with_suffix(".map")
                # The raw link must resolve every dependency before a managed
                # rejection can establish the native export guard.
                self.run([*self.raw, *flags, obj, fixture, runtime, *options,
                          f"-Wl,-Map,{control_map}", "-o", control])
                raw_elf = ElfData(control, require_symbols=not stripped)
                table = raw_elf.exports({"exchange_copy_v1", public})
                target_address = raw_elf.map_symbol_address(control_map, target_symbol, linker)
                route = raw_elf.thunk_route(table["exports"][public]["address"], target_address)
                require(route["termination"] == termination and route["hops"] == hops,
                        f"raw ELF export has an incorrect route: {name}: {route}")
                require(number not in (4, 5, 13) or "eb" in route["opcodes"],
                        "short-jump control did not exercise an actual EB opcode")
                if number == 13:
                    require(any(right < left for left, right in
                                zip(route["address_path"], route["address_path"][1:])),
                            "EB backward control did not exercise a backward edge")
                if number == 6:
                    require(table["exports"][public]["type"] != 2 and
                            raw_elf.data_section(target_address, 1),
                            "entropy alias is not a non-FUNC export of actual runtime data")
                raw_elf.private_runtime(entropy)
                require(not stripped or not raw_elf.symbols,
                        "stripped control retained a private ELF .symtab")
                self.result["controls"].append({
                    "kind": "resolvable-native-export-control", "case": name, "linker": linker,
                    "stripped": stripped, "image": str(control), "fixture": str(fixture),
                    "native_map": str(control_map), "runtime_symbol": target_symbol,
                    "target_address": target_address, "export_endpoint": route,
                    "elf_metadata": table, "same_protected_object": str(obj),
                    "same_runtime_archive": str(runtime)})
                self.save()
                output = case_folder / f"{name}-managed.so"
                output_map = output.with_suffix(".map")
                result = self.run([self.args.wrapper, f"--obf-config={config}", *flags,
                                   obj, fixture, *options, f"-Wl,-Map,{output_map}", "-o", output],
                                  rejects=rejects)
                if rejects:
                    require_native_rejection(result)
                    require("private runtime export " in result.stderr,
                            "managed export did not fail through the private-runtime guard")
                    require(not output.exists(), "native export rejection left its shared library")
                    self.result["rejections"].append({
                        "case": name, "linker": linker, "stripped": stripped,
                        "exit": result.returncode, "guard": "native-final-link",
                        "raw_control": str(control), "raw_export_endpoint": route,
                        "diagnostic": result.stderr, "output_absent": True})
                else:
                    accepted = ElfData(output)
                    accepted_table = accepted.exports({"exchange_copy_v1", public})
                    accepted_target = accepted.map_symbol_address(output_map, target_symbol, linker)
                    accepted_route = accepted.thunk_route(
                        accepted_table["exports"][public]["address"], accepted_target)
                    require(accepted_route["termination"] == termination and
                            accepted_route["hops"] == hops,
                            "accepted ordinary export changed its raw control route")
                    accepted.private_runtime(entropy)
                    self.result["controls"].append({
                        "kind": "bounded-export-traversal-control", "case": name,
                        "linker": linker, "image": str(output), "native_map": str(output_map),
                        "guard_hop_limit": 32, "export_endpoint": accepted_route,
                        "elf_metadata": accepted_table})
                self.save()
            # Artifact cleanup can rename ledger helper names. Test every local
            # function in the producer's actual MAP contribution. This includes
            # every per-source helper, the keeper, and the entropy thunk.
            helpers = elf.object_functions(legitimate_map, obj, linker)
            require(len(helpers) >= len(compiler["decoder_roles"]),
                    "mapped private functions do not cover authenticated decoder roles")
            self.result["controls"].append({
                "kind": "private-helper-symbol-control", "linker": linker,
                "ledger_decoder_roles": compiler["decoder_roles"],
                "mapped_producer_local_functions": helpers})
            private_exports = [(f"helper-{index}", 11, helper["name"])
                               for index, helper in enumerate(helpers, 1)]
            private_exports += [(f"payload-{index}", 12, bundle["ciphertext_symbol"])
                                for index, bundle in enumerate(bundles, 1)]
            for kind, number, symbol in private_exports:
                name = f"private-{kind}"
                fixture = self.export_fixture(case_folder, name, number, "private_alias", symbol)
                raw_output = case_folder / f"{name}-raw-rejected.so"
                output = case_folder / f"{name}-managed-rejected.so"
                raw_result = self.run([*self.raw, *flags, obj, fixture, runtime,
                                       "-o", raw_output], rejects=True)
                result = self.run([self.args.wrapper, f"--obf-config={config}", *flags,
                                   obj, fixture, "-o", output], rejects=True)
                for rejected, image in ((raw_result, raw_output), (result, output)):
                    require(not any(line.startswith("obf-native-link:")
                                    for line in rejected.stderr.splitlines()) and
                            symbol in rejected.stderr and
                            re.search(r"undefined (?:reference|symbol)", rejected.stderr,
                                      re.IGNORECASE),
                            "private source export did not fail through the actual linker")
                    require(not image.exists(), "private source linker failure left an image")
                self.result["rejections"].append({
                    "case": name, "linker": linker, "symbol": symbol,
                    "exit": result.returncode, "raw_exit": raw_result.returncode,
                    "guard": "actual-linker-missing-private-symbol", "fixture": str(fixture),
                    "raw_diagnostic": raw_result.stderr, "diagnostic": result.stderr,
                    "output_absent": True})
                self.save()

    def matrix(self):
        if self.args.only_export_isolation:
            self.export_boundaries(self.work)
            self.result["status"] = "passed"
            self.save()
            print(f"CROSS_DSO_STRING_COPY_COMPLETE result={self.work / 'result.json'}", flush=True)
            return
        self.host = self.work / "host"
        self.run([*self.raw, "-std=c11", "-O2", "-g", FIXTURES / "cross-dso-string-copy-host.c",
                  "-fuse-ld=lld", "-pthread", "-ldl", "-o", self.host])
        for optimization in self.args.optimization:
            raw_producers, raw_consumer, incompatible, baseline = self.build_raw(optimization)
            self.concurrency(optimization, raw_producers, raw_consumer)
            for level in self.args.level:
                consumer, consumer_compiler = self.build_consumer(optimization, level)
                hybrid = self.native("semantics", *raw_producers, consumer, incompatible)
                require(hybrid == baseline, "VM consumer differs with independent raw producers")
                self.result["controls"].append({"optimization": optimization, "level": level,
                                                "kind": "raw_producers_vm_consumer", "native": hybrid})
                self.concurrency(optimization, raw_producers, consumer,
                                 consumer_level=level, consumer_compiler=consumer_compiler)
                if self.args.only_concurrency:
                    continue
                for strategy in self.args.strategy:
                    images, compilers, bundles, _ = self.build_producers(
                        optimization, strategy, raw_consumer, incompatible, baseline)
                    observed = self.native("semantics", *images, consumer, incompatible)
                    require(observed == baseline,
                            f"copy semantics changed: O{optimization} {level} {strategy}")
                    row = {"optimization": optimization, "level": level, "strategy": strategy,
                           "producers": list(map(str, images)), "consumer": str(consumer),
                           "producer_compilers": compilers, "consumer_compiler": consumer_compiler,
                           "native": observed, "freshness": []}
                    self.result["rows"].append(row)
                    self.save()
                    self.freshness(images, bundles, consumer, strategy, row["freshness"])
                    self.save()
                    print(f"CROSS_DSO_STRING_COPY_PASS O{optimization} {level} {strategy}", flush=True)
            for exporter_level in ("vm", "strong_vm"):
                for strategy in self.args.strategy:
                    images, compilers, bundles, observed = self.build_producers(
                        optimization, strategy, raw_consumer, incompatible, baseline,
                        level=exporter_level)
                    row = {"optimization": optimization, "level": exporter_level,
                           "strategy": strategy, "producers": list(map(str, images)),
                           "compiler": compilers, "native": observed, "freshness": []}
                    self.result["exporters"].append(row)
                    if not self.args.only_concurrency:
                        self.freshness(images, bundles, raw_consumer, strategy, row["freshness"])
                    for consumer_level in self.args.level:
                        consumer, consumer_compiler = self.build_consumer(optimization, consumer_level)
                        self.concurrency(optimization, images, consumer, strategy=strategy,
                                         exporter_level=exporter_level, consumer_level=consumer_level,
                                         bundles=bundles, producer_compilers=compilers,
                                         consumer_compiler=consumer_compiler)
                    self.save()
                    print(f"CROSS_DSO_STRING_COPY_EXPORTER_PASS O{optimization} "
                          f"{exporter_level} {strategy}", flush=True)
        if not self.args.skip_negatives and not self.args.only_concurrency:
            self.negative_builds()
        self.result["status"] = "passed"
        self.save()
        print(f"CROSS_DSO_STRING_COPY_COMPLETE result={self.work / 'result.json'}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wrapper", required=True)
    parser.add_argument("--clang", required=True)
    parser.add_argument("--runtime", type=Path, help="matching configured native runtime archive")
    parser.add_argument("--runtime-header", type=Path, help="configured generated runtime ABI header")
    parser.add_argument("--linker", choices=("lld", "bfd"), default="lld",
                        help="export-only filter; the default full run tests both linkers")
    parser.add_argument("--only-export-isolation", action="store_true")
    parser.add_argument("--only-concurrency", action="store_true",
                        help="run fresh concurrent native cases without corruption/export negatives")
    parser.add_argument("--work", type=Path, default=Path("/var/tmp"))
    parser.add_argument("--optimization", type=int, choices=(0, 2), action="append")
    parser.add_argument("--level", choices=("vm", "strong_vm"), action="append")
    parser.add_argument("--strategy", choices=("lazy", "ctor"), action="append")
    parser.add_argument("--tamper", choices=MUTATIONS, action="append")
    parser.add_argument("--warm-only", action="store_true")
    parser.add_argument("--skip-negatives", action="store_true")
    args = parser.parse_args()
    require(not args.only_export_isolation or not args.skip_negatives,
            "--only-export-isolation cannot combine with --skip-negatives")
    require(not args.only_export_isolation or not args.only_concurrency,
            "--only-export-isolation cannot combine with --only-concurrency")
    require(platform.system() == "Linux" and platform.machine().lower() in ("x86_64", "amd64")
            and platform.libc_ver()[0] == "glibc", "native Linux x86-64 glibc required")
    args.optimization = list(dict.fromkeys(args.optimization or [0, 2]))
    args.level = list(dict.fromkeys(args.level or ["vm", "strong_vm"]))
    args.strategy = list(dict.fromkeys(args.strategy or ["lazy", "ctor"]))
    args.tamper = list(dict.fromkeys(args.tamper or MUTATIONS))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    harness = Harness(args)
    try:
        harness.matrix()
    except Exception as error:
        harness.result.update(status="failed", error=str(error))
        harness.save()
        raise


if __name__ == "__main__":
    main()
