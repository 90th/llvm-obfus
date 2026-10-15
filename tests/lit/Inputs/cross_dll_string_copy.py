"""Check native Windows x64 authenticated copy-only DLL exchange and real unload.

Source IDs are unchanged from the ELF fixture: 1 is a file-local primary array,
2 is a C++ function-local static secondary array, and 3 is a file-local empty
array. Cold means the first application copy (CRT decoding has already run for
ctor rows). A lazy cache has no certified contents before decoding, so cache
corruption is meaningful only after a successful copy; every other lazy field
is tested both cold and warm. No application copy executes in a loader callback.

Reduced smoke: --optimization 0 --level vm --strategy lazy --tamper tag
--source-id 2 --variant 1 --skip-exporters --skip-negatives. Omit filters for the
complete O0/O2 matrix. --only-negatives isolates compiler/link boundary probes.
--only-export-isolation --linker lld (or msvc for native link.exe) isolates the
private-export raw-link/EAT controls and managed final-link rejection probes.
Full negatives always include LLD, nonincremental MSVC, and MSVC incremental
(/DEBUG /INCREMENTAL /OPT:NOREF /OPT:NOICF) export profiles. The incremental raw
alias/NONAME controls must exercise real bounded E9 chains to the V3 MAP body;
legitimate public accessor ILT thunks must remain accepted by managed linking.
All commands, compiler ledgers, private PE-data offsets, and native witnesses
remain in a fresh TEMP child; result.json records the exact requested scope.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import struct
import tempfile

from cpp_dll_abi import CXX_FLAGS
from report_contract import coverage_contract
from vm_incoming_abi import run_process

FIXTURES = Path(__file__).resolve().parent
INCLUDE = FIXTURES.parents[2] / "include"
FLAGS = (*CXX_FLAGS, "-fno-vectorize", "-fno-slp-vectorize", "-fno-unroll-loops")
C_FLAGS = ("-x", "c", "-std=c11", "-fno-inline", "-fms-runtime-lib=dll",
           "-fno-vectorize", "-fno-slp-vectorize", "-fno-unroll-loops")
TEXTS = ((b"amber producer A owns this copy\0", b"A: independent data 1847\0", b"\0"),
         (b"violet producer B has another payload\0", b"B: distinct data 9263\0", b"\0"))
MUTATIONS = ("cache", "tag", "ciphertext", "length", "version")
TRAP_CODE = 0xC000001D


def require(condition, message):
    if not condition:
        raise AssertionError(message)


class PeData:
    """Bound PE32+ data reads and exports without PDBs or exported test hooks."""

    def __init__(self, image):
        self.image = image
        self.data = image.read_bytes()
        require(len(self.data) >= 64 and self.data[:2] == b"MZ", "not a PE image")
        pe = struct.unpack_from("<I", self.data, 0x3C)[0]
        require(pe + 24 <= len(self.data) and self.data[pe:pe + 4] == b"PE\0\0",
                "invalid PE header")
        machine, count = struct.unpack_from("<HH", self.data, pe + 4)
        optional_size, characteristics = struct.unpack_from("<HH", self.data, pe + 20)
        optional = pe + 24
        require(machine == 0x8664 and characteristics & 0x2000,
                "expected native AMD64 DLL")
        require(optional_size >= 240 and optional + optional_size + count * 40 <= len(self.data)
                and struct.unpack_from("<H", self.data, optional)[0] == 0x20B,
                "expected bounded PE32+ optional header and section table")
        self.base = struct.unpack_from("<Q", self.data, optional + 24)[0]
        self.image_size = struct.unpack_from("<I", self.data, optional + 56)[0]
        require(self.base > 0 and self.image_size > 0, "invalid PE image bounds")
        self.sections = []
        for index in range(count):
            position = optional + optional_size + index * 40
            name = self.data[position:position + 8].split(b"\0", 1)[0].decode("ascii")
            virtual, rva, raw_size, raw_offset = struct.unpack_from(
                "<IIII", self.data, position + 8)
            flags = struct.unpack_from("<I", self.data, position + 36)[0]
            require(raw_offset + raw_size <= len(self.data) and
                    rva + virtual <= self.image_size, f"PE section exceeds bounds: {name}")
            self.sections.append({"name": name, "rva": rva, "size": virtual,
                                  "raw_size": raw_size, "raw_offset": raw_offset,
                                  "flags": flags})
        require(struct.unpack_from("<I", self.data, optional + 108)[0] >= 1,
                "PE data directories omit exports")
        self.export_rva, self.export_size = struct.unpack_from("<II", self.data, optional + 112)

    def section(self, rva, size, *, data_only=True):
        require(rva >= 0 and size > 0 and rva + size <= self.image_size,
                "PE RVA/size exceeds image")
        found = [section for section in self.sections
                 if section["rva"] <= rva and
                 rva + size <= section["rva"] + section["size"]]
        require(len(found) == 1, f"PE RVA has no unique bounded section: {rva:#x}+{size}")
        section = found[0]
        if data_only:
            require(section["flags"] & 0x40000000 and not section["flags"] & 0x20000000,
                    f"PE target is not readable nonexecutable data: {rva:#x}")
        return section

    def read(self, rva, size, *, raw=False, data_only=True):
        section = self.section(rva, size, data_only=data_only)
        relative = rva - section["rva"]
        available = max(0, min(size, section["raw_size"] - relative))
        require(not raw or available == size, "PE table is not completely file-backed")
        start = section["raw_offset"] + relative
        return self.data[start:start + available] + bytes(size - available)

    def pointer(self, rva):
        value = struct.unpack("<Q", self.read(rva, 8, raw=True))[0]
        if self.base <= value < self.base + self.image_size:
            result = value - self.base
        else:
            require(0 < value < self.image_size, f"unresolved private PE pointer: {value:#x}")
            result = value
        self.section(result, 1)
        return result

    def export_table(self):
        require(self.export_rva and self.export_size >= 40, "missing PE export directory")
        header = self.read(self.export_rva, 40, raw=True)
        ordinal_base, function_count, name_count, functions, names, ordinals = struct.unpack_from(
            "<IIIIII", header, 16)
        require(function_count > 0 and name_count > 0, "empty PE export table")
        functions = self.read(functions, function_count * 4, raw=True)
        names = self.read(names, name_count * 4, raw=True)
        ordinals = self.read(ordinals, name_count * 2, raw=True)
        entries = {}
        for index in range(function_count):
            address = struct.unpack_from("<I", functions, index * 4)[0]
            if not address:
                continue
            require(not self.export_rva <= address < self.export_rva + self.export_size,
                    "fixture export is a forwarder rather than an actual function")
            require(self.section(address, 1, data_only=False)["flags"] & 0x20000000,
                    "fixture exports nonexecutable data")
            entries[ordinal_base + index] = address
        exports, named_ordinals = {}, {}
        for index in range(name_count):
            name_rva = struct.unpack_from("<I", names, index * 4)[0]
            section = self.section(name_rva, 1)
            remaining = min(section["size"], section["raw_size"]) - (name_rva - section["rva"])
            require(remaining > 0, "export name has no raw storage")
            text = self.read(name_rva, remaining, raw=True)
            end = text.find(b"\0")
            require(end >= 0, "unterminated PE export name")
            name = text[:end].decode("ascii")
            index_in_table = struct.unpack_from("<H", ordinals, index * 2)[0]
            ordinal = ordinal_base + index_in_table
            require(index_in_table < function_count and ordinal in entries and name not in exports,
                    "duplicate name or invalid PE export ordinal")
            exports[name] = entries[ordinal]
            named_ordinals[name] = ordinal
        return {"named": exports, "named_ordinals": named_ordinals, "entries": entries,
                "ordinal_base": ordinal_base, "function_count": function_count}

    def exports(self, expected):
        table = self.export_table()
        require(set(table["named"]) == set(expected) and
                len(table["entries"]) == table["function_count"] == len(expected) and
                len(set(table["named_ordinals"].values())) == len(expected),
                f"exact public PE exports differ (including ordinal-only entries): {table}")
        return {"machine": "AMD64", "format": "PE32+", "exports": table["named"],
                "ordinal_only_exports": 0, "exported_private_data": False}

    def map_symbol_rva(self, path, symbol):
        native_map = path.read_text(encoding="utf-8", errors="replace")
        addresses = {int(match.group(1), 16) for match in re.finditer(
            rf"^\s*[0-9a-fA-F]{{4}}:[0-9a-fA-F]{{8,16}}\s+"
            rf"{re.escape(symbol)}\s+([0-9a-fA-F]{{8,16}})(?:\s|$)",
            native_map, re.MULTILINE)}
        require(len(addresses) == 1, f"native MAP omits unambiguous symbol address: {symbol}")
        rva = addresses.pop() - self.base
        require(self.section(rva, 1, data_only=False)["flags"] & 0x20000000,
                f"mapped symbol is not an actual executable body: {symbol}")
        self.read(rva, 1, raw=True, data_only=False)
        return rva

    def e9_endpoint(self, exported_rva, expected_body_rva):
        # MSVC incremental exports can point at ILT E9 rel32 stubs rather than
        # the actual public MAP address. Decode only that bounded opcode, never
        # arbitrary instructions or bytes outside file-backed executable ranges.
        path, visited = [], set()
        current = exported_rva
        for _ in range(64):
            require(current not in visited, "cycle in executable PE E9 export thunk chain")
            visited.add(current)
            require(self.section(current, 1, data_only=False)["flags"] & 0x20000000,
                    "export thunk chain escaped executable PE bounds")
            opcode = self.read(current, 1, raw=True, data_only=False)
            path.append(current)
            if current == expected_body_rva:
                return {"exported_rva": exported_rva, "endpoint_rva": current,
                        "rva_path": path, "e9_hops": len(path) - 1}
            require(opcode == b"\xe9",
                    "export does not reach its actual native MAP body through E9 rel32 thunks")
            instruction = self.read(current, 5, raw=True, data_only=False)
            current += 5 + struct.unpack_from("<i", instruction, 1)[0]
        raise AssertionError("excessive executable PE E9 export thunk depth")

    def bundle(self, text):
        # These are the existing private V3 runtime offsets, not a new ABI. Scan
        # only bounded file-backed nonexecutable sections; no symbol-table/PDB
        # dependency and no code-byte mutation is permitted by this harness.
        length = len(text)
        candidates = []
        for section in self.sections:
            if not section["flags"] & 0x40000000 or section["flags"] & 0x20000000:
                continue
            limit = min(section["size"], section["raw_size"])
            first = (section["rva"] + 7) & ~7
            for rva in range(first, section["rva"] + limit - 168 + 1, 8):
                blob = self.read(rva, 168, raw=True)
                version, flags, actual = struct.unpack_from("<IIQ", blob)
                if (version, flags, actual) == (3, 1, length) and struct.unpack_from(
                        "<QQQ", blob, 80) == (length, length, 32):
                    candidates.append((rva, blob))
        require(len(candidates) == 1,
                f"expected one private V3 descriptor length={length}: {self.image}")
        descriptor, blob = candidates[0]
        refs = [self.pointer(descriptor + offset) for offset in (136, 144, 152)]
        targets = [self.pointer(reference + 8) for reference in refs]
        for reference, offset in zip(refs, (48, 56, 64)):
            require(self.read(reference, 8) == blob[offset:offset + 8],
                    "private V3 reference cookie differs from descriptor")
        cache, ciphertext, key = targets
        state = self.pointer(descriptor + 160)
        require(self.read(state, 8) == blob[72:80], "private V3 state cookie differs")
        self.section(state, 24)
        cold_status, completion = struct.unpack("<QQ", self.read(state + 8, 16))
        require(cold_status == completion, "private V3 initial completion differs")
        require(self.section(cache, length)["flags"] & 0x80000000,
                "decoded cache is not writable producer data")
        require(self.read(cache, length) == bytes(length), "on-disk cache contains plaintext")
        encrypted = self.read(ciphertext, length)
        build_key = self.read(key, 32)
        require(length == 1 or encrypted != text, "ciphertext retained producer plaintext")
        require(build_key != bytes(32), "private build key is empty")
        mutations = {"cache": cache, "tag": descriptor + 120, "ciphertext": ciphertext,
                     "length": descriptor + 8, "version": descriptor}
        originals = {mode: text[0] if mode == "cache" else self.read(target, 1)[0]
                     for mode, target in mutations.items()}
        return {"descriptor": descriptor, "cache": cache, "ciphertext": ciphertext,
                "build_key": key, "state": state, "length": length,
                "cold_status": cold_status,
                "module_id": struct.unpack_from("<Q", blob, 16)[0],
                "ciphertext_sha256": hashlib.sha256(encrypted).hexdigest(),
                "build_key_sha256": hashlib.sha256(build_key).hexdigest(),
                "targets": mutations, "originals": originals,
                "sections": {name: self.section(address, size)["name"]
                             for name, address, size in (("descriptor", descriptor, 168),
                                                       ("cache", cache, length),
                                                       ("ciphertext", ciphertext, length),
                                                       ("build_key", key, 32))}}


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
    require(path.is_file(), f"missing compiler ledger: {path}")
    report = coverage_contract(json.loads(path.read_text(encoding="utf-8")))
    require(report["capture"] == "enabled", "compiler ledger not captured")
    selected = [event["policy"] for event in report["requested_policy"]
                if event["owner"] == owner and event["phase"] == "selected"]
    require(len(selected) == 1 and selected[0]["level"] == level,
            f"requested policy changed for {owner}")
    result = {"level": level}
    if producer:
        # Ctor encoding can rewrite zero ordinary reads. Emitted encoding,
        # authenticated roles/bindings/finalizers, and private V3 descriptor
        # inspection establish protection independently of rewritten-use count.
        require(any(event["owner"] == owner and event["mechanism"] == "string_encoding"
                    and event["status"] == "emitted"
                    for event in report["emission"]), "producer emitted no string encoding")
        decoders = {role["target"] for role in report["roles"]
                    if role["owner"] == owner and role["role"] == "string_decoder"
                    and "authenticated_string_decode" in role["obligations"]}
        require(len(decoders) >= 3, "producer lacks three authenticated decoder obligations")
        for phase, status in (("emission", "generated"), ("emission", "bound"),
                              ("finalization", "validated")):
            events = [event for event in report[phase] if event["owner"] == owner
                      and event["mechanism"] == "string_copy_export" and event["status"] == status]
            ids = {int(match.group(1)) for event in events
                   for match in [re.search(r"(?:^|, )id=(\d+)(?:,|$)", event["reason"])]
                   if match}
            require(len(events) == 3 and ids == {1, 2, 3},
                    f"copy-export ledger lost exact source binding at {phase}/{status}")
        result.update(authenticated_sources=3, decoder_roles=sorted(decoders),
                      source_ids=[1, 2, 3], export_finalizer="validated")
    if not producer or level in ("vm", "strong_vm"):
        require(selected[0]["allow_vm"], "selected byte-reader/exporter lost VM eligibility")
        require(any(event["owner"] == owner and event["mechanism"] == "vm" and
                    event["scope"] == "whole_function" and event["status"] == "admitted"
                    for event in report["admission"]), "whole-function VM was not admitted")
        require(any(event["owner"] == owner and event["mechanism"] == "vm" and
                    event["scope"] == "whole_function" and event["status"] == "emitted" and
                    event["count"] > 0 for event in report["emission"]),
                "whole-function VM was not emitted")
        result["vm_exporter" if producer else "vm_consumer"] = "whole_function"
    require(any(event["mechanism"] == "security_gates" and event["status"] == "validated"
                for event in report["finalization"]), "compiler security gates did not validate")
    return result


def require_native_rejection(result):
    require(result.returncode == 2 and any(line.startswith("obf-native-link:")
                                          for line in result.stderr.splitlines()),
            "rejection did not come from native final-link validation")


class Harness:
    def __init__(self, args):
        self.args = args
        parent = args.work.resolve()
        temp = Path(tempfile.gettempdir()).resolve()
        require(parent.is_relative_to(temp), "scratch/evidence must stay under native TEMP")
        parent.mkdir(parents=True, exist_ok=True)
        self.work = Path(tempfile.mkdtemp(prefix="xcdll-", dir=parent)).resolve()
        self.raw = [args.clang, "--driver-mode=g++"]
        self.producers = {}
        self.category = "setup"
        self.result = {"status": "running", "work": str(self.work), "rows": [],
                       "controls": [], "exporters": [], "rejections": [],
                       "scope": "native Windows x64 MSVC PE/COFF copy-only DLL exchange",
                       "sources": {"1": "file-local primary", "2": "C++ local-static secondary",
                                   "3": "file-local empty"},
                       "matrix": {"optimization": args.optimization, "level": args.level,
                                  "strategy": args.strategy, "tamper": args.tamper,
                                  "source_id": args.source_id, "variant": args.variant,
                                  "cold_authentication": not args.warm_only,
                                  "freshness": not args.skip_freshness,
                                  "exporters": not args.skip_exporters,
                                  "exporter_level": args.exporter_level,
                                  "rejections": not args.skip_negatives,
                                  "only_export_isolation": args.only_export_isolation,
                                  "export_linker_filter": args.linker if args.only_export_isolation else None,
                                  "only_negatives": args.only_negatives},
                       "unsupported_phases": [{"strategy": "lazy", "mode": "cache",
                                               "warm": False,
                                               "reason": "uncertified zero cache is overwritten by first decode"}]}
        self.save()
        print(f"CROSS_DLL_STRING_COPY_WORK {self.work}", flush=True)

    def save(self):
        (self.work / "result.json").write_text(json.dumps(self.result, indent=2) + "\n",
                                                encoding="utf-8")

    def run(self, command, *, report=None, native=False, rejects=False):
        command = [str(value) for value in command]
        environment = {key: value for key, value in os.environ.items()
                       if not key.upper().startswith("OBF_")}
        environment.update(TMPDIR=str(self.work), TMP=str(self.work), TEMP=str(self.work))
        if report is not None:
            environment["OBF_COVERAGE_REPORT"] = str(report)
        record = {"category": self.category, "command": command,
                  "report": str(report) if report else None}
        try:
            result = run_process(command, cwd=self.work, env=environment,
                                 timeout=40 if native else 300)
            record.update(exit=result.returncode, stdout=result.stdout, stderr=result.stderr)
        except BaseException as error:
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
        observed = json.loads(self.run([self.host, *arguments], native=True).stdout)
        require(observed.get("ok") is True, f"missing native outcome: {observed}")
        return observed

    def compile(self, folder, name, source, optimization, *, config=None, defines=(),
                report=False, extra=()):
        obj = folder / f"{name}.obj"
        ledger = folder / f"{name}-coverage.json" if report else None
        driver = [self.args.wrapper, f"--obf-config={config}"] if config else self.raw
        flags = C_FLAGS if str(source).endswith(".c") else FLAGS
        self.run([*driver, *flags, f"-O{optimization}", "-g", "-I", INCLUDE,
                  *defines, *extra, "-c", FIXTURES / source, "-o", obj], report=ledger)
        return obj, ledger

    def shared(self, obj, config=None, *, exports=None):
        image = obj.with_suffix(".dll")
        driver = [self.args.wrapper, f"--obf-config={config}"] if config else self.raw
        self.run([*driver, *CXX_FLAGS, "-shared", "-fuse-ld=lld", obj,
                  f"-Wl,/implib:{obj.with_suffix('.lib')}",
                  f"-Wl,/map:{obj.with_suffix('.map')}", "-o", image])
        require(image.is_file(), "native shared link produced no DLL")
        metadata = PeData(image).exports(exports) if exports else None
        require(not list(obj.parent.glob("*.def")), "ordinary fixture link introduced a .def file")
        return image, metadata

    def build_raw(self, optimization):
        self.category = f"O{optimization}/raw"
        folder = self.work / f"o{optimization}-raw"
        folder.mkdir()
        producers, metadata = [], []
        for variant in (1, 2):
            obj, _ = self.compile(folder, f"producer-{variant}", "cross-dll-string-copy-raw.cpp",
                                  optimization, defines=[f"-DCOPY_VARIANT={variant}"])
            image, pe = self.shared(obj, exports={"exchange_copy_v1"})
            producers.append(image)
            metadata.append(pe)
        obj, _ = self.compile(folder, "consumer", "cross-dll-string-copy-consumer.cpp", optimization)
        consumer, consumer_pe = self.shared(obj, exports={"exchange_read_bytes"})
        obj, _ = self.compile(folder, "v2-only", "cross-dll-string-copy-raw.cpp", optimization,
                              defines=["-DCOPY_VARIANT=1", "-DCOPY_V2_ONLY"])
        incompatible, incompatible_pe = self.shared(obj, exports={"exchange_copy_v2"})
        observed = self.native("semantics", *producers, consumer, incompatible)
        self.result["controls"].append({"optimization": optimization, "kind": "independent_raw",
                                        "producers": list(map(str, producers)),
                                        "consumer": str(consumer), "incompatible": str(incompatible),
                                        "pe_metadata": metadata + [consumer_pe, incompatible_pe],
                                        "native": observed})
        self.save()
        return producers, consumer, incompatible, observed

    def build_consumer(self, optimization, level):
        self.category = f"O{optimization}/{level}/consumer"
        folder = self.work / f"o{optimization}-{level}-consumer"
        folder.mkdir()
        config = folder / "policy.yaml"
        policy(config, "exchange_read_bytes", level)
        obj, report = self.compile(folder, "consumer", "cross-dll-string-copy-consumer.cpp",
                                   optimization, config=config, report=True)
        compiler = check_report(report, "exchange_read_bytes", level)
        image, metadata = self.shared(obj, config, exports={"exchange_read_bytes"})
        return image, {"report": str(report), "outcome": compiler, "pe_metadata": metadata}

    def build_producers(self, optimization, strategy, raw_consumer, incompatible,
                        baseline, *, level="strong"):
        key = (optimization, strategy, level)
        if key in self.producers:
            return self.producers[key]
        self.category = f"O{optimization}/{level}/{strategy}/producers"
        folder = self.work / f"o{optimization}-{strategy}-{level}-producers"
        folder.mkdir()
        images, compilers, bundles = [], [], []
        for variant in (1, 2):
            config = folder / f"producer-{variant}.yaml"
            policy(config, "exchange_copy_v1", level, seed=8675309 + variant * 104729,
                   strategy=strategy, debug=level == "strong", ctor=strategy != "lazy")
            obj, report = self.compile(folder, f"producer-{variant}",
                                       "cross-dll-string-copy-producer.cpp", optimization,
                                       config=config, defines=[f"-DCOPY_VARIANT={variant}"], report=True)
            compiler = check_report(report, "exchange_copy_v1", level, producer=True)
            image, metadata = self.shared(obj, config, exports={"exchange_copy_v1"})
            pe = PeData(image)
            source_bundles = [pe.bundle(text) for text in TEXTS[variant - 1]]
            require(len({bundle["descriptor"] for bundle in source_bundles}) == 3 and
                    len({bundle["cache"] for bundle in source_bundles}) == 3 and
                    len({bundle["ciphertext"] for bundle in source_bundles}) == 3,
                    "producer source descriptors/cache/ciphertext alias each other")
            private_data = folder / f"producer-{variant}-private-data.json"
            private_data.write_text(json.dumps(source_bundles, indent=2) + "\n", encoding="utf-8")
            images.append(image)
            compilers.append({"report": str(report), "outcome": compiler,
                              "pe_metadata": metadata, "private_data": str(private_data)})
            bundles.append(source_bundles)
        for source in range(3):
            require(bundles[0][source]["build_key_sha256"] != bundles[1][source]["build_key_sha256"],
                    "independent producer keys are identical")
            # A one-byte empty-string ciphertext can collide across independent
            # keys. Distinct nonempty data and every key are the useful proof.
            if source != 2:
                require(bundles[0][source]["ciphertext_sha256"] !=
                        bundles[1][source]["ciphertext_sha256"],
                        "independent producer nonempty ciphertext data are identical")
        observed = self.native("semantics", *images, raw_consumer, incompatible)
        require(observed == baseline, "protected producers differ from independent raw oracle")
        self.result["controls"].append({"optimization": optimization, "strategy": strategy,
                                        "level": level, "kind": "protected_producers_raw_consumer",
                                        "native": observed, "independent_keys_and_data": True})
        self.producers[key] = (images, compilers, bundles, observed)
        self.save()
        return self.producers[key]

    def freshness(self, images, bundles, consumer, strategy, observations):
        if self.args.skip_freshness:
            return
        for variant, (image, sources) in enumerate(zip(images, bundles), 1):
            if variant not in self.args.variant:
                continue
            for source_id, bundle in enumerate(sources, 1):
                if source_id not in self.args.source_id:
                    continue
                for mode in self.args.tamper:
                    phases = [True]
                    if not self.args.warm_only and (strategy == "ctor" or mode != "cache"):
                        phases.append(False)
                    for warm in phases:
                        observed = self.native("tamper", image, consumer, variant, source_id,
                                               mode, int(warm), hex(bundle["targets"][mode]),
                                               bundle["originals"][mode], strategy,
                                               hex(bundle["cache"]), hex(bundle["state"]),
                                               hex(bundle["cold_status"]))
                        require(observed["kind"] == "tamper" and observed["mode"] == mode and
                                observed["warm"] is warm and observed["variant"] == variant and
                                observed["id"] == source_id and observed["ordinary_rejections"] == 5 and
                                observed["exception_code"] == TRAP_CODE and observed["stage"] == 3 and
                                observed["destination_unchanged"] and observed["effect_unchanged"] and
                                observed["required"] == bundle["length"] and
                                observed["lazy_state_checked"] is (strategy == "lazy"),
                                "missing exact native trap or metadata non-certification evidence")
                        observations.append(observed)
                        self.save()

    def export_rejection(self, ledger, code):
        require(ledger.is_file(), "rejected export has no compiler ledger")
        report = coverage_contract(json.loads(ledger.read_text(encoding="utf-8")))
        require(any(event["mechanism"] == "string_copy_export" and
                    event["status"] == "rejected" and
                    event["reason"].partition(",")[0] == f"code={code}"
                    for event in report["finalization"]),
                f"export did not reject through expected finalizer gate: {code}")

    def reject_build(self, folder, name, source, config, *, code, defines=(), extra=()):
        output = folder / f"{name}.obj"
        ledger = folder / f"{name}-coverage.json"
        result = self.run([self.args.wrapper, f"--obf-config={config}", *C_FLAGS, "-O2",
                           "-I", INCLUDE, *defines, *extra, "-c", FIXTURES / source,
                           "-o", output], report=ledger, rejects=True)
        require(not output.exists(), f"rejected object survived: {output}")
        if code == "strict_vm":
            report = coverage_contract(json.loads(ledger.read_text(encoding="utf-8")))
            require(any(event["mechanism"] == "vm" and event["owner"] == "exchange_copy_v1" and
                        event["status"] == "skipped" for event in report["admission"]) and
                    any(event["mechanism"] == "string_plaintext_gate" and
                        event["owner"] == "exchange_copy_v1" and event["status"] == "rejected"
                        for event in report["finalization"]),
                    "strict VM budget lost its admission and plaintext gates")
        else:
            self.export_rejection(ledger, code)
        self.result["rejections"].append({"case": name, "exit": result.returncode,
                                          "report": str(ledger), "gate": code,
                                          "output_absent": True})
        self.save()

    def negative_builds(self):
        self.category = "compiler-rejections"
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
            self.compile(folder, f"{name}-raw", "cross-dso-string-copy-invalid.c", 2,
                         defines=[f"-DCOPY_BAD_CASE={number}"])
            self.reject_build(folder, name, "cross-dso-string-copy-invalid.c", base,
                              code=code, defines=[f"-DCOPY_BAD_CASE={number}"])
        for name, number, code in (("dllimport-accessor", 1, "accessor_abi"),
                                   ("dllexport-source", 2, "source_kind")):
            self.compile(folder, f"{name}-raw", "cross-dll-string-copy-invalid.c", 2,
                         defines=[f"-DCOPY_PE_BAD_CASE={number}"])
            self.reject_build(folder, name, "cross-dll-string-copy-invalid.c", base,
                              code=code, defines=[f"-DCOPY_PE_BAD_CASE={number}"])
        for name, target in (("windows-gnu", "x86_64-w64-windows-gnu"),
                             ("windows-x86", "i686-pc-windows-msvc")):
            extra = [f"--target={target}"]
            self.compile(folder, f"{name}-raw", "cross-dll-string-copy-invalid.c", 2,
                         defines=["-DCOPY_PE_BAD_CASE=0"], extra=extra)
            self.reject_build(folder, name, "cross-dll-string-copy-invalid.c", base,
                              code="binding", defines=["-DCOPY_PE_BAD_CASE=0"], extra=extra)
        variants = (("disabled-auth", {"authenticated": False}),
                    ("disabled-auth-vm", {"level": "vm", "authenticated": False}),
                    ("disabled-auth-strong-vm", {"level": "strong_vm", "authenticated": False}),
                    ("encoding-limit", {"limit": 0}),
                    ("unsupported-strategy", {"strategy": "ctor", "ctor": False}),
                    ("inline-only-strategy", {"strategy": "ctor", "ctor": False, "ephemeral": True}),
                    ("disabled-encoding", {"frontend": "tinygo", "limit": 0}),
                    ("unselected-none-export", {"frontend": "rust", "owner": "exchange_anchor"}),
                    ("strict-vm-budget", {"level": "strong_vm", "budget": 1}))
        for name, options in variants:
            config = folder / f"{name}.yaml"
            options = dict(options)
            owner = options.pop("owner", "exchange_copy_v1")
            level = options.pop("level", "strong")
            policy(config, owner, level, **options)
            self.reject_build(folder, name, "cross-dso-string-copy-invalid.c", config,
                              code="strict_vm" if name == "strict-vm-budget" else "source_strategy",
                              defines=["-DCOPY_BAD_CASE=0"])
        # PE LTO is rejected by wrapper preflight, before compiler invocation;
        # it therefore has no string-copy finalizer ledger. Prove valid input
        # syntax with a raw LTO frontend and a protected native-route control,
        # then vary only the managed LTO route and check wrapper-origin failure.
        raw_lto, _ = self.compile(folder, "lto-raw", "cross-dll-string-copy-producer.cpp",
                                  2, defines=["-DCOPY_VARIANT=1"], extra=["-flto"])
        with raw_lto.open("rb") as stream:
            magic = stream.read(4)
        require(magic in (b"BC\xc0\xde", b"\xde\xc0\x17\x0b"),
                "raw PE LTO frontend control did not emit LLVM bitcode")
        native_obj, native_ledger = self.compile(
            folder, "lto-native", "cross-dll-string-copy-producer.cpp", 2,
            config=base, defines=["-DCOPY_VARIANT=1"], report=True)
        native_compiler = check_report(native_ledger, "exchange_copy_v1", "strong", producer=True)
        native_image, native_metadata = self.shared(native_obj, base, exports={"exchange_copy_v1"})
        pe = PeData(native_image)
        native_bundles = [pe.bundle(text) for text in TEXTS[0]]
        self.result["controls"].append({
            "kind": "pe-lto-input-controls", "raw_lto_object": str(raw_lto),
            "raw_bitcode_magic": magic.hex(), "native_image": str(native_image),
            "native_report": str(native_ledger), "native_compiler": native_compiler,
            "pe_metadata": native_metadata, "private_v3_descriptors": native_bundles})
        self.save()
        lto = folder / "lto-export.dll"
        ledger = folder / "lto-export-coverage.json"
        result = self.run([self.args.wrapper, f"--obf-config={base}", *FLAGS, "-O2", "-flto",
                           "-shared", "-fuse-ld=lld", "-I", INCLUDE, "-DCOPY_VARIANT=1",
                           FIXTURES / "cross-dll-string-copy-producer.cpp", "-o", lto],
                          report=ledger, rejects=True)
        require(result.returncode == 2 and any(line.startswith("obf-clang:")
                                               for line in result.stderr.splitlines()),
                "PE LTO rejection did not originate from wrapper preflight")
        require(not lto.exists(), "wrapper-rejected PE LTO export left a DLL")
        require(not ledger.exists(), "PE LTO wrapper preflight unexpectedly produced a compiler ledger")
        self.result["rejections"].append({
            "case": "lto-export", "exit": result.returncode, "gate": "pe-lto-wrapper",
            "raw_frontend_control": str(raw_lto), "native_control": str(native_image),
            "compiler_report_created": False, "output_absent": True})
        self.static_boundaries()
        self.export_boundaries(folder)
        self.save()

    def static_boundaries(self):
        self.category = "native-ownership-rejections"
        # Keep real linker paths short even when the retained matrix is large.
        # Descriptive case names remain in result.json and command categories.
        folder = self.work / "own"
        folder.mkdir()
        source = "cross-dll-string-copy-static.c"
        main, _ = self.compile(folder, "main", source, 2)
        provider, _ = self.compile(folder, "text", source, 2,
                                   defines=["-DCOPY_STATIC_PROVIDER"])
        raw_reader, _ = self.compile(folder, "raw", source, 2,
                                     defines=["-DCOPY_STATIC_READER"])
        raw_image = folder / "s-raw.exe"
        link_flags = ["-fms-runtime-lib=dll", "-fuse-ld=lld"]
        self.run([*self.raw, *link_flags, main, raw_reader, provider, "-o", raw_image])
        self.run([raw_image], native=True)
        strict = folder / "s.yaml"
        policy(strict, "exchange_static_read", "strong_vm")
        reader, report = self.compile(folder, "vm", source, 2,
                                       config=strict, defines=["-DCOPY_STATIC_READER"], report=True)
        check_report(report, "exchange_static_read", "strong_vm")
        none = folder / "n.yaml"
        policy(none, "absent_owner", "none")
        strict_image = folder / "s-no.exe"
        result = self.run([self.args.wrapper, f"--obf-config={none}", *link_flags,
                           main, reader, provider, "-o", strict_image], rejects=True)
        require_native_rejection(result)
        require(not strict_image.exists(), "strict foreign-static rejection left an EXE")
        self.result["rejections"].append({"case": "strict-static-import", "exit": result.returncode,
                                          "raw_control_executed": True, "output_absent": True,
                                          "report": str(report)})
        dll_provider, _ = self.compile(folder, "dll", source, 2,
                                       defines=["-DCOPY_STATIC_PROVIDER", "-DCOPY_DLL_EXPORT"])
        dll, _ = self.shared(dll_provider)
        import_library = dll.with_suffix(".lib")
        imported_raw, _ = self.compile(folder, "imp", source, 2,
                                       defines=["-DCOPY_STATIC_READER", "-DCOPY_DLL_IMPORT"])
        dynamic_control = folder / "d-raw.exe"
        self.run([*self.raw, *link_flags, main, imported_raw, import_library,
                  "-o", dynamic_control])
        self.run([dynamic_control], native=True)
        imported, imported_report = self.compile(
            folder, "ivm", source, 2, config=strict,
            defines=["-DCOPY_STATIC_READER", "-DCOPY_DLL_IMPORT"], report=True)
        check_report(imported_report, "exchange_static_read", "strong_vm")
        # Like native_string_ownership.py, the rejection must use exactly the
        # protected reader/provider set that first links and runs without the
        # native gate. A separate raw reader alone cannot establish that.
        runtime = (self.args.runtime or
                   Path(self.args.wrapper).parent / "libobf_runtime.a").resolve()
        require(runtime.is_file(), "matching runtime archive unavailable: pass --runtime")
        dynamic_vm_control = folder / "d-vm.exe"
        self.run([*self.raw, *link_flags, main, imported, import_library,
                  runtime, "-o", dynamic_vm_control])
        self.run([dynamic_vm_control], native=True)
        dynamic_rejected = folder / "d-no.exe"
        result = self.run([self.args.wrapper, f"--obf-config={none}", *link_flags,
                           main, imported, import_library, "-o", dynamic_rejected], rejects=True)
        require_native_rejection(result)
        require(not dynamic_rejected.exists(), "strict DLL foreign-data import left an EXE")
        self.result["rejections"].append({"case": "strict-static-dll-import",
                                          "exit": result.returncode, "raw_control_executed": True,
                                          "protected_reader_raw_link_executed": True,
                                          "protected_reader_raw_image": str(dynamic_vm_control),
                                          "binding": "COFF-IAT-pointer-cell",
                                          "static_dependency": "__imp_foreign_copy_text",
                                          "output_absent": True, "report": str(imported_report)})
        numeric, _ = self.compile(folder, "num", source, 2,
                                  defines=["-DCOPY_STATIC_NUMERIC_PROVIDER"])
        declaration = {"version": 1, "providers": [{"path": numeric.name,
                       "sha256": hashlib.sha256(numeric.read_bytes()).hexdigest(),
                       "definitions": [{"symbol": "foreign_copy_text", "local": False,
                                        "kind": "non_string", "targets": []}]}]}
        valid = folder / "n.json"
        valid.write_text(json.dumps(declaration, sort_keys=True) + "\n", encoding="utf-8")
        managed_control = folder / "m-ok.exe"
        self.run([self.args.wrapper, f"--obf-config={none}",
                  f"--obf-native-provenance={valid}", *link_flags, main, reader,
                  numeric, "-o", managed_control])
        self.run([managed_control], native=True)
        declaration["providers"][0]["definitions"][0]["kind"] = "protected"
        forbidden = folder / "p.json"
        forbidden.write_text(json.dumps(declaration, sort_keys=True) + "\n", encoding="utf-8")
        rejected = folder / "m-no.exe"
        result = self.run([self.args.wrapper, f"--obf-config={none}",
                           f"--obf-native-provenance={forbidden}", *link_flags,
                           main, reader, numeric, "-o", rejected], rejects=True)
        require_native_rejection(result)
        require(not rejected.exists(), "raw protected-manifest rejection left an EXE")
        self.result["rejections"].append({"case": "raw-manifest-protected",
                                          "exit": result.returncode, "raw_control_executed": True,
                                          "managed_control_executed": True, "output_absent": True,
                                          "manifest": str(forbidden)})
        self.save()

    def export_boundaries(self, folder):
        self.category = "native-export-rejections"
        root = folder / "exports"
        root.mkdir()
        config = root / "policy.yaml"
        policy(config, "exchange_copy_v1", "strong", debug=True)
        obj, ledger = self.compile(root, "private-producer", "cross-dll-string-copy-producer.cpp",
                                    2, config=config, defines=["-DCOPY_VARIANT=1"], report=True)
        compiler = check_report(ledger, "exchange_copy_v1", "strong", producer=True)
        headers = ([self.args.runtime_header] if self.args.runtime_header else
                   [Path(self.args.wrapper).parent / "include/obf/support/runtime_abi_generated.h",
                    Path(self.args.wrapper).parent.parent / "include/obf/support/runtime_abi_generated.h"])
        header = next((path for path in headers if path.is_file()), None)
        require(header is not None,
                "runtime ABI header unavailable: pass --runtime-header with installed generated header")
        match = re.search(r'^#define\s+OBF_RT_STRING_AUTH_DECODE_V3_STR\s+"([^"\r\n]+)"',
                          header.read_text(encoding="utf-8"), re.MULTILINE)
        require(match is not None, "generated header omits actual V3 runtime ABI symbol")
        runtime_symbol = match.group(1)
        # The build config places this exact archive beside both native wrapper
        # launchers. An explicit path supports relocated installations, without
        # searching for a different runtime or inspecting wrapper source text.
        runtime = (self.args.runtime or
                   Path(self.args.wrapper).parent / "libobf_runtime.a").resolve()
        require(runtime.is_file(), "matching runtime archive unavailable: pass --runtime")
        helpers = compiler["decoder_roles"]
        report = coverage_contract(json.loads(ledger.read_text(encoding="utf-8")))
        sources = sorted({event["target"] for event in report["finalization"]
                          if event["mechanism"] == "string_copy_export" and
                          event["status"] == "validated"})
        require(helpers and sources, "compiler ledger omits private helper/data names")
        profiles = [("lld-nonincremental", "lld", False),
                    ("msvc-nonincremental", "msvc", False),
                    ("msvc-incremental", "msvc", True)]
        if self.args.only_export_isolation:
            profiles = [profile for profile in profiles if profile[1] == self.args.linker]
        self.result["export_profiles"] = [profile[0] for profile in profiles]
        self.save()
        for profile, linker, incremental in profiles:
            self.category = f"native-export-rejections/{profile}"
            case = root / profile
            case.mkdir()
            selected_linker = "link" if linker == "msvc" else "lld"
            link_flags = [*CXX_FLAGS, "-shared", f"-fuse-ld={selected_linker}"]
            if incremental:
                # This is a permanent regression row, not an optional workaround:
                # the raw export must exercise the actual MSVC incremental ILT.
                link_flags += ["-Wl,/DEBUG", "-Wl,/INCREMENTAL",
                               "-Wl,/OPT:NOREF", "-Wl,/OPT:NOICF"]
            else:
                link_flags += ["-Wl,/INCREMENTAL:NO"]
            image = case / "legitimate.dll"
            image_map = image.with_suffix(".map")
            self.run([self.args.wrapper, f"--obf-config={config}", *link_flags, obj,
                      f"-Wl,/map:{image_map}", "-o", image])
            legitimate = PeData(image)
            metadata = legitimate.exports({"exchange_copy_v1"})
            accessor_rva = legitimate.map_symbol_rva(image_map, "exchange_copy_v1")
            public_endpoint = legitimate.e9_endpoint(
                metadata["exports"]["exchange_copy_v1"], accessor_rva)
            require(not incremental or public_endpoint["e9_hops"] > 0,
                    "MSVC incremental legitimate accessor did not exercise an accepted ILT thunk")
            self.result["controls"].append({
                "kind": "native-export-boundary-control", "image": str(image),
                "profile": profile, "linker": linker, "incremental": incremental,
                "pe_metadata": metadata, "public_accessor_endpoint": public_endpoint,
                "native_map": str(image_map), "report": str(ledger),
                "runtime_header": str(header), "runtime_archive": str(runtime),
                "runtime_sha256": hashlib.sha256(runtime.read_bytes()).hexdigest()})
            self.save()
            for name, definition, public_name in (
                    ("runtime-export", None, runtime_symbol),
                    ("runtime-alias", f"EXPORTS\n  public_alias={runtime_symbol}\n", "public_alias"),
                    ("runtime-ordinal-only",
                     f"EXPORTS\n  ordinal_alias={runtime_symbol} @7 NONAME\n", None)):
                target = case / f"{name}.dll"
                if definition is None:
                    options = [f"-Wl,/EXPORT:{runtime_symbol}"]
                    def_file = None
                else:
                    def_file = case / f"{name}.def"
                    def_file.write_text(definition, encoding="utf-8")
                    options = [f"-Wl,/DEF:{def_file}"]
                # Same protected object and matching runtime, with a real raw
                # link before every rejection probe. EAT -> bounded E9 chain ->
                # actual native MAP body is the oracle, not diagnostic wording.
                control = case / f"{name}-raw-control.dll"
                control_map = control.with_suffix(".map")
                self.run([*self.raw, *link_flags, obj, runtime, *options,
                          f"-Wl,/map:{control_map}", "-o", control])
                pe = PeData(control)
                table = pe.export_table()
                decoder_rva = pe.map_symbol_rva(control_map, runtime_symbol)
                require(len(table["entries"]) == 2,
                        "raw export control lost its accessor or added unrelated exports")
                if public_name is None:
                    require(set(table["named"]) == {"exchange_copy_v1"} and
                            7 in table["entries"] and 7 not in table["named_ordinals"].values(),
                            "raw NONAME control omitted ordinal 7 or unexpectedly named it")
                    exported_rva = table["entries"][7]
                else:
                    require(set(table["named"]) == {"exchange_copy_v1", public_name} and
                            len(set(table["named_ordinals"].values())) == 2,
                            "raw named/alias control has incorrect export identity")
                    exported_rva = table["named"][public_name]
                endpoint = pe.e9_endpoint(exported_rva, decoder_rva)
                if incremental and name in ("runtime-alias", "runtime-ordinal-only"):
                    require(endpoint["e9_hops"] > 0,
                            "MSVC alias/NONAME control did not exercise actual incremental E9 indirection")
                self.result["controls"].append({
                    "kind": "resolvable-private-runtime-export", "case": name,
                    "profile": profile, "linker": linker, "incremental": incremental,
                    "image": str(control), "native_map": str(control_map),
                    "runtime_symbol": runtime_symbol, "decoder_rva": decoder_rva,
                    "export_endpoint": endpoint, "pe_export_table": table})
                self.save()
                result = self.run([self.args.wrapper, f"--obf-config={config}", *link_flags,
                                   obj, *options, "-o", target], rejects=True)
                require_native_rejection(result)
                require(not target.exists(), "private runtime export rejection left primary DLL")
                self.result["rejections"].append({
                    "case": name, "exit": result.returncode, "profile": profile,
                    "linker": linker, "incremental": incremental,
                    "runtime_symbol": runtime_symbol, "raw_control": str(control),
                    "raw_control_eat_reaches_decoder": True, "raw_export_endpoint": endpoint,
                    "definition": str(def_file) if def_file else None,
                    "guard": "native-final-link", "output_absent": True})
                self.save()
            # Per-source helpers and payloads remain private even with debug
            # names. The successful paired raw controls exclude missing runtime
            # dependencies; adding only the private-symbol .def must fail in
            # both real linker routes, before any native export validation.
            for kind, symbol in (("helper", helpers[0]), ("data", sources[0])):
                definition = case / f"private-{kind}.def"
                definition.write_text(f'EXPORTS\n  private_alias="{symbol}"\n', encoding="utf-8")
                target = case / f"private-{kind}-export.dll"
                raw_target = case / f"private-{kind}-raw-rejected.dll"
                options = [f"-Wl,/DEF:{definition}"]
                raw_result = self.run([*self.raw, *link_flags, obj, runtime, *options,
                                       "-o", raw_target], rejects=True)
                require(not raw_target.exists(), "raw private-symbol rejection left a DLL")
                result = self.run([self.args.wrapper, f"--obf-config={config}", *link_flags,
                                   obj, *options, "-o", target], rejects=True)
                require(not any(line.startswith("obf-native-link:")
                                for line in result.stderr.splitlines()),
                        "private per-source export was not rejected by the actual linker")
                require(not target.exists(), "private per-source export failure left a DLL")
                self.result["rejections"].append({
                    "case": f"private-{kind}-def-export", "exit": result.returncode,
                    "raw_exit": raw_result.returncode, "profile": profile,
                    "linker": linker, "incremental": incremental,
                    "symbol": symbol, "guard": "actual-linker-missing-private-symbol",
                    "definition": str(definition), "output_absent": True})
                self.save()

    def matrix(self):
        if self.args.only_export_isolation:
            self.export_boundaries(self.work)
            self.result["status"] = "passed"
            self.save()
            print(f"CROSS_DLL_STRING_COPY_COMPLETE result={self.work / 'result.json'}", flush=True)
            return
        if not self.args.only_negatives:
            self.host = self.work / "host.exe"
            self.category = "host"
            self.run([*self.raw, *FLAGS, "-O2", "-g", "-fuse-ld=lld",
                      FIXTURES / "cross-dll-string-copy-host.cpp", "-o", self.host])
            for optimization in self.args.optimization:
                raw_producers, raw_consumer, incompatible, baseline = self.build_raw(optimization)
                for level in self.args.level:
                    consumer, consumer_compiler = self.build_consumer(optimization, level)
                    hybrid = self.native("semantics", *raw_producers, consumer, incompatible)
                    require(hybrid == baseline, "VM consumer differs with independent raw producers")
                    self.result["controls"].append({"optimization": optimization, "level": level,
                                                    "kind": "raw_producers_vm_consumer", "native": hybrid})
                    for strategy in self.args.strategy:
                        images, compilers, bundles, _ = self.build_producers(
                            optimization, strategy, raw_consumer, incompatible, baseline)
                        self.category = f"O{optimization}/{level}/{strategy}/exchange"
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
                        print(f"CROSS_DLL_STRING_COPY_PASS O{optimization} {level} {strategy}", flush=True)
                if not self.args.skip_exporters:
                    for level in self.args.exporter_level:
                        for strategy in self.args.strategy:
                            images, compilers, bundles, observed = self.build_producers(
                                optimization, strategy, raw_consumer, incompatible, baseline,
                                level=level)
                            self.category = f"O{optimization}/{level}/{strategy}/exporter"
                            row = {"optimization": optimization, "level": level, "strategy": strategy,
                                   "producers": list(map(str, images)), "compiler": compilers,
                                   "native": observed, "freshness": []}
                            self.result["exporters"].append(row)
                            self.save()
                            self.freshness(images, bundles, raw_consumer, strategy, row["freshness"])
                            print(f"CROSS_DLL_STRING_COPY_EXPORTER_PASS O{optimization} "
                                  f"{level} {strategy}", flush=True)
        if not self.args.skip_negatives:
            self.negative_builds()
        self.result["status"] = "passed"
        self.save()
        print(f"CROSS_DLL_STRING_COPY_COMPLETE result={self.work / 'result.json'}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--wrapper", required=True, help="native obf-clang++ launcher")
    parser.add_argument("--clang", required=True, help="canonical Clang executable")
    parser.add_argument("--runtime-header", type=Path, help="installed generated runtime ABI header")
    parser.add_argument("--runtime", type=Path, help="matching configured native runtime archive")
    parser.add_argument("--linker", choices=("lld", "msvc"), default="lld",
                        help="linker filter for --only-export-isolation; full negatives test lld and msvc")
    parser.add_argument("--work", type=Path, default=Path(tempfile.gettempdir()))
    parser.add_argument("--optimization", type=int, choices=(0, 2), action="append")
    parser.add_argument("--level", choices=("vm", "strong_vm"), action="append")
    parser.add_argument("--strategy", choices=("lazy", "ctor"), action="append")
    parser.add_argument("--tamper", choices=MUTATIONS, action="append")
    parser.add_argument("--source-id", type=int, choices=(1, 2, 3), action="append")
    parser.add_argument("--variant", type=int, choices=(1, 2), action="append")
    parser.add_argument("--exporter-level", choices=("vm", "strong_vm"), action="append")
    parser.add_argument("--warm-only", action="store_true")
    parser.add_argument("--skip-freshness", action="store_true")
    parser.add_argument("--skip-exporters", action="store_true")
    parser.add_argument("--skip-negatives", action="store_true")
    parser.add_argument("--only-negatives", action="store_true")
    parser.add_argument("--only-export-isolation", action="store_true",
                        help="run only native private-export raw controls and managed rejection probes")
    args = parser.parse_args()
    require(os.name == "nt" and platform.machine().lower() in ("x86_64", "amd64"),
            "native Windows x64 required")
    require(not (args.only_negatives and args.skip_negatives), "negative-only and skip-negatives conflict")
    require(not (args.only_export_isolation and (args.only_negatives or args.skip_negatives)),
            "export-isolation-only conflicts with negative-only/skip-negatives")
    for name, default in (("optimization", [0, 2]), ("level", ["vm", "strong_vm"]),
                          ("strategy", ["lazy", "ctor"]), ("tamper", MUTATIONS),
                          ("source_id", [1, 2, 3]), ("variant", [1, 2]),
                          ("exporter_level", ["vm", "strong_vm"])):
        setattr(args, name, list(dict.fromkeys(getattr(args, name) or default)))
    args.wrapper = str(Path(args.wrapper).resolve())
    args.clang = str(Path(args.clang).resolve())
    harness = Harness(args)
    try:
        harness.matrix()
    except BaseException as error:
        harness.result.update(status="failed", error=str(error))
        harness.save()
        raise


if __name__ == "__main__":
    main()
