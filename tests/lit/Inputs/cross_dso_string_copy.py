"""Check native copy-only string exchange, VM consumers, unload, and authentication."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
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
TEXTS = ((b"amber producer A owns this copy\0", b"A: independent data 1847\0", b"\0"),
         (b"violet producer B has another payload\0", b"B: distinct data 9263\0", b"\0"))
MUTATIONS = ("cache", "tag", "ciphertext", "length", "version")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


class ElfData:
    """Read private data addresses from ELF64 symbols and native relocations."""

    def __init__(self, image):
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
        require(self.symbols, "private ELF .symtab is required for data-only corruption")
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
        cache = self.pointer(destination_ref + 8)
        ciphertext = self.pointer(ciphertext_ref + 8)
        self.private_object(destination_ref, 16)
        self.private_object(ciphertext_ref, 16)
        cache_symbol = self.private_object(cache, length)
        ciphertext_symbol = self.private_object(ciphertext, length)
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
                "length": length, "module_id": struct.unpack_from("<Q", blob, 16)[0],
                "ciphertext_sha256": hashlib.sha256(encrypted).hexdigest(),
                "targets": targets, "originals": originals}


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
        decoders = [role for role in report["roles"]
                    if role["owner"] == owner and role["role"] == "string_decoder"
                    and "authenticated_string_decode" in role["obligations"]]
        require(len({role["target"] for role in decoders}) >= 3,
                "producer sources lack independent authenticated decoder obligations")
        result.update({"authenticated_sources": 3,
                       "decoder_roles": sorted({role["target"] for role in decoders})})
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
        require(args.work.resolve().is_relative_to(Path("/tmp")),
                "scratch and evidence must stay under /tmp")
        args.work.mkdir(parents=True, exist_ok=True)
        self.work = Path(tempfile.mkdtemp(prefix="cross-dso-string-copy-", dir=args.work)).resolve()
        tempfile.tempdir = str(self.work)
        self.raw = [args.clang]
        self.result = {"status": "running", "work": str(self.work), "rows": [],
                       "controls": [], "exporters": [], "rejections": [],
                       "scope": "native Linux x86-64 glibc copy-only DSO exchange",
                       "matrix": {"optimization": args.optimization, "level": args.level,
                                  "strategy": args.strategy, "tamper": args.tamper,
                                  "cold_authentication": not args.warm_only,
                                  "rejections": not args.skip_negatives}}
        self.producers = {}
        self.save()
        print(f"CROSS_DSO_STRING_COPY_WORK {self.work}", flush=True)

    def save(self):
        (self.work / "result.json").write_text(json.dumps(self.result, indent=2) + "\n", encoding="utf-8")

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
        self.run([*driver, *FLAGS, f"-O{optimization}", "-g", "-fPIC", "-I", INCLUDE,
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
        folder = self.work / f"o{optimization}-{level}-consumer"
        folder.mkdir()
        config = folder / "policy.yaml"
        policy(config, "exchange_read_bytes", level)
        obj, report = self.compile(folder, "consumer", "cross-dso-string-copy-consumer.c",
                                   optimization, config=config, report=True)
        compiler = check_report(report, "exchange_read_bytes", level)
        return self.shared(obj, config), {"report": str(report), "outcome": compiler}

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
                   strategy=strategy, debug=level == "strong")
            obj, report = self.compile(folder, f"producer-{variant}",
                                       "cross-dso-string-copy-producer.c", optimization,
                                       config=config, defines=[f"-DCOPY_VARIANT={variant}"], report=True)
            compiler = check_report(report, "exchange_copy_v1", level, producer=True)
            image = self.shared(obj, config)
            elf = ElfData(image)
            source_bundles = [elf.bundle(text) for text in TEXTS[variant - 1]]
            (folder / f"producer-{variant}-private-data.json").write_text(
                json.dumps(source_bundles, indent=2) + "\n", encoding="utf-8")
            images.append(image)
            compilers.append({"report": str(report), "outcome": compiler})
            bundles.append(source_bundles)
        require(bundles[0][0]["ciphertext_sha256"] != bundles[1][0]["ciphertext_sha256"],
                "independent producer seeds and data produced identical ciphertext")
        observed = self.native("semantics", *images, raw_consumer, incompatible)
        require(observed == baseline, "protected producers differ from independent raw semantic oracle")
        self.result["controls"].append({"optimization": optimization, "strategy": strategy,
                                        "level": level,
                                        "kind": "protected_producers_raw_consumer", "native": observed})
        self.producers[key] = (images, compilers, bundles, observed)
        self.save()
        return self.producers[key]

    def freshness(self, images, bundles, consumer, strategy, observations):
        for variant, (image, sources) in enumerate(zip(images, bundles), 1):
            for source_id, bundle in enumerate(sources, 1):
                for mode in self.args.tamper:
                    phases = [True]
                    if strategy == "lazy" and mode != "cache" and not self.args.warm_only:
                        phases.append(False)
                    for warm in phases:
                        observed = self.native("tamper", image, consumer, variant, source_id,
                                               mode, int(warm), hex(bundle["targets"][mode]),
                                               bundle["originals"][mode], strategy, hex(bundle["cache"]))
                        require(observed["kind"] == "tamper" and observed["mode"] == mode and
                                observed["warm"] is warm and observed["variant"] == variant and
                                observed["id"] == source_id and observed["ordinary_rejections"] == 5 and
                                observed["destination_unchanged"] and observed["effect_unchanged"],
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
        result = self.run([self.args.wrapper, f"--obf-config={base}", *FLAGS, "-O2", "-flto",
                           "-fPIC", "-shared", "-fuse-ld=lld", "-I", INCLUDE,
                           "-DCOPY_VARIANT=1", FIXTURES / "cross-dso-string-copy-producer.c",
                           "-o", lto], report=lto_ledger, rejects=True)
        require(not lto.exists(), "rejected LTO export image survived")
        self.export_rejection(lto_ledger, "native_route")
        self.result["rejections"].append({"case": "lto-export", "exit": result.returncode,
                                           "gate": "native_route", "report": str(lto_ledger),
                                           "output_absent": True})
        self.static_boundaries(folder)
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

    def matrix(self):
        self.host = self.work / "host"
        self.run([*self.raw, "-std=c11", "-O2", "-g", FIXTURES / "cross-dso-string-copy-host.c",
                  "-fuse-ld=lld", "-ldl", "-o", self.host])
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
                images, compilers, bundles, observed = self.build_producers(
                    optimization, "ctor", raw_consumer, incompatible, baseline, level=exporter_level)
                row = {"optimization": optimization, "level": exporter_level,
                       "strategy": "ctor", "producers": list(map(str, images)),
                       "compiler": compilers, "native": observed, "freshness": []}
                self.result["exporters"].append(row)
                self.freshness(images, bundles, raw_consumer, "ctor", row["freshness"])
                self.save()
                print(f"CROSS_DSO_STRING_COPY_EXPORTER_PASS O{optimization} {exporter_level}", flush=True)
        if not self.args.skip_negatives:
            self.negative_builds()
        self.result["status"] = "passed"
        self.save()
        print(f"CROSS_DSO_STRING_COPY_COMPLETE result={self.work / 'result.json'}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wrapper", required=True)
    parser.add_argument("--clang", required=True)
    parser.add_argument("--work", type=Path, default=Path("/tmp"))
    parser.add_argument("--optimization", type=int, choices=(0, 2), action="append")
    parser.add_argument("--level", choices=("vm", "strong_vm"), action="append")
    parser.add_argument("--strategy", choices=("lazy", "ctor"), action="append")
    parser.add_argument("--tamper", choices=MUTATIONS, action="append")
    parser.add_argument("--warm-only", action="store_true")
    parser.add_argument("--skip-negatives", action="store_true")
    args = parser.parse_args()
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
