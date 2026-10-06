"""Check native static-data ownership with real compiler and linker outcomes."""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import tempfile

from report_contract import coverage_contract
from vm_incoming_abi import run_process


KINDS = {"direct": 0, "cell": 1, "table": 2, "integer": 3, "unused": 4,
         "integer-cell": 5, "integer-chain": 6, "matrix": 7, "struct": 8,
         "indexed-direct": 9}
VALUES = {
    "direct": [110] * 6,
    "cell": [110, 65, 84, 110, 65, 84],
    "table": [110, 65, 84, 83, 69, 67],
    "integer": [110, 110, 110, 78, 78, 78],
    "integer-cell": [110, 110, 110, 78, 78, 78],
    "integer-chain": [110, 110, 110, 78, 78, 78],
    "matrix": [110, 78, 110, 31, 47, 31],
    "struct": [110, 110, 110, 78, 78, 78],
    "indexed-numeric": [110, 78, 12, 110, 78, 12],
    "indexed-plaintext": [110, 83, 84, 110, 83, 84],
    "local-primary-plaintext": [110, 83, 84, 110, 78, 12],
    "local-aux-plaintext": [110, 78, 12, 110, 83, 84],
}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def definition(symbol, kind, *, local=False, targets=()):
    return {"symbol": symbol, "local": local, "kind": kind, "targets": list(targets)}


def definitions(kind):
    if kind == "direct":
        return [definition("audit_direct", "plaintext")]
    if kind == "integer":
        return [definition("audit_integers", "non_string")]
    if kind in {"integer-cell", "integer-chain"}:
        result = [definition("audit_leaf_numbers", "non_string", local=True),
                  definition("audit_integer_cell", "forward", local=kind == "integer-chain",
                             targets=[{"symbol": "audit_leaf_numbers", "local": True}])]
        if kind == "integer-chain":
            result.append(definition("audit_integer_chain", "forward", targets=[
                {"symbol": "audit_integer_cell", "local": True}]))
        return result
    target = {"symbol": "audit_secret", "local": True}
    result = [definition("audit_secret", "plaintext", local=True)]
    if kind == "cell":
        result.append(definition("audit_cell", "forward", targets=[target]))
    else:
        result += [definition("audit_second", "plaintext", local=True),
                   definition("audit_table", "forward", targets=[
                       target, {"symbol": "audit_second", "local": True}])]
    return result


class Harness:
    def __init__(self, args, work, language, optimization, reports):
        self.args = args
        self.work = work
        self.language = language
        self.optimization = optimization
        self.reports = reports
        self.serial = 0
        self.results = []
        self.wrapper = args.wrapperxx if language == "c++" else args.wrapper
        self.raw = [args.clang] + (["--driver-mode=g++"] if language == "c++" else [])
        self.flags = ["-x", language, f"-O{optimization}", "-fno-inline"]
        self.flags += ["-std=c++17"] if language == "c++" else ["-std=c11"]
        if args.format == "coff":
            self.flags += ["-fms-runtime-lib=dll"]
        else:
            self.flags += ["-fPIC"]
        self.none = self.policy("none", "none")
        self.strong = self.policy("strong", "strong_vm")
        self.vm = self.policy("vm", "vm")
        self.main = self.compile("consumer", "consumer.c", "integer", managed=False)

    def policy(self, name, level, *, owners=("audit_read", "audit_runtime")):
        path = self.work / f"{name}.yaml"
        lines = ["seed: 8675309", "default_level: none", "targets:"]
        for owner in owners:
            lines += [f"  - match: {owner}", f"    level: {level}"]
        lines += ["vm:", "  max_mba_depth: 0", "self_checksum:", "  enabled: false",
                  "security:", "  fail_on_public_obf_symbol: true"]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def run(self, command, *, succeeds=True, compile_report=False, env_updates=None):
        self.serial += 1
        env = {key: value for key, value in os.environ.items() if not key.upper().startswith("OBF_")}
        report = self.work / f"coverage-{self.serial}.json" if compile_report and self.reports else None
        if report:
            env["OBF_COVERAGE_REPORT"] = str(report)
        if env_updates:
            env.update(env_updates)
        result = run_process([str(value) for value in command],
                             cwd=self.work, env=env, timeout=300)
        with (self.work / "commands.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"command": [str(value) for value in command],
                                     "exit": result.returncode, "stdout": result.stdout,
                                     "stderr": result.stderr,
                                     "report": str(report) if report else None}) + "\n")
        if report and report.exists():
            coverage_contract(json.loads(report.read_text(encoding="utf-8")))
        if succeeds is not None:
            require((result.returncode == 0) == succeeds,
                    f"unexpected exit {result.returncode}: {command!r}\n"
                    f"{result.stdout}\n{result.stderr}")
        return result

    def compile(self, name, source, kind, *, managed=True, policy=None, extra=(), succeeds=True):
        obj = self.work / (name + (".obj" if self.args.format == "coff" else ".o"))
        driver = [self.wrapper, f"--obf-config={policy or self.none}"] if managed else self.raw
        result = self.run([*driver, *self.flags, f"-DAUDIT_KIND={KINDS[kind]}", *extra,
                           "-c", self.work / source, "-o", obj],
                          succeeds=succeeds, compile_report=managed)
        return (obj, result) if succeeds is None else obj

    def archive(self, name, members):
        path = self.work / (name + (".lib" if self.args.format == "coff" else ".a"))
        self.run([self.args.ar, "rcs", path, *members])
        return path

    def manifest(self, name, entries):
        path = self.work / f"{name}.json"
        path.write_text(json.dumps({"version": 1, "providers": entries}, sort_keys=True) + "\n",
                        encoding="utf-8")
        return path

    def provider(self, obj, records, *, archive=None):
        result = {"path": (archive or obj).name,
                  "sha256": hashlib.sha256(obj.read_bytes()).hexdigest(),
                  "definitions": records}
        if archive:
            result["member"] = obj.name
        return result

    def link(self, name, inputs, linker, *, managed=True, manifest=None, succeeds=True, extra=()):
        image = self.work / (name + (".exe" if self.args.format == "coff" else ""))
        map_path = self.work / f"{name}.map"
        flags = [f"-fuse-ld={linker}"]
        if self.args.format == "coff":
            flags += ["-fms-runtime-lib=dll", f"-Wl,/map:{map_path}"]
        else:
            flags += [f"-Wl,-Map,{map_path},--cref"]
        if managed:
            driver = [self.wrapper, f"--obf-config={self.none}"]
            if manifest:
                driver.append(f"--obf-native-provenance={manifest}")
            runtime = []
        else:
            driver = self.raw
            runtime = [self.args.runtime]
        self.run([*driver, *flags, self.main, *inputs, *runtime, "-o", image, *extra], succeeds=succeeds)
        if not succeeds:
            require(not image.exists(), f"rejected native image survived: {image}")
        return image, map_path

    def partial_link(self, name, inputs, linker, *, managed=True, action="-r",
                     selected=(), unused=()):
        obj = self.work / f"{name}.o"
        map_path = self.work / f"{name}.map"
        driver = [self.wrapper, f"--obf-config={self.none}"] if managed else self.raw
        self.run([*driver, f"-fuse-ld={linker}", action, "-nostdlib", "-no-pie",
                  f"-Wl,-Map,{map_path},--cref", *inputs, "-o", obj])
        require(obj.is_file(), f"partial linker did not produce its object: {obj}")
        self.map_members(map_path, selected=selected, unused=unused)
        return obj

    def execute(self, image, kind):
        data = json.loads(self.run([image]).stdout)
        require(data == {"values": VALUES[kind], "effects": VALUES[kind],
                         "runtime": [110, 78, 78], "runtime_effects": [110, 78, 78]},
                f"wrong native return/effect values: {image}: {data}")

    def map_members(self, map_path, *, selected=(), unused=()):
        text = map_path.read_text(encoding="utf-8", errors="replace").lower()
        for member in selected:
            require(member.name.lower() in text, f"actual linker did not extract {member}: {map_path}")
        for member in unused:
            require(member.name.lower() not in text, f"actual linker extracted unused {member}: {map_path}")

    def outcome(self, name, inputs, kind, *, accepts, manifest=None, selected=(), unused=(),
                linkers=None):
        for linker in (self.args.linker if linkers is None else linkers):
            stem = f"{name}-{linker}"
            # The same protected reader and provider set must link and run without
            # the ownership validator before a rejection counts as an outcome.
            baseline, baseline_map = self.link(stem + "-raw-link", inputs, linker, managed=False)
            self.execute(baseline, kind)
            self.map_members(baseline_map, selected=selected, unused=unused)
            image, user_map = self.link(stem + "-wrapped", inputs, linker,
                                        manifest=manifest, succeeds=accepts)
            if accepts:
                self.execute(image, kind)
                self.map_members(user_map, selected=selected, unused=unused)
            self.results.append({"case": name, "linker": linker,
                                 "accepted": accepts, "baseline_execution": True})

    def same_tu_rejection(self, kind):
        raw = self.compile(f"same-{kind}-raw", "reader.c", kind, managed=False,
                           extra=["-DAUDIT_SAME_TU"])
        for linker in self.args.linker:
            image, _ = self.link(f"same-{kind}-{linker}-baseline", [raw], linker, managed=False)
            self.execute(image, kind)
        obj, result = self.compile(f"same-{kind}-strong", "reader.c", kind, policy=self.strong,
                                   extra=["-DAUDIT_SAME_TU"], succeeds=None)
        if result.returncode == 0:
            for linker in self.args.linker:
                self.link(f"same-{kind}-{linker}-rejected", [obj], linker, succeeds=False)
        self.results.append({"case": f"same-{kind}", "accepted": False,
                             "rejection_stage": "compile" if result.returncode else "link"})

    def core(self):
        direct = self.compile("same-direct-strong", "reader.c", "direct", policy=self.strong,
                              extra=["-DAUDIT_SAME_TU", "-DAUDIT_LOCAL_DIRECT"])
        self.outcome("same-direct", [direct], "direct", accepts=True)
        # A combined job exercises temporary frontend objects inside the proxy.
        for linker in self.args.linker:
            image = self.work / (f"combined-direct-{linker}" +
                                 (".exe" if self.args.format == "coff" else ""))
            self.run([self.wrapper, f"--obf-config={self.strong}", *self.flags,
                      "-DAUDIT_KIND=0", "-DAUDIT_SAME_TU", "-DAUDIT_LOCAL_DIRECT",
                      self.work / "reader.c",
                      self.work / "consumer.c", f"-fuse-ld={linker}", "-o", image],
                     compile_report=True)
            self.execute(image, "direct")
        reader = self.compile("split-direct-strong", "reader.c", "direct", policy=self.strong)
        provider = self.compile("split-direct-provider", "provider.c", "direct")
        self.outcome("managed-direct-plaintext", [reader, provider], "direct", accepts=False)
        for linker in self.args.linker:
            image = self.work / (f"combined-split-direct-{linker}" +
                                 (".exe" if self.args.format == "coff" else ""))
            self.run([self.wrapper, f"--obf-config={self.strong}", *self.flags,
                      "-DAUDIT_KIND=0", self.work / "reader.c", "-x", "none",
                      self.main, provider, f"-fuse-ld={linker}", "-o", image],
                     succeeds=False, compile_report=True)
            require(not image.exists(), f"rejected combined native image survived: {image}")

    def boundaries(self):
        direct_reader = self.compile("direct-raw-reader", "reader.c", "direct", policy=self.strong)
        direct_raw = self.compile("direct-raw-provider", "provider.c", "direct", managed=False)
        self.outcome("raw-direct-missing", [direct_reader, direct_raw], "direct", accepts=False)
        direct_manifest = self.manifest("raw-direct-plaintext", [
            self.provider(direct_raw, definitions("direct"))])
        self.outcome("raw-direct-plaintext", [direct_reader, direct_raw], "direct",
                     accepts=False, manifest=direct_manifest)
        direct_archive = self.archive("raw-direct-archive", [direct_raw])
        archive_manifest = self.manifest("raw-direct-archive", [
            self.provider(direct_raw, definitions("direct"), archive=direct_archive)])
        self.outcome("raw-direct-extracted", [direct_reader, direct_archive], "direct",
                     accepts=False, manifest=archive_manifest, selected=[direct_raw])
        for kind in ("cell", "table"):
            self.same_tu_rejection(kind)
            reader = self.compile(f"{kind}-strong", "reader.c", kind, policy=self.strong)
            managed = self.compile(f"{kind}-managed-provider", "provider.c", kind)
            raw = self.compile(f"{kind}-raw-provider", "provider.c", kind, managed=False)
            self.outcome(f"managed-{kind}-plaintext", [reader, managed], kind, accepts=False)
            self.outcome(f"raw-{kind}-missing", [reader, raw], kind, accepts=False)
            manifest = self.manifest(f"raw-{kind}-forward", [self.provider(raw, definitions(kind))])
            self.outcome(f"raw-{kind}-forward", [reader, raw], kind,
                         accepts=False, manifest=manifest)
            missing_leaf = [record for record in definitions(kind) if not record["local"]]
            missing_leaf_manifest = self.manifest(f"raw-{kind}-missing-leaf", [
                self.provider(raw, missing_leaf)])
            self.outcome(f"raw-{kind}-missing-leaf", [reader, raw], kind,
                         accepts=False, manifest=missing_leaf_manifest)
            archive = self.archive(f"{kind}-managed-archive", [managed])
            self.outcome(f"extracted-{kind}", [reader, archive], kind,
                         accepts=False, selected=[managed])
            ordinary = self.compile(f"{kind}-ordinary-vm", "reader.c", kind, policy=self.vm)
            self.outcome(f"ordinary-vm-{kind}", [ordinary, raw], kind, accepts=True)
        self.integer_and_manifests()
        self.prevailing()
        self.partial_links()
        self.bounded_forwarding()
        self.local_reader_authority()
        self.cleanup_output()
        self.numeric_aggregates()

    def integer_and_manifests(self):
        reader = self.compile("integer-strong", "reader.c", "integer", policy=self.strong)
        managed = self.compile("integer-managed", "provider.c", "integer")
        raw = self.compile("integer-raw", "provider.c", "integer", managed=False)
        self.outcome("managed-integer", [reader, managed], "integer", accepts=True)
        self.outcome("raw-integer-missing", [reader, raw], "integer", accepts=False)
        self.outcome("raw-integer-missing-manifest-file", [reader, raw], "integer",
                     accepts=False, manifest=self.work / "absent-manifest.json")
        entry = self.provider(raw, definitions("integer"))
        valid = self.manifest("integer-valid", [entry])
        self.outcome("raw-integer-classified", [reader, raw], "integer", accepts=True, manifest=valid)
        variants = {}
        mismatch = copy.deepcopy(entry)
        mismatch["sha256"] = "0" * 64
        variants["hash-mismatch"] = [mismatch]
        missing = copy.deepcopy(entry)
        missing["definitions"] = []
        variants["missing-definition"] = [missing]
        unknown = copy.deepcopy(entry)
        unknown["definitions"] = [definition("audit_integers", "unknown")]
        variants["unknown"] = [unknown]
        conflict = copy.deepcopy(entry)
        conflict["definitions"] = [definition("audit_integers", "unknown")]
        variants["conflicting-raw"] = [entry, conflict]
        protected = copy.deepcopy(entry)
        protected["definitions"] = [definition("audit_integers", "protected")]
        variants["forbidden-protected"] = [protected]
        wrong_symbol = copy.deepcopy(entry)
        wrong_symbol["definitions"] = [definition("audit_absent", "non_string")]
        variants["absent-symbol"] = [wrong_symbol]
        for name, entries in variants.items():
            manifest = self.manifest("integer-" + name, entries)
            self.outcome("integer-" + name, [reader, raw], "integer", accepts=False, manifest=manifest)
        malformed = self.work / "integer-malformed.json"
        malformed.write_text('{"version":1,"providers":[', encoding="utf-8")
        self.outcome("integer-malformed", [reader, raw], "integer", accepts=False, manifest=malformed)
        managed_conflict = self.manifest("integer-managed-conflict", [
            self.provider(managed, [definition("audit_integers", "unknown")])])
        self.outcome("integer-managed-conflict", [reader, managed], "integer",
                     accepts=False, manifest=managed_conflict)
        bad = self.compile("integer-bad-record", "provider.c", "integer", managed=False,
                           extra=["-DAUDIT_BAD_RECORD"])
        bad_manifest = self.manifest("integer-bad-record", [self.provider(bad, definitions("integer"))])
        self.outcome("integer-malformed-object-record", [reader, bad], "integer",
                     accepts=False, manifest=bad_manifest)
        unused = self.compile("unused-plaintext", "provider.c", "unused")
        archive = self.archive("managed-integer-and-unused", [managed, unused])
        self.outcome("managed-unused-member", [reader, archive], "integer",
                     accepts=True, selected=[managed], unused=[unused])
        raw_unused = self.compile("raw-unused-plaintext", "provider.c", "unused", managed=False)
        raw_archive = self.archive("raw-integer-and-unused", [raw, raw_unused])
        ignored = self.provider(raw_unused, [])
        ignored["sha256"] = "0" * 64
        ignored["definitions"] = False
        archive_manifest = self.manifest("raw-archive", [
            self.provider(raw, definitions("integer"), archive=raw_archive),
            {**ignored, "path": raw_archive.name, "member": raw_unused.name}])
        self.outcome("raw-archive-classified-unused-ignored", [reader, raw_archive], "integer",
                     accepts=True, manifest=archive_manifest, selected=[raw], unused=[raw_unused])
        self.outcome("raw-archive-missing", [reader, raw_archive], "integer",
                     accepts=False, selected=[raw], unused=[raw_unused])
        wrong_member = self.provider(raw, definitions("integer"), archive=raw_archive)
        wrong_member["member"] = raw_unused.name
        wrong_member_manifest = self.manifest("raw-archive-wrong-member", [wrong_member])
        self.outcome("raw-archive-wrong-member", [reader, raw_archive], "integer",
                     accepts=False, manifest=wrong_member_manifest, selected=[raw], unused=[raw_unused])

    def prevailing(self):
        reader = self.compile("prevailing-reader", "reader.c", "direct", policy=self.strong,
                              extra=["-DAUDIT_CALL_FORCE"])
        for binary_strong in (True, False):
            label = "strong-binary" if binary_strong else "strong-string"
            weak_flags = ["-DAUDIT_WEAK", "-DAUDIT_FORCE"]
            strong_flags = []
            (strong_flags if binary_strong else weak_flags).append("-DAUDIT_BINARY")
            weak = self.compile(label + "-weak", "provider.c", "direct", extra=weak_flags)
            strong = self.compile(label + "-strong", "provider.c", "direct", extra=strong_flags)
            self.outcome(label + "-objects", [reader, weak, strong], "direct", accepts=binary_strong)
            unused = self.compile(label + "-unused", "provider.c", "unused")
            archive = self.archive(label + "-archive", [weak, unused])
            self.outcome(label + "-archive", [reader, strong, archive], "direct", accepts=binary_strong,
                         selected=[weak], unused=[unused])

    def partial_links(self):
        if self.args.format != "elf":
            return
        for kind, accepts in (("direct", False), ("integer", True)):
            reader = self.compile(f"partial-{kind}-reader", "reader.c", kind, policy=self.strong)
            provider = self.compile(f"partial-{kind}-provider", "provider.c", kind)
            for linker in self.args.linker:
                partial = self.work / f"partial-{kind}-{linker}.o"
                self.run([self.wrapper, f"--obf-config={self.none}", f"-fuse-ld={linker}",
                          "-r", "-nostdlib", reader, provider, "-o", partial])
                image, _ = self.link(f"partial-{kind}-{linker}-final", [partial], linker,
                                     succeeds=accepts)
                if accepts:
                    self.execute(image, kind)
                self.results.append({"case": f"partial-{kind}", "linker": linker,
                                     "accepted": accepts})

    def partial(self):
        reader = self.compile("partial-indexed-reader", "reader.c", "indexed-direct",
                              policy=self.strong)
        ordinary = {
            "vm": self.compile("partial-indexed-vm", "reader.c", "indexed-direct", policy=self.vm),
            "none": self.compile("partial-indexed-none", "reader.c", "indexed-direct"),
        }
        unused = self.compile("partial-unselected-provider", "provider.c", "unused")
        providers = {}
        for binary_strong in (True, False):
            label = "numeric-winner" if binary_strong else "plaintext-winner"
            weak_flags = ["-DAUDIT_WEAK"]
            strong_flags = []
            (strong_flags if binary_strong else weak_flags).append("-DAUDIT_BINARY")
            providers[binary_strong] = (
                self.compile(f"partial-{label}-weak", "provider.c", "indexed-direct",
                             extra=weak_flags),
                self.compile(f"partial-{label}-strong", "provider.c", "indexed-direct",
                             extra=strong_flags),
            )
        for linker in self.args.linker:
            reconciled = {}
            unresolved = self.partial_link(f"partial-unresolved-{linker}", [reader], linker)
            for binary_strong, (weak, strong) in providers.items():
                label = "numeric-winner" if binary_strong else "plaintext-winner"
                profile = "indexed-numeric" if binary_strong else "indexed-plaintext"
                for included in (False, True):
                    for reverse in (False, True):
                        stem = (f"partial-{label}-{linker}-"
                                f"{'included' if included else 'providers'}-"
                                f"{'strong-first' if reverse else 'weak-first'}")
                        inputs = [strong, weak] if reverse else [weak, strong]
                        if included:
                            inputs = [reader, *inputs]
                        obj = self.partial_link(stem, inputs, linker)
                        final_inputs = [obj] if included else [reader, obj]
                        self.outcome(stem, final_inputs, profile, accepts=binary_strong,
                                     linkers=[linker])
                        if not included and not reverse:
                            reconciled[binary_strong] = obj

                # The first partial has an unresolved global dependency, or only
                # a weak provider. A later job must still choose the real winner.
                self.outcome(f"partial-unresolved-final-{label}-{linker}",
                             [unresolved, strong], profile, accepts=binary_strong,
                             linkers=[linker])
                first = self.partial_link(f"partial-late-first-{label}-{linker}",
                                          [reader, weak], linker)
                self.outcome(f"partial-late-final-{label}-{linker}", [first, strong],
                             profile, accepts=binary_strong, linkers=[linker])
                second = self.partial_link(f"partial-late-second-{label}-{linker}",
                                           [first, strong], linker,
                                           action="-Wl,-i" if linker == "bfd" else "-r")
                third = self.partial_link(f"partial-late-third-{label}-{linker}",
                                          [second, unused], linker, action="-Wl,--relocatable")
                self.outcome(f"partial-repeated-{label}-{linker}", [third], profile,
                             accepts=binary_strong, linkers=[linker])
                self.partial_archives(reader, unused, binary_strong, linker)

            for level, ordinary_reader in ordinary.items():
                obj = self.partial_link(f"partial-{level}-plaintext-{linker}",
                                        [ordinary_reader, reconciled[False]], linker)
                self.outcome(f"partial-{level}-plaintext-{linker}", [obj], "indexed-plaintext",
                             accepts=True, linkers=[linker])
            self.partial_manifest_boundaries(reader, reconciled[True], unresolved, linker)
            self.partial_raw_boundaries(reader, ordinary, providers[True],
                                        reconciled[True], unused, linker)
            self.partial_local_scopes(linker)

    def partial_archives(self, reader, unused, binary_strong, linker):
        label = "numeric-winner" if binary_strong else "plaintext-winner"
        stem = f"partial-archive-{label}-{linker}"
        weak_flags = ["-DAUDIT_WEAK", "-DAUDIT_FORCE"]
        strong_flags = ["-DAUDIT_PULL_FORCE"]
        (strong_flags if binary_strong else weak_flags).append("-DAUDIT_BINARY")
        weak = self.compile(stem + "-weak", "provider.c", "indexed-direct", extra=weak_flags)
        strong = self.compile(stem + "-strong", "provider.c", "indexed-direct", extra=strong_flags)
        archive = self.archive(stem + "-inputs", [weak, unused])
        profile = "indexed-numeric" if binary_strong else "indexed-plaintext"
        for included in (False, True):
            name = stem + ("-included" if included else "-providers")
            inputs = [strong, archive]
            if included:
                inputs.insert(0, reader)
            obj = self.partial_link(name, inputs, linker, selected=[weak], unused=[unused])
            self.outcome(name, [obj] if included else [reader, obj], profile,
                         accepts=binary_strong, linkers=[linker])
            if not included:
                final_archive = self.archive(stem + "-final-inputs", [obj, unused])
                self.outcome(stem + "-final-extraction", [reader, final_archive], profile,
                             accepts=binary_strong, selected=[obj], unused=[unused],
                             linkers=[linker])

    def partial_manifest_boundaries(self, reader, obj, reader_partial, linker):
        valid = self.manifest(f"partial-managed-truthful-{linker}", [
            self.provider(obj, [definition("audit_direct", "non_string")])])
        self.outcome(f"partial-managed-truthful-{linker}", [reader, obj], "indexed-numeric",
                     accepts=True, manifest=valid, linkers=[linker])
        conflict = self.manifest(f"partial-managed-conflict-{linker}", [
            self.provider(obj, [definition("audit_direct", "plaintext")])])
        self.outcome(f"partial-managed-conflict-{linker}", [reader, obj], "indexed-numeric",
                     accepts=False, manifest=conflict, linkers=[linker])
        raw = self.compile(f"partial-raw-manifest-provider-{linker}", "provider.c", "indexed-direct",
                           managed=False, extra=["-DAUDIT_BINARY"])
        raw_entry = self.provider(raw, [definition("audit_direct", "non_string")])
        raw_valid = self.manifest(f"partial-raw-truthful-{linker}", [raw_entry])
        self.outcome(f"partial-raw-truthful-{linker}", [reader_partial, raw], "indexed-numeric",
                     accepts=True, manifest=raw_valid, linkers=[linker])
        raw_conflict = self.manifest(f"partial-raw-conflict-{linker}", [
            raw_entry, self.provider(raw, [definition("audit_direct", "unknown")])])
        self.outcome(f"partial-raw-conflict-{linker}", [reader_partial, raw], "indexed-numeric",
                     accepts=False, manifest=raw_conflict, linkers=[linker])

    def partial_raw_boundaries(self, reader, ordinary, providers, reconciled, unused, linker):
        weak, strong = providers
        raw = self.partial_link(f"partial-raw-multi-{linker}", [weak, strong], linker,
                                managed=False)
        raw_included = self.partial_link(f"partial-raw-included-{linker}",
                                         [reader, weak, strong], linker, managed=False)
        stale = self.partial_link(f"partial-raw-stale-{linker}", [reconciled, unused], linker,
                                  managed=False)
        for label, obj, included in (("multi-v1", raw, False),
                                     ("included-v1", raw_included, True),
                                     ("stale-v2", stale, False)):
            stem = f"partial-unresolved-{label}-{linker}"
            inputs = [obj] if included else [reader, obj]
            self.outcome(stem, inputs, "indexed-numeric", accepts=False, linkers=[linker])
            rewrapped = self.partial_link(stem + "-rewrapped", inputs, linker)
            self.outcome(stem + "-rewrapped", [rewrapped], "indexed-numeric",
                         accepts=False, linkers=[linker])
            truthful = self.manifest(stem + "-truthful", [
                self.provider(obj, [definition("audit_direct", "non_string")])])
            self.outcome(stem + "-truthful", inputs, "indexed-numeric",
                         accepts=False, manifest=truthful, linkers=[linker])
            rewrapped_manifest = self.manifest(stem + "-rewrapped-truthful", [
                self.provider(rewrapped, [definition("audit_direct", "non_string")])])
            self.outcome(stem + "-rewrapped-truthful", [rewrapped], "indexed-numeric",
                         accepts=False, manifest=rewrapped_manifest, linkers=[linker])

        # Collections without a mandatory reader keep their best-effort behavior.
        for label, obj in (("multi-v1", raw), ("stale-v2", stale)):
            for level, ordinary_reader in ordinary.items():
                stem = f"partial-unresolved-{label}-{level}-{linker}"
                self.outcome(stem, [ordinary_reader, obj], "indexed-numeric",
                             accepts=True, linkers=[linker])
                rewrapped = self.partial_link(stem + "-rewrapped", [ordinary_reader, obj], linker)
                self.outcome(stem + "-rewrapped", [rewrapped], "indexed-numeric",
                             accepts=True, linkers=[linker])

    def partial_local_scopes(self, linker):
        numeric_reader = self.compile(f"partial-local-leaf-numeric-reader-{linker}",
                                      "reader.c", "integer-cell", policy=self.strong)
        plaintext_reader = self.compile(f"partial-local-leaf-plaintext-reader-{linker}",
                                        "reader.c", "cell", policy=self.strong)
        local_policy = self.policy(f"partial-local-policy-{linker}", "strong_vm",
                                   owners=("audit_owned", "audit_runtime"))
        for origin in ("source-distinct", "same-source"):
            stem = f"partial-local-{origin}-{linker}"
            alternate_provider = "provider.c"
            alternate_reader = "reader.c"
            if origin == "source-distinct":
                alternate_provider = "provider-distinct.c"
                alternate_reader = "reader-distinct.c"
                shutil.copyfile(self.work / "provider.c", self.work / alternate_provider)
                shutil.copyfile(self.work / "reader.c", self.work / alternate_reader)
            numeric = self.compile(stem + "-numeric-leaf", "provider.c", "integer-cell",
                                   extra=['-DAUDIT_INTEGER_LEAF_SYMBOL="audit_shared_leaf"'])
            plaintext = self.compile(stem + "-plaintext-leaf", alternate_provider, "cell",
                                     extra=['-DAUDIT_CELL_LEAF_SYMBOL="audit_shared_leaf"'])
            for kind, owned_reader, accepts in (("integer-cell", numeric_reader, True),
                                               ("cell", plaintext_reader, False)):
                name = stem + "-leaf-" + kind
                obj = self.partial_link(name, [owned_reader, numeric, plaintext], linker)
                rebound = self.partial_link(name + "-rebound", [obj], linker)
                self.outcome(name, [rebound], kind, accepts=accepts, linkers=[linker])

            primary = self.compile(stem + "-primary-reader", "reader.c", "indexed-direct",
                                   policy=local_policy,
                                   extra=["-DAUDIT_LOCAL_READER", "-DAUDIT_PAIRED_READER"])
            auxiliary = self.compile(stem + "-aux-reader", alternate_reader, "indexed-direct",
                                     policy=local_policy,
                                     extra=["-DAUDIT_LOCAL_READER", "-DAUDIT_SECOND_READER",
                                            "-DAUDIT_OTHER_DIRECT"])
            for plain_primary, plain_aux in ((False, False), (True, False), (False, True)):
                label = ("primary-plaintext" if plain_primary else
                         "aux-plaintext" if plain_aux else "numeric-pair")
                name = stem + "-reader-" + label
                first_provider = self.compile(name + "-primary-data", "provider.c", "indexed-direct",
                                              extra=[] if plain_primary else ["-DAUDIT_BINARY"])
                second_provider = self.compile(
                    name + "-aux-data", alternate_provider, "indexed-direct",
                    extra=["-DAUDIT_OTHER_DIRECT"] + ([] if plain_aux else ["-DAUDIT_BINARY"]))
                inputs = [primary, auxiliary, first_provider, second_provider]
                if plain_aux:
                    inputs.reverse()
                obj = self.partial_link(name, inputs, linker)
                rebound = self.partial_link(name + "-rebound", [obj], linker,
                                             action="-Wl,--relocatable")
                profile = ("local-primary-plaintext" if plain_primary else
                           "local-aux-plaintext" if plain_aux else "indexed-numeric")
                self.outcome(name, [rebound], profile, accepts=not (plain_primary or plain_aux),
                             linkers=[linker])

    def bounded_forwarding(self):
        for kind, accepts in (("integer-cell", True), ("integer-chain", False)):
            reader = self.compile(kind + "-reader", "reader.c", kind, policy=self.strong)
            raw = self.compile(kind + "-provider", "provider.c", kind, managed=False)
            manifest = self.manifest(kind + "-valid", [self.provider(raw, definitions(kind))])
            self.outcome(kind, [reader, raw], kind, accepts=accepts, manifest=manifest)
            if kind == "integer-cell":
                for leaf in ("audit_missing_leaf", "audit_leaf_number"):
                    records = [definition(leaf, "non_string", local=True),
                               definition("audit_integer_cell", "forward", targets=[
                                   {"symbol": leaf, "local": True}])]
                    invalid = self.manifest("phantom-" + leaf, [self.provider(raw, records)])
                    self.outcome("phantom-" + leaf, [reader, raw], kind,
                                 accepts=False, manifest=invalid)

    def local_reader_authority(self):
        if self.args.format != "coff":
            return
        reader = self.compile("local-static-reader", "discarded-reader.c", "integer",
                              policy=self.strong, extra=["-ffunction-sections"])
        owner = self.coff_local_reader(reader)
        integers = self.compile("local-integer-provider", "provider.c", "integer")
        plaintext = self.compile("local-plaintext-provider", "provider.c", "direct",
                                 managed=False)
        manifest = self.manifest("local-plaintext", [
            self.provider(plaintext, definitions("direct"))])
        for linker in self.args.linker:
            for optimize in ("NOREF", "REF"):
                name = f"local-{linker}-{optimize.lower()}"
                authority_map = self.work / (name + ".lldmap")
                flags = [f"-Wl,/OPT:{optimize}"]
                if linker == "lld":
                    flags.append(f"-Wl,/lldmap:{authority_map}")
                baseline, baseline_map = self.link(name + "-baseline", [reader, integers, plaintext],
                                                    linker, managed=False, extra=flags)
                self.execute(baseline, "integer")
                live = self.coff_reader_in_map(authority_map if linker == "lld" else baseline_map,
                                               reader, owner)
                if optimize == "NOREF":
                    require(live, "actual linker did not retain the local reader under /OPT:NOREF")
                # Real VM initialization can retain an otherwise unused owner.
                # Follow actual liveness rather than assuming /OPT:REF drops it.
                for declared in (None, manifest):
                    suffix = "-declared" if declared else "-missing"
                    image, user_map = self.link(name + suffix, [reader, integers, plaintext], linker,
                                               manifest=declared, succeeds=not live, extra=flags)
                    if not live:
                        self.execute(image, "integer")
                    require(self.coff_reader_in_map(authority_map if linker == "lld" else user_map,
                                                   reader, owner) == live,
                            "native local-reader liveness changed between paired linker jobs")
                self.results.append({"case": "local-static-reader", "linker": linker,
                                     "optimization": optimize, "owner_live": live,
                                     "accepted": not live, "baseline_execution": True})

        unselected = self.compile("unselected-owned-reader", "discarded-reader.c", "integer",
                                  policy=self.strong, extra=["-ffunction-sections", "-DAUDIT_DEAD_ONLY"])
        archive = self.archive("unselected-owned-reader", [unselected])
        live_reader = self.compile("archive-live-reader", "reader.c", "integer", policy=self.strong)
        self.outcome("unselected-owned-reader", [live_reader, integers, plaintext, archive],
                     "integer", accepts=True, unused=[unselected])

    def coff_local_reader(self, obj):
        import struct

        data = obj.read_bytes()
        require(len(data) >= 20 and struct.unpack_from("<H", data)[0] == 0x8664,
                "local-reader authority requires a native x64 COFF object")
        section_count = struct.unpack_from("<H", data, 2)[0]
        section_start = 20 + struct.unpack_from("<H", data, 16)[0]
        payloads = []
        for index in range(section_count):
            offset = section_start + index * 40
            require(offset + 40 <= len(data), "truncated COFF section table")
            if data[offset:offset + 8].rstrip(b"\0") == b".obfns":
                size, start = struct.unpack_from("<II", data, offset + 16)
                require(start + size <= len(data), "truncated native ownership section")
                payloads.append(data[start:start + size])
        owners = set()
        for payload in payloads:
            require(len(payload) >= 32, "truncated native ownership header")
            magic, version, header_size, byte_count, count, _, flags, reserved = struct.unpack_from(
                "<4sHHIIQII", payload)
            require((magic, version, header_size, flags, reserved) == (b"OBNS", 1, 32, 0, 0)
                    and byte_count == len(payload) - header_size,
                    "cannot decode native ownership identities")
            offset = header_size
            for _ in range(count):
                require(offset + 8 <= len(payload), "truncated native ownership entry")
                size, kind, entry_flags = struct.unpack_from("<IHH", payload, offset)
                offset += 8
                require(entry_flags == 0 and offset + size <= len(payload),
                        "cannot decode native ownership entry identity")
                if kind == 1:
                    record = json.loads(payload[offset:offset + size].decode("utf-8"))
                    if record["local"]:
                        owners.add(record["owner"])
                offset += size
            require(offset == len(payload), "unexpected native ownership payload bytes")
        require(len(owners) == 1, "fixture must identify one actual local ownership reader")
        return owners.pop()

    def coff_reader_in_map(self, map_path, obj, owner):
        contributor = None
        for line in map_path.read_text(encoding="utf-8", errors="replace").splitlines():
            fields = line.split()
            if len(fields) < 4:
                continue
            if ":" in fields[0] and fields[1] == owner:
                section, _ = fields[0].split(":", 1)
                source = fields[-1].replace("\\", "/").rsplit("/", 1)[-1]
                if int(section, 16) != 0 and source == obj.name:
                    return True
            elif ":" not in fields[0]:
                rendered = " ".join(fields[3:])
                if ":(" in rendered:
                    source = rendered.split(":(", 1)[0]
                    contributor = source.replace("\\", "/").rsplit("/", 1)[-1]
                elif rendered == owner and contributor == obj.name and int(fields[0], 16) != 0:
                    return True
                elif rendered.startswith("."):
                    contributor = None
        return False

    def cleanup_output(self):
        if self.args.format != "elf" or "bfd" not in self.args.linker:
            return
        reader = self.compile("cleanup-reader", "reader.c", "integer", policy=self.strong)
        raw = self.compile("cleanup-provider", "provider.c", "integer", managed=False)
        manifest = self.manifest("cleanup-valid", [self.provider(raw, definitions("integer"))])
        sentinel_bytes = b"native-ownership-unrelated-sentinel\x00\x7f"
        orphan_sentinel = self.work / "rph=place"
        orphan_sentinel.write_bytes(sentinel_bytes)
        baseline, _ = self.link("orphan-baseline", [reader, raw], "bfd",
                                managed=False, extra=["-Wl,-orph=place"])
        self.execute(baseline, "integer")
        self.link("orphan-rejected", [reader, raw], "bfd",
                  succeeds=False, extra=["-Wl,-orph=place"])
        require(orphan_sentinel.is_file() and orphan_sentinel.read_bytes() == sentinel_bytes,
                "rejected orphan-handling link changed an unrelated sentinel")
        self.results.append({"case": "orphan-handling-cleanup", "linker": "bfd",
                             "accepted": False, "baseline_execution": True,
                             "sentinel_preserved": True})
        accepted, _ = self.link("orphan-accepted", [reader, raw], "bfd",
                                manifest=manifest, extra=["-Wl,-orph=place"])
        self.execute(accepted, "integer")
        require(orphan_sentinel.is_file() and orphan_sentinel.read_bytes() == sentinel_bytes,
                "accepted orphan-handling link changed an unrelated sentinel")
        self.results.append({"case": "orphan-handling-accepted", "linker": "bfd",
                             "accepted": True, "native_values_and_effects": True,
                             "sentinel_preserved": True})

        # GNU ld parses single-dash -omagic as joined -o with filename magic.
        # It differs from the actual --omagic option. The earlier -o path must
        # survive, and the validator must remove the actual output magic.
        earlier = self.work / "joined-output-earlier"
        earlier.write_bytes(sentinel_bytes)
        actual = self.work / "magic"
        self.run([*self.raw, "-fuse-ld=bfd", self.main, reader, raw, self.args.runtime,
                  "-o", earlier, "-Wl,-omagic"])
        self.execute(actual, "integer")
        require(earlier.is_file() and earlier.read_bytes() == sentinel_bytes,
                "real joined-output baseline changed the earlier output path")
        actual.unlink()
        # Invoke the compiled proxy with the real driver's actual linker job.
        # A failing Clang driver may delete its earlier -o path independently.
        wrapper_api = runpy.run_path(self.args.wrapper)
        query = self.run([*self.raw, "-fuse-ld=bfd", self.main, reader, raw, self.args.runtime,
                          "-o", earlier, "-Wl,-omagic", "-###"])
        commands = [wrapper_api["_split_arguments"](line.strip())
                    for line in (query.stdout + "\n" + query.stderr).splitlines()
                    if line.strip().startswith('"')]
        linker_job = wrapper_api["_linker_job"](commands)
        require(linker_job is not None, "actual driver query did not provide a linker job")
        self.run([wrapper_api["NATIVE_LINKER"], *linker_job[1:]], succeeds=False,
                 env_updates={"OBF_NATIVE_REAL_LINKER": linker_job[0],
                              "OBF_NATIVE_LINK_FLAVOR": "elf"})
        require(earlier.is_file() and earlier.read_bytes() == sentinel_bytes,
                "rejected joined-output link changed the unrelated earlier output path")
        require(not actual.exists(), "rejected joined-output primary image survived")
        self.results.append({"case": "gnu-joined-output-cleanup", "linker": "bfd",
                             "accepted": False, "baseline_execution": True,
                             "sentinel_preserved": True})
        self.run([self.wrapper, f"--obf-config={self.none}",
                  f"--obf-native-provenance={manifest}", "-fuse-ld=bfd",
                  self.main, reader, raw, "-o", earlier, "-Wl,-omagic"])
        self.execute(actual, "integer")
        require(earlier.is_file() and earlier.read_bytes() == sentinel_bytes,
                "accepted joined-output link changed the unrelated earlier output path")
        self.results.append({"case": "gnu-joined-output-accepted", "linker": "bfd",
                             "accepted": True, "native_values_and_effects": True,
                             "sentinel_preserved": True})

    def numeric_aggregates(self):
        for kind, symbol in (("matrix", "audit_matrix"), ("struct", "audit_counters")):
            reader = self.compile(kind + "-reader", "numeric-reader.c", kind, policy=self.strong)
            managed = self.compile(kind + "-managed-provider", "numeric-provider.c", kind)
            raw = self.compile(kind + "-raw-provider", "numeric-provider.c", kind, managed=False)
            self.outcome("managed-" + kind, [reader, managed], kind, accepts=True)
            self.outcome("raw-" + kind + "-missing", [reader, raw], kind, accepts=False)
            manifest = self.manifest(kind + "-valid", [
                self.provider(raw, [definition(symbol, "non_string")])])
            self.outcome("raw-" + kind + "-classified", [reader, raw], kind,
                         accepts=True, manifest=manifest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wrapper", required=True, help="configured obf-clang launcher")
    parser.add_argument("--wrapperxx", required=True, help="configured obf-clang++ launcher")
    parser.add_argument("--clang", required=True, help="canonical Clang executable")
    parser.add_argument("--ar", required=True, help="matching llvm-ar executable")
    parser.add_argument("--runtime", required=True, help="matching obf runtime archive")
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--format", required=True, choices=("elf", "coff"))
    parser.add_argument("--phase", required=True, choices=("core", "boundaries", "partial"))
    parser.add_argument("--linker", action="append", help="repeat to test each native linker")
    args = parser.parse_args()
    require((os.name == "nt") == (args.format == "coff"), "run COFF natively on Windows and ELF on Linux")
    require(args.phase != "partial" or args.format == "elf", "partial ownership phase requires ELF")
    args.linker = args.linker or (["link", "lld"] if args.format == "coff" else ["bfd", "lld"])
    require(set(args.linker).issubset({"link", "lld"} if args.format == "coff" else {"bfd", "lld"}),
            "unsupported regression linker selection")
    for name in ("wrapper", "wrapperxx", "clang", "ar", "runtime"):
        setattr(args, name, str(Path(getattr(args, name)).resolve()))
    parent = args.work.resolve()
    parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=f"native-ownership-{args.phase}-", dir=parent))
    print(f"NATIVE_OWNERSHIP_WORK {work}", flush=True)
    fixtures = Path(__file__).with_name("native-string-ownership")
    summary = []
    for language in ("c", "c++"):
        for optimization in (0, 2):
            for reports in (False, True):
                folder = work / f"{language.replace('+', 'x')}-O{optimization}-reports-{int(reports)}"
                folder.mkdir()
                for source in fixtures.iterdir():
                    if source.is_file():
                        shutil.copyfile(source, folder / source.name)
                harness = Harness(args, folder, language, optimization, reports)
                getattr(harness, args.phase)()
                summary.append({"language": language, "optimization": optimization,
                                "reports": reports, "cases": harness.results})
                (work / "results.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
                print(f"NATIVE_OWNERSHIP_PASS {args.phase} {language} O{optimization} reports={int(reports)}",
                      flush=True)
    print(f"NATIVE_OWNERSHIP_COMPLETE {args.format} {args.phase} native_values_and_effects=checked", flush=True)


if __name__ == "__main__":
    main()
