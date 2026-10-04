import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def run(command, *, succeeds=True, cwd=None):
    env = os.environ.copy()
    for key in ("OBF_CONFIG", "OBF_ENABLE", "OBF_SEED", "OBF_LTO_MODE", "OBF_LTO_INPUTS_VALIDATED"):
        env.pop(key, None)
    result = subprocess.run(command, env=env, cwd=cwd, capture_output=True, text=True, timeout=300)
    if succeeds is not None and (result.returncode == 0) != succeeds:
        raise RuntimeError(
            f"unexpected exit {result.returncode}: {command!r}\n{result.stdout}\n{result.stderr}"
        )
    return result


def check_binary(binary, args, *, regional=False):
    result = run([str(binary)])
    expected = 0
    for index in range(16):
        expected ^= (((index * 113 + 1) ^ 0x5A5A) + 17) * 3
    if result.stdout != f"lto-protection result={expected}\n":
        raise RuntimeError(f"incorrect native result: {result.stdout!r}")
    symbols = run([args.nm, "--defined-only", "--extern-only", str(binary)]).stdout
    if "__obf_" in symbols:
        raise RuntimeError(f"public protection symbols: {symbols}")
    assembly = run([args.objdump, "--disassemble-symbols=protected_calc", str(binary)]).stdout
    indirect = re.search(r"\b(?:callq?|jmpq?)\s+\*", assembly)
    if not indirect and regional:
        for callee in re.findall(r"\bcallq?\s+0x[0-9a-f]+\s+<([^>]+)>", assembly):
            callee_assembly = run(
                [args.objdump, f"--disassemble-symbols={callee}", str(binary)]
            ).stdout
            if re.search(r"\b(?:callq?|jmpq?)\s+\*", callee_assembly):
                indirect = True
                break
    if not indirect:
        raise RuntimeError(f"VM entry was not retained: {assembly}")
    excluded = run([args.objdump, "--disassemble-symbols=excluded_calc", str(binary)]).stdout
    if not re.search(r"<excluded_calc>:", excluded) or re.search(r"\b(?:callq?|jmpq?)\s+\*", excluded):
        raise RuntimeError(f"explicitly excluded function lost its native boundary: {excluded}")
    undefined = run([args.nm, "--undefined-only", str(binary)]).stdout
    if "__obf_lto_finalize_required" in undefined:
        raise RuntimeError("pending finalization survived into the native artifact")


def backend_modules(case, args, suffix="opt"):
    return {path: run([args.dis, str(path), "-o", "-"]).stdout
            for path in sorted(case.rglob(f"*.{suffix}.bc"))}


def check_backend_ir(case, args, *, entry="protected_calc", parameters=("i32",), modules=None):
    if modules is None:
        modules = backend_modules(case, args)
    vm_parameters = (*parameters, "i64")
    entries = []
    engines = []
    for module in modules.values():
        for function in re.finditer(
            r"^define ([^\n]+)\{(.*?)^\}", module, re.MULTILINE | re.DOTALL
        ):
            header, body = function.groups()
            if f"@{entry}(" in header:
                entries.append(body)
            elif any(tuple(re.findall(r"\bi(?:8|16|32|64)\b", signature)) == vm_parameters
                     for signature in re.findall(r"\(([^)]*)\)", header)):
                engines.append(body)
    if not any(tuple(re.findall(r"\bi(?:8|16|32|64)\b", call)) == vm_parameters
               for body in entries
               for call in re.findall(r"call i32 %[^(\s]+\(([^)]*)\)", body)):
        raise RuntimeError(f"post-LTO {entry} lost its indirect hidden-token VM boundary")
    if not any(re.search(r"(?:getelementptr|ptrtoint)[^\n]*@", body) and
               re.search(r"load i(?:8|16|32|64),", body) and "indirectbr " in body
               for body in engines):
        raise RuntimeError("post-LTO VM implementation lost table-backed execution")


def contract_matrix(args, inputs, work):

    for mode in ("full", "thin"):
        for optimization in ("0", "2"):
            for selector in ("config", "annotation"):
                case = work / f"{mode}-{optimization}-{selector}"
                case.mkdir(exist_ok=True)
                policy = case / "policy.yaml"
                shutil.copyfile(inputs / f"lto-protection-{selector}.yaml", policy)
                target = case / "target.o"
                consumer = case / "consumer.o"
                binary = case / "program"
                config = f"--obf-config={policy}"
                opt = f"-O{optimization}"
                flags = ["-DOBF_LTO_ANNOTATED"] if selector == "annotation" else []
                run([args.wrapper, config, opt, f"-flto={mode}", "-fPIC", *flags, "-c",
                     str(inputs / "lto-protection-target.c"), "-o", str(target)])
                run([args.clang, opt, "-c", str(inputs / "lto-protection-main.c"),
                     "-o", str(consumer)])
                archive = case / "protected.a"
                run([args.ar, "rcs", str(archive), str(target)])
                link = [args.wrapper, config, opt, "-Wl,--save-temps",
                        str(consumer), str(archive), "-o", str(binary)]
                if mode == "thin":
                    link.insert(3, f"-Wl,--thinlto-cache-dir={case / 'cache'}")
                run(link)
                check_binary(binary, args)
                check_backend_ir(case, args)
                missing = run([args.clang, opt, "-fuse-ld=lld", str(consumer), str(archive),
                               args.runtime, "-o", str(case / "missing-backend")], succeeds=False)
                if "__obf_lto_finalize_required" not in missing.stderr:
                    raise RuntimeError(f"missing backend failed for another reason: {missing.stderr}")
                missing_shared = run([args.clang, opt, "-fuse-ld=lld", "-shared", str(target),
                                      args.runtime, "-o", str(case / "missing-backend.so")], succeeds=False)
                if "__obf_lto_finalize_required" not in missing_shared.stderr:
                    raise RuntimeError(f"shared link failed for another reason: {missing_shared.stderr}")
                run([args.wrapper, config, opt, f"-flto={mode}", "-fuse-ld=bfd",
                     str(consumer), str(archive), "-o", str(case / "unsupported")], succeeds=False)
                if mode == "thin":
                    run(link)
                    check_binary(binary, args)
                    policy.write_text(policy.read_text().replace("424242", "424243"))
                    changed = run(link, succeeds=False)
                    if not re.search(r"LTO.*(identity|config|seed|policy)|rebuild", changed.stderr, re.IGNORECASE):
                        raise RuntimeError(f"changed policy failed for another reason: {changed.stderr}")
                    policy.write_text(policy.read_text().replace("424243", "424242"))
                print(f"passed {mode} O{optimization} {selector}: archive, native, guard, route")

    direct = work / "single-invocation"
    run([args.wrapper, f"--obf-config={inputs / 'lto-protection-config.yaml'}", "-O2",
         "-flto=full", str(inputs / "lto-protection-target.c"),
         str(inputs / "lto-protection-main.c"), "-o", str(direct)])
    check_binary(direct, args)

    for mode in ("full", "thin"):
        case = work / f"link-only-{mode}"
        case.mkdir(exist_ok=True)
        target = case / "target.o"
        consumer = case / "consumer.o"
        binary = case / "program"
        run([args.clang, "-O0", f"-flto={mode}", "-c",
             str(inputs / "lto-protection-target.c"), "-o", str(target)])
        run([args.clang, "-O0", "-c",
             str(inputs / "lto-protection-main.c"), "-o", str(consumer)])
        run([args.wrapper, f"--obf-config={inputs / 'lto-protection-config.yaml'}", "-O0",
             f"-flto={mode}", "-Wl,--save-temps", str(consumer), str(target), "-o", str(binary)])
        check_binary(binary, args)
        check_backend_ir(case, args)
        print(f"passed {mode} linker-only O0 preparation")
        unsupported = case / "escaping.o"
        run([args.clang, "-O0", f"-flto={mode}", "-c",
             str(inputs / "lto-protection-escaping-alloca.c"), "-o", str(unsupported)])
        rejected = run(
            [args.wrapper, f"--obf-config={inputs / 'lto-protection-config.yaml'}", "-O0",
             f"-flto={mode}", str(consumer), str(unsupported), "-o", str(case / "escaping")],
            succeeds=False,
        )
        if "strong_vm" not in rejected.stderr or "alloca" not in rejected.stderr:
            raise RuntimeError(f"unsupported allocation failed for another reason: {rejected.stderr}")
        regional = case / "regional.o"
        regional_binary = case / "regional"
        run([args.wrapper, f"--obf-config={inputs / 'lto-protection-config.yaml'}", "-O0",
             f"-flto={mode}", "-x", "ir", "-c", str(inputs / "lto-protection-regional.ir"),
             "-o", str(regional)])
        run([args.wrapper, f"--obf-config={inputs / 'lto-protection-config.yaml'}", "-O2",
             str(consumer), str(regional), "-o", str(regional_binary)])
        check_binary(regional_binary, args, regional=True)
        print(f"passed {mode} regional strong_vm")

    native_shadow = work / "native-shadow.o"
    run([args.clang, "-O0", "-c", str(inputs / "lto-protection-target.c"),
         "-o", str(native_shadow)])
    shadowed = run(
        [args.wrapper, f"--obf-config={inputs / 'lto-protection-config.yaml'}", "-O0",
         str(work / "full-0-config" / "consumer.o"), str(native_shadow),
         str(work / "full-0-config" / "protected.a"), "-o", str(work / "native-shadow")],
        succeeds=False,
    )
    if "competing native definition" not in shadowed.stderr:
        raise RuntimeError(f"native shadow failed for another reason: {shadowed.stderr}")
    annotation_shadowed = run(
        [args.wrapper, f"--obf-config={inputs / 'lto-protection-annotation.yaml'}", "-O0",
         str(work / "full-0-annotation" / "consumer.o"), str(native_shadow),
         str(work / "full-0-annotation" / "protected.a"), "-o", str(work / "annotation-shadow")],
        succeeds=False,
    )
    if "competing native definition" not in annotation_shadowed.stderr:
        raise RuntimeError(f"annotation shadow failed for another reason: {annotation_shadowed.stderr}")
    selection_raw = work / "selection-raw.o"
    selection_native = work / "selection-native.o"
    run([args.clang, "-O0", "-flto=thin", "-c", str(inputs / "lto-protection-selection.c"),
         "-o", str(selection_raw)])
    run([args.clang, "-O0", "-DOBF_NATIVE_SELECTION", "-c",
         str(inputs / "lto-protection-selection.c"), "-o", str(selection_native)])
    run([str(Path(args.wrapper).parent / "obf-driver"), "--quiet",
         f"--config={inputs / 'lto-protection-annotation.yaml'}",
         f"--validate-lto-input={selection_raw}", f"--validate-lto-input={selection_native}"])
    alias_raw = work / "alias-raw.o"
    alias_policy = work / "alias-policy.yaml"
    run([args.clang, "-O0", "-flto=thin", "-x", "ir", "-c",
         str(inputs / "lto-protection-alias.ir"), "-o", str(alias_raw)])
    alias_policy.write_text(
        "frontend: rust\nseed: 424242\ndefault_level: none\n"
        "targets:\n  - match: configured_alias\n    level: strong_vm\n"
    )
    alias_rejected = run(
        [str(Path(args.wrapper).parent / "obf-driver"), "--quiet", f"--config={alias_policy}",
         f"--validate-lto-input={alias_raw}", f"--validate-lto-input={selection_native}"],
        succeeds=False,
    )
    if "competing native definition" not in alias_rejected.stderr:
        raise RuntimeError(f"alias shadow failed for another reason: {alias_rejected.stderr}")

    unresolved_policy = work / "unresolved.yaml"
    unresolved_policy.write_text(
        (inputs / "lto-protection-config.yaml").read_text().replace("protected_calc", "missing_target")
    )
    rejected = run(
        [args.wrapper, f"--obf-config={unresolved_policy}", "-O0", "-flto=thin",
         str(work / "link-only-thin" / "consumer.o"), str(work / "link-only-thin" / "target.o"),
         "-o", str(work / "unresolved")],
        succeeds=False,
    )
    if "missing_target" not in rejected.stderr or "bitcode definition" not in rejected.stderr:
        raise RuntimeError(f"missing selection failed for another reason: {rejected.stderr}")

    mixed = work / "thin-via-full-driver"
    run([args.wrapper, f"--obf-config={inputs / 'lto-protection-config.yaml'}",
         "-O0", "-flto=full", "-Wl,--lto-O0",
         str(work / "thin-0-config" / "consumer.o"),
         str(work / "thin-0-config" / "protected.a"), "-o", str(mixed)])
    check_binary(mixed, args)

    linker_script = work / "libindirect.so"
    linker_script.write_text(f'INPUT("{work / "link-only-thin" / "target.o"}")\n')
    script_rejection = run(
        [args.wrapper, f"--obf-config={inputs / 'lto-protection-config.yaml'}", "-O0",
         str(work / "link-only-thin" / "consumer.o"), str(linker_script),
         "-o", str(work / "indirect")], succeeds=False,
    )
    if "script" not in script_rejection.stderr.lower() or "LTO" not in script_rejection.stderr:
        raise RuntimeError(f"script-based LTO failed for another reason: {script_rejection.stderr}")

    script_dir = work / "scripts"
    script_dir.mkdir(exist_ok=True)
    shutil.copyfile(native_shadow, work / "target.o")
    shutil.copyfile(work / "link-only-thin" / "target.o", script_dir / "target.o")
    relative_script = script_dir / "wrapper.ld"
    relative_script.write_text("INPUT(target.o)\n")
    relative_rejection = run(
        [args.wrapper, f"--obf-config={inputs / 'lto-protection-config.yaml'}", "-O0",
         str(work / "link-only-thin" / "consumer.o"), str(relative_script),
         "-o", str(work / "relative-script")], succeeds=False, cwd=work,
    )
    if "script" not in relative_rejection.stderr.lower() or "LTO" not in relative_rejection.stderr:
        raise RuntimeError(f"script search order failed for another reason: {relative_rejection.stderr}")

    long_library = work / "liblong.a"
    run([args.ar, "rcs", str(long_library), str(work / "thin-0-config" / "target.o")])
    for library_flag, path_flag in (("--library=long", f"--library-path={work}"),
                                    ("-library=long", f"-library-path={work}")):
        long_binary = work / "long-library"
        run([args.wrapper, f"--obf-config={inputs / 'lto-protection-config.yaml'}", "-O0",
             str(work / "thin-0-config" / "consumer.o"), f"-Wl,{path_flag},{library_flag}",
             "-o", str(long_binary)])
        check_binary(long_binary, args)
    shutil.copyfile(native_shadow, work / "liblong.so")
    static_binary = work / "long-static"
    run([args.wrapper, f"--obf-config={inputs / 'lto-protection-config.yaml'}", "-O0",
         str(work / "thin-0-config" / "consumer.o"),
         f"-Wl,--library-path={work},--Bstatic,--library=long,--Bdynamic",
         "-o", str(static_binary)])
    check_binary(static_binary, args)

    script_root_rejection = run(
        [args.wrapper, f"--obf-config={inputs / 'lto-protection-config.yaml'}", "-O0",
         str(work / "link-only-thin" / "consumer.o"), f"-Wl,-L{script_dir},-T,wrapper.ld",
         "-o", str(work / "script-root")], succeeds=False, cwd=work,
    )
    if "script" not in script_root_rejection.stderr.lower() or "LTO" not in script_root_rejection.stderr:
        raise RuntimeError(f"script root failed for another reason: {script_root_rejection.stderr}")

    run([args.ar, "rcs", str(script_dir / "libstate.a"),
         str(work / "link-only-thin" / "target.o")])
    run([args.ar, "rcs", str(work / "libstate.a"), str(native_shadow)])
    shutil.copyfile(native_shadow, work / "libstate.so")
    state_script = script_dir / "state.ld"
    state_script.write_text("INPUT(-lstate)\n")
    script_state_rejection = run(
        [args.wrapper, f"--obf-config={inputs / 'lto-protection-config.yaml'}", "-O0",
         str(work / "link-only-thin" / "consumer.o"),
         f"-Wl,-L{script_dir},--Bstatic,-T,{state_script},--Bdynamic",
         "-o", str(work / "script-state")], succeeds=False, cwd=work,
    )
    if "script" not in script_state_rejection.stderr.lower() or "LTO" not in script_state_rejection.stderr:
        raise RuntimeError(f"script static state failed for another reason: {script_state_rejection.stderr}")

    linker_response = work / "linker.rsp"
    linker_response.write_text("--as-needed\n" * 4096)
    response_binary = work / "response"
    run([args.wrapper, f"--obf-config={inputs / 'lto-protection-config.yaml'}", "-O0",
         f"-Wl,@{linker_response}", str(work / "thin-0-config" / "consumer.o"),
         str(work / "thin-0-config" / "protected.a"), "-o", str(response_binary)])
    check_binary(response_binary, args)

    ordinary_policy = work / "ordinary.yaml"
    ordinary_policy.write_text(
        (inputs / "lto-protection-config.yaml").read_text().replace("strong_vm", "vm")
    )
    for mode in ("full", "thin"):
        binary = work / f"ordinary-{mode}"
        run([args.wrapper, f"--obf-config={ordinary_policy}", "-O2", f"-flto={mode}",
             str(inputs / "lto-protection-target.c"), str(inputs / "lto-protection-main.c"),
             "-o", str(binary)])
        check_binary(binary, args)
        print(f"passed {mode} ordinary VM")
    print("LTO contract native matrix passed")


FORWARDED_SECRET = b"forwarded-lto-private-secret-73!"


def forwarded_output(shape, topology):
    data = (0x0BADC0DE).to_bytes(4, "little") if topology == "integer" else FORWARDED_SECRET + b"\0"
    values = ",".join(str(byte) for byte in data)
    if shape == "cell":
        return f"cell={values}\n"
    output = ""
    for slot in range(2):
        values = ",".join(str(byte) for byte in data[slot:])
        output += f"table[{slot}]={values}\n"
        if topology == "shared":
            output += f"shared[{slot}]={values}\n"
        elif topology == "escape":
            output += f"escaped[{slot}]={values}\n"
    return output


def check_forwarded_binary(binary, args, shape, topology, level):
    result = run([str(binary)])
    expected = forwarded_output(shape, topology)
    if result.stdout != expected:
        raise RuntimeError(f"incorrect forwarded native result: {result.stdout!r} != {expected!r}")
    if level == "strong_vm" and FORWARDED_SECRET in binary.read_bytes():
        raise RuntimeError(f"strong_vm forwarded original plaintext survived in {binary}")
    symbols = run([args.nm, "--defined-only", "--extern-only", str(binary)]).stdout
    if "__obf_" in symbols:
        raise RuntimeError(f"public forwarded protection symbols: {symbols}")
    reader = f"protected_{shape}_read"
    assembly = run([args.objdump, f"--disassemble-symbols={reader}", str(binary)]).stdout
    if not re.search(r"\b(?:callq?|jmpq?)\s+\*", assembly):
        raise RuntimeError(f"forwarded VM entry was not retained: {assembly}")
    undefined = run([args.nm, "--undefined-only", str(binary)]).stdout
    if "__obf_lto_finalize_required" in undefined:
        raise RuntimeError("pending forwarded finalization survived into the native artifact")


def check_forwarded_visibility(case, args, mode, shape, topology):
    modules = backend_modules(case, args, "preopt")
    if not modules:
        # Whole-input ThinLTO rejection deliberately happens before a backend.
        return
    reader = f"protected_{shape}_read"
    readers = [text for text in modules.values()
               if re.search(rf"^define [^\n]*@{reader}\(", text, re.MULTILINE)]
    if len(readers) != 1:
        raise RuntimeError(f"expected one preopt partition defining {reader}, found {len(readers)}")
    def has_data(text):
        if topology == "integer":
            return bool(re.search(r"= [^\n]*constant i32 195936478\b", text))
        return FORWARDED_SECRET.decode() in text

    if mode == "thin" and topology in ("cross", "escape", "integer"):
        if has_data(readers[0]):
            raise RuntimeError("ThinLTO preimport reader unexpectedly owns the provider's private data")
        if not any(has_data(text) for text in modules.values() if text != readers[0]):
            raise RuntimeError("ThinLTO provider partition lost its private data definition")
        if not re.search(rf"^@forwarded_{shape} = external\b", readers[0], re.MULTILINE):
            raise RuntimeError("ThinLTO reader partition lost its external forwarding declaration")
    elif not has_data(readers[0]):
        raise RuntimeError("local/FullLTO reader backend did not receive the secret definition")


def check_forwarded_rejection(result, mode, shape, topology, *, retained=False):
    diagnostic = result.stdout + result.stderr
    if retained and "LTO protection structure lost:" in diagnostic:
        return
    if mode == "thin" and topology in ("cross", "escape"):
        required = ("strong_vm", "ThinLTO",
                    f"forwarded_{shape}", f"protected_{shape}_read")
    else:
        required = ("strong_vm", "plaintext")
    if any(term not in diagnostic for term in required):
        raise RuntimeError(f"forwarded rejection lacks {required!r}: {diagnostic}")


def forwarded_case(args, inputs, work, mode, optimization, preparation, shape, topology, level):
    name = f"{mode}-{optimization}-{preparation}-{shape}-{topology}-{level}"
    case = work / name
    case.mkdir()
    reader = f"protected_{shape}_read"
    policy = case / "policy.yaml"
    policy.write_text(
        f"seed: 424242\ndefault_level: none\ntargets:\n"
        f"  - match: {reader}\n    level: {level}\n"
        "mba:\n  max_ir_instructions: 96\n"
        "vm:\n  max_mba_depth: 0\n"
        "string_encoding:\n  authenticated_mode: true\n"
        "security:\n  fail_on_public_obf_symbol: true\n"
    )
    config = f"--obf-config={policy}"
    opt = f"-O{optimization}"
    common = [opt, f"-flto={mode}", "-x", "ir", "-c"]
    compiler = [args.clang] if preparation == "raw" else [args.wrapper, config]
    reader_source = inputs / f"lto-forwarded-{shape}-reader.ir"
    provider_source = inputs / ("lto-forwarded-integer.ir" if topology == "integer"
                                else "lto-forwarded-strings.ir")
    objects = []
    if topology in ("local", "shared"):
        # Derive the local control from precisely the same forwarding globals
        # and load instructions as the paired-TU probe.
        local_source = case / "local.ir"
        declaration = (f"@forwarded_{shape} = external constant "
                       + ("ptr" if shape == "cell" else "[2 x ptr]") + "\n")
        reader_ir = reader_source.read_text()
        if reader_ir.count(declaration) != 1:
            raise RuntimeError(f"unexpected forwarding declaration in {reader_source}")
        reader_ir = reader_ir.replace(declaration, "")
        if topology == "shared":
            reader_ir += "\n" + reader_ir.replace(f"@{reader}(", "@unprotected_read(")
        local_source.write_text(
            provider_source.read_text().replace(" = constant ", " = internal constant ") + reader_ir
        )
        reader_source = local_source
    else:
        provider = case / "provider.o"
        run(compiler + common + [str(provider_source), "-o", str(provider)])
        objects.append(provider)
    consumer = case / "reader.o"
    run(compiler + common + [str(reader_source), "-o", str(consumer)])
    objects.append(consumer)
    if topology in ("cross", "escape", "integer"):
        provider_ir = run([args.dis, str(objects[0]), "-o", "-"]).stdout
        consumer_ir = run([args.dis, str(consumer), "-o", "-"]).stdout
        if topology == "integer":
            if "constant i32 195936478" not in provider_ir or 'c"' in provider_ir:
                raise RuntimeError("integer-only provider gained string data")
        elif FORWARDED_SECRET.decode() not in provider_ir:
            raise RuntimeError("paired provider input lost the original secret")
        if FORWARDED_SECRET.decode() in consumer_ir or not re.search(
                rf"^@forwarded_{shape} = external\b", consumer_ir, re.MULTILINE):
            raise RuntimeError("paired reader no longer exercises external forwarding")
    native = case / "main.o"
    defines = ["-DFORWARDED_TABLE"] if shape == "table" else []
    if topology == "integer":
        defines.append("-DFORWARDED_BYTES=4")
    if topology in ("shared", "escape"):
        defines.append(f"-DFORWARDED_{topology.upper()}")
    run([args.clang, opt, *defines, "-c", str(inputs / "lto-forwarded-main.c"),
         "-o", str(native)])
    binary = case / "program"
    link = [args.wrapper, config, opt, f"-flto={mode}", "-Wl,--save-temps",
            str(native), *(str(path) for path in objects), "-o", str(binary)]
    cache = case / "cache"
    if mode == "thin":
        cache.mkdir()
        link.insert(5, f"-Wl,--thinlto-cache-dir={cache}")
        link.insert(6, "-Wl,--thinlto-jobs=1")
    rejects = level == "strong_vm" and (
        (mode == "thin" and topology == "cross") or topology in ("shared", "escape")
    )
    # Retained frontend VM shapes can fail the existing structure or lazy-use
    # proof. Require a specific fail-closed gate, never an arbitrary link error.
    guarded_retained = preparation == "frontend" and not rejects
    # Successful Thin links populate this cache before the second link. Rejected
    # Thin links must remain rejected on a repeat with the same cache namespace.
    for attempt in range(2 if mode == "thin" else 1):
        result = run(link, succeeds=None if guarded_retained else not rejects)
        if result.returncode:
            check_forwarded_rejection(result, mode, shape, topology, retained=guarded_retained)
            if binary.exists():
                raise RuntimeError(f"rejected forwarded topology produced {binary}")
        else:
            check_forwarded_binary(binary, args, shape, topology, level)
            modules = backend_modules(case, args)
            check_backend_ir(case, args, entry=reader,
                             parameters=("i64",) if shape == "cell" else ("i64", "i64"),
                             modules=modules)
            if level == "strong_vm" and any(FORWARDED_SECRET.decode() in text
                                            for text in modules.values()):
                raise RuntimeError("strong_vm forwarded original plaintext survived in backend IR")
            if level == "strong_vm" and topology != "integer" and not any(
                    re.search(r"\bcall ptr @rt_core_sd3\(", text) for text in modules.values()):
                raise RuntimeError("strong_vm forwarded backend lost authenticated string decoding")
            if mode == "thin" and not any(path.is_file() for path in cache.rglob("llvmcache-*")):
                raise RuntimeError("successful ThinLTO link did not populate its managed cache")
        if attempt == 0:
            check_forwarded_visibility(case, args, mode, shape, topology)
    outcome = "rejected" if result.returncode else "native+VM"
    cache_note = (" repeat-cache rejection" if result.returncode else " cold/warm-cache") if mode == "thin" else ""
    print(f"passed forwarded {name}: {outcome}{cache_note}")


def forwarded_matrix(args, inputs, work):
    for mode in ("full", "thin"):
        for optimization in ("0", "2"):
            for preparation in ("raw", "frontend"):
                for shape in ("cell", "table"):
                    for level in ("strong_vm", "vm"):
                        forwarded_case(args, inputs, work, mode, optimization,
                                       preparation, shape, "cross", level)
            # Both local controls use the exact paired fixtures but give the
            # selected backend ownership of the table and original string.
            for shape in ("cell", "table"):
                forwarded_case(args, inputs, work, mode, optimization,
                               "raw", shape, "local", "strong_vm")
        # Bound the boundary probes to raw O0; the cross-TU matrix above owns
        # frontend preparation and optimization coverage.
        for topology in ("shared", "escape"):
            for level in ("strong_vm", "vm"):
                forwarded_case(args, inputs, work, mode, "0",
                               "raw", "table", topology, level)
    # A pointer cell alone is not evidence of string forwarding: this paired
    # integer-only provider must keep working under strong_vm ThinLTO.
    forwarded_case(args, inputs, work, "thin", "0", "raw", "cell", "integer", "strong_vm")
    print("LTO forwarded string matrix passed")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--wrapper", required=True)
    parser.add_argument("--clang", required=True)
    parser.add_argument("--dis", default="llvm-dis")
    parser.add_argument("--ar", required=True)
    parser.add_argument("--nm", required=True)
    parser.add_argument("--objdump", required=True)
    parser.add_argument("--runtime", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--matrix", choices=("all", "contract", "forwarded"), default="all")
    args = parser.parse_args()
    inputs = Path(__file__).resolve().parent
    work = Path(args.work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="run-", dir=work))
    for matrix, action in (("contract", contract_matrix), ("forwarded", forwarded_matrix)):
        if args.matrix in ("all", matrix):
            case = work / matrix
            case.mkdir()
            action(args, inputs, case)


if __name__ == "__main__":
    main()
