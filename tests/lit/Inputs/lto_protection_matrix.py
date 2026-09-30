import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def run(command, *, succeeds=True, cwd=None):
    env = os.environ.copy()
    for key in ("OBF_CONFIG", "OBF_ENABLE", "OBF_SEED", "OBF_LTO_MODE"):
        env.pop(key, None)
    result = subprocess.run(command, env=env, cwd=cwd, capture_output=True, text=True, timeout=300)
    if (result.returncode == 0) != succeeds:
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


def check_backend_ir(case, args):
    modules = [run([args.dis, str(path), "-o", "-"]).stdout
               for path in case.rglob("*.opt.bc")]
    entries = []
    engines = []
    for module in modules:
        for function in re.finditer(
            r"^define ([^\n]+)\{(.*?)^\}", module, re.MULTILINE | re.DOTALL
        ):
            header, body = function.groups()
            if "@protected_calc(" in header:
                entries.append(body)
            elif re.search(r"\([^)]*i32[^)]*,\s*i64[^)]*\)", header):
                engines.append(body)
    if not any(re.search(r"call i32 %[^(\s]+\([^)]*i32[^)]*,\s*i64", body)
               for body in entries):
        raise RuntimeError("post-LTO entry lost its indirect hidden-token VM boundary")
    if not any(re.search(r"(?:getelementptr|ptrtoint)[^\n]*@", body) and
               re.search(r"load i(?:8|16|32|64),", body) and "indirectbr " in body
               for body in engines):
        raise RuntimeError("post-LTO VM implementation lost table-backed execution")


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
    args = parser.parse_args()
    inputs = Path(__file__).resolve().parent
    work = Path(args.work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="run-", dir=work))

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


if __name__ == "__main__":
    main()
