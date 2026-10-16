"""Check scalar VM intrinsics against integer arithmetic and native execution."""

import argparse
import json
import os
from pathlib import Path
import subprocess

from report_contract import whole_vm_contract


WIDTHS = (1, 3, 8, 64, 128)
SATURATION = ("uadd", "usub", "sadd", "ssub")
OVERFLOW = ("uadd", "sadd", "usub", "ssub", "umul", "smul")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def signed(value, width):
    return value - (1 << width) if value & (1 << (width - 1)) else value


def arithmetic(operation, a, b, width):
    if operation.startswith("s"):
        a, b = signed(a, width), signed(b, width)
    if "add" in operation:
        return a + b
    if "sub" in operation:
        return a - b
    return a * b


def bounds(operation, width):
    if operation.startswith("s"):
        return -(1 << (width - 1)), (1 << (width - 1)) - 1
    return 0, (1 << width) - 1


def inputs(width):
    if width <= 3:
        return list(range(1 << width))
    mask = (1 << width) - 1
    sign = 1 << (width - 1)
    half = 1 << (width // 2)
    return sorted({value & mask for value in
                   (0, 1, 2, 3, 7, sign - 2, sign - 1, sign, sign + 1,
                    mask - 1, mask, half - 1, half, half + 1,
                    -half - 1, -half, -half + 1)})


def signature(family, width):
    integer = f"i{width}"
    if family in ("abs", "abs_poison", "hints"):
        return integer
    if family == "scmp":
        return "i32"
    if family == "ucmp":
        return "i2"
    if family.endswith("_overflow"):
        return "{ " + integer + ", i1 }"
    return integer


def expected(family, a, b, width):
    mask = (1 << width) - 1
    if family in ("abs", "abs_poison"):
        return str(abs(signed(a, width)) & mask)
    if family == "hints":
        return str(a)
    if family in ("scmp", "ucmp"):
        left, right = (signed(a, width), signed(b, width)) if family == "scmp" else (a, b)
        return str((left > right) - (left < right))
    operation, mode = family.split("_")
    exact = arithmetic(operation, a, b, width)
    low, high = bounds(operation, width)
    if mode == "sat":
        return str(min(high, max(low, exact)) & mask)
    overflow = "true" if exact < low or exact > high else "false"
    return f"{{ i{width} {exact & mask}, i1 {overflow} }}"


def prepare(work):
    families = ("abs", "abs_poison", "scmp", "ucmp", "hints") + tuple(
        operation + "_sat" for operation in SATURATION) + tuple(
        operation + "_overflow" for operation in OVERFLOW)
    lines = ['target datalayout = "e-p:64:64-i64:64-i128:128-v128:128-n8:16:32:64-S128"',
             "declare void @llvm.assume(i1)",
             "declare void @llvm.experimental.noalias.scope.decl(metadata)"]
    owners = []
    rows = 0
    for width in WIDTHS:
        integer = f"i{width}"
        for family in families:
            result = signature(family, width)
            owner = f"vm_scalar_{family}{width}"
            owners.append(owner)
            if family == "hints":
                lines += [f"declare {integer} @llvm.expect.{integer}({integer}, {integer})",
                          f"declare {integer} @llvm.expect.with.probability.{integer}({integer}, {integer}, double)",
                          f"define {integer} @{owner}({integer} %a, {integer} %b) noinline {{",
                          "  call void @llvm.assume(i1 true)",
                          "  call void @llvm.experimental.noalias.scope.decl(metadata !2)",
                          f"  %hint = call {integer} @llvm.expect.{integer}({integer} %a, {integer} %b)",
                          f"  %result = call {integer} @llvm.expect.with.probability.{integer}({integer} %hint, {integer} %b, double 5.000000e-01)",
                          f"  ret {integer} %result", "}"]
                continue
            if family in ("abs", "abs_poison"):
                intrinsic = f"llvm.abs.{integer}"
                if family == "abs":
                    lines.append(f"declare {integer} @{intrinsic}({integer}, i1 immarg)")
                args = f"{integer} %a, i1 {'true' if family == 'abs_poison' else 'false'}"
            elif family in ("scmp", "ucmp"):
                intrinsic = f"llvm.{family}.{result}.{integer}"
                lines.append(f"declare {result} @{intrinsic}({integer}, {integer})")
                args = f"{integer} %a, {integer} %b"
            else:
                operation, mode = family.split("_")
                suffix = "sat" if mode == "sat" else "with.overflow"
                intrinsic = f"llvm.{operation}.{suffix}.{integer}"
                lines.append(f"declare {result} @{intrinsic}({integer}, {integer})")
                args = f"{integer} %a, {integer} %b"
            lines += [f"define {result} @{owner}({integer} %a, {integer} %b) noinline {{",
                      f"  %result = call {result} @{intrinsic}({args})",
                      f"  ret {result} %result", "}"]

        fields = [integer, integer] + [signature(family, width) for family in families]
        record = "{ " + ", ".join(fields) + " }"
        values = inputs(width)
        count = len(values) ** 2
        rows += count
        records = []
        for a in values:
            for b in values:
                members = [f"{integer} {a}", f"{integer} {b}"] + [
                    f"{signature(family, width)} {expected(family, a, b, width)}"
                    for family in families]
                records.append(record + " { " + ", ".join(members) + " }")
        lines.append(f"@rows{width} = private constant [{count} x {record}] [" + ",\n".join(records) + "]")
        lines += [f"define i1 @check{width}(ptr %row) noinline {{",
                  f"  %ap = getelementptr {record}, ptr %row, i32 0, i32 0",
                  f"  %bp = getelementptr {record}, ptr %row, i32 0, i32 1",
                  f"  %a = load {integer}, ptr %ap", f"  %b = load {integer}, ptr %bp"]
        bad = []
        for index, family in enumerate(families):
            result = signature(family, width)
            lines += [f"  %expectedp{index} = getelementptr {record}, ptr %row, i32 0, i32 {index + 2}",
                      f"  %expected{index} = load {result}, ptr %expectedp{index}",
                      f"  %actual{index} = call {result} @vm_scalar_{family}{width}({integer} %a, {integer} %b)"]
            if family.endswith("_overflow"):
                lines += [f"  %actual.value{index} = extractvalue {result} %actual{index}, 0",
                          f"  %actual.flag{index} = extractvalue {result} %actual{index}, 1",
                          f"  %expected.value{index} = extractvalue {result} %expected{index}, 0",
                          f"  %expected.flag{index} = extractvalue {result} %expected{index}, 1",
                          f"  %bad.value{index} = icmp ne {integer} %actual.value{index}, %expected.value{index}",
                          f"  %bad.flag{index} = icmp ne i1 %actual.flag{index}, %expected.flag{index}",
                          f"  %bad{index} = or i1 %bad.value{index}, %bad.flag{index}"]
            elif family == "abs_poison":
                lines += [f"  %minimum = icmp eq {integer} %a, {1 << (width - 1)}",
                          f"  %abs.bad = icmp ne {result} %actual{index}, %expected{index}",
                          f"  %bad{index} = select i1 %minimum, i1 false, i1 %abs.bad"]
            else:
                lines.append(f"  %bad{index} = icmp ne {result} %actual{index}, %expected{index}")
            bad.append(f"%bad{index}")
        previous = bad[0]
        for index, value in enumerate(bad[1:]):
            lines.append(f"  %errors{index} = or i1 {previous}, {value}")
            previous = f"%errors{index}"
        lines += [f"  ret i1 {previous}", "}",
                  f"define i1 @matrix{width}() noinline {{", "entry:", "  br label %loop", "loop:",
                  "  %index = phi i64 [ 0, %entry ], [ %next, %loop ]",
                  "  %errors = phi i1 [ false, %entry ], [ %bad, %loop ]",
                  f"  %row = getelementptr [{count} x {record}], ptr @rows{width}, i64 0, i64 %index",
                  f"  %current = call i1 @check{width}(ptr %row)",
                  "  %bad = or i1 %errors, %current", "  %next = add i64 %index, 1",
                  f"  %done = icmp eq i64 %next, {count}",
                  "  br i1 %done, label %exit, label %loop", "exit:", "  ret i1 %bad", "}"]
    lines += ["define i32 @main() {", "entry:"]
    previous = "false"
    for width in WIDTHS:
        lines += [f"  %bad{width} = call i1 @matrix{width}()",
                  f"  %errors{width} = or i1 {previous}, %bad{width}"]
        previous = f"%errors{width}"
    lines += [f"  %code = zext i1 {previous} to i32", "  ret i32 %code", "}",
              "!0 = distinct !{!0}", "!1 = distinct !{!1, !0}", "!2 = !{!1}"]
    module = work / "scalar-intrinsics.ll"
    module.write_text("\n".join(lines) + "\n")
    (work / "owners.json").write_text(json.dumps(owners) + "\n")
    return module, owners, rows


def run(command, env=None):
    command = [str(item) for item in command]
    result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=300)
    require(result.returncode == 0,
            f"command failed: {command!r}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def runtime_objects(command):
    objects = []
    index = 1
    while index < len(command):
        item = command[index]
        if item.startswith(("--extra-object=", "-extra-object=")):
            objects.append(item.split("=", 1)[1])
        elif item in ("--extra-object", "-extra-object"):
            index += 1
            require(index < len(command), "missing lli runtime object")
            objects.append(command[index])
        else:
            raise AssertionError(f"unsupported lli argument: {item}")
        index += 1
    return objects


def native(args, module, objects, stem):
    for optimization in (0, 2):
        executable = args.work / f"{stem}-o{optimization}{'.exe' if os.name == 'nt' else ''}"
        flags = [f"-O{optimization}", "-Wno-override-module"]
        if os.name == "nt":
            flags.append("-fuse-ld=lld")
        run([args.clang, *flags, module, *objects, "-o", executable])
        run([executable])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--opt", required=True, nargs="+")
    parser.add_argument("--plugin", required=True)
    parser.add_argument("--clang", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--semantics", required=True, type=Path)
    parser.add_argument("--lli", required=True, nargs=argparse.REMAINDER)
    args = parser.parse_args()
    args.work = args.work.absolute()
    args.work.mkdir(parents=True, exist_ok=True)
    module, owners, rows = prepare(args.work)
    require(args.lli, "the expanded lli command is required")
    objects = runtime_objects(args.lli)
    if os.name == "nt":
        resource = Path(run([args.clang, "-print-resource-dir"]).strip())
        builtins = resource / "lib" / "windows" / "clang_rt.builtins-x86_64.lib"
        require(builtins.is_file(), f"missing compiler-rt archive: {builtins}")
        objects.append(str(builtins))
    native(args, module, objects, "reference")
    semantic_reference = args.work / "semantic-reference.ll"
    run([*args.opt, "-passes=instcombine<no-verify-fixpoint>,verify", "-S",
         args.semantics, "-o", semantic_reference])
    native(args, semantic_reference, objects, "semantic-reference")
    for source, selected, stem in ((module, owners, "matrix"),
                                    (args.semantics, SEMANTIC_OWNERS, "semantics")):
        for seed in (1, 387541):
            protected = args.work / f"{stem}-{seed}.ll"
            report = args.work / f"{stem}-{seed}.json"
            env = {key: value for key, value in os.environ.items()
                   if not key.upper().startswith("OBF")}
            env["OBF_COVERAGE_REPORT"] = str(report)
            run([*args.opt, "-load-pass-plugin", args.plugin, f"--obf-config={args.config}",
                 f"--obf-seed={seed}", "-passes=obf-vm,verify",
                 "-S", source, "-o", protected], env)
            whole_vm_contract(argparse.Namespace(report=report, owner=selected))
            native(args, protected, objects, f"{stem}-{seed}")
    print(json.dumps({"ok": True, "matrix_rows": rows,
                      "whole_function_owners": len(owners) + len(SEMANTIC_OWNERS),
                      "native_optimizations": [0, 2], "seeds": [1, 387541]}))


SEMANTIC_OWNERS = ["vm_scalar_discard_poison", "vm_scalar_freeze_results",
                   "vm_scalar_frozen_choices", "vm_scalar_undef_bounds"]


if __name__ == "__main__":
    main()
