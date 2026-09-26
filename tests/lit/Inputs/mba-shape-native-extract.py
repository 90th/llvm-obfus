#!/usr/bin/env python3
"""Compile live opaque-zero expressions emitted by the constant-encoding pass in isolation."""

import argparse
from pathlib import Path
import re


ASSIGN = re.compile(r"^\s*%([\w.]+) = (.*)$")
VALUE = re.compile(r"%([\w.]+)")
FAMILIES = ("bit_partition_pair", "cmp_select_pair")


def shape_mix(text):
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("define i64 @shape_mix("))
    end = lines.index("}", start)
    definitions = {}
    for line in lines[start + 1 : end]:
        match = ASSIGN.match(line)
        if match:
            definitions[match[1]] = match[2]
    result = next(line.strip() for line in lines[start + 1 : end] if line.strip().startswith("ret i64 "))
    return lines, definitions, VALUE.findall(result)


def dependencies(name, definitions, seen):
    if name in seen:
        return
    seen.add(name)
    for dependency in VALUE.findall(definitions.get(name, "")):
        if dependency in definitions:
            dependencies(dependency, definitions, seen)


def emit_family(family, definitions, live, zero_family):
    roots = (name for name in definitions if re.fullmatch(rf"obf\.mba\.zero\.{family}\d*", name))
    root = next((name for name in roots if name in live and "i64" in definitions[name]), None)
    if root is None:
        raise ValueError(f"no live i64 {family} root in shape_mix")

    lines = []
    seen = set()
    inputs = set()

    def visit(name):
        if name in seen:
            return
        seen.add(name)
        expr = definitions[name]
        if re.fullmatch(r"obf\.mba\.zero\.input\.[ab]\d*", name):
            input_name = name.rsplit(".", 1)[1].rstrip("0123456789")
            inputs.add(input_name)
            expr = f"freeze i64 %{input_name}"
        elif name == root and family == zero_family:
            expr = "add i64 0, 0"
        else:
            for dependency in VALUE.findall(expr):
                if dependency not in definitions:
                    raise ValueError(f"unexpected external operand %{dependency} in %{name}")
                visit(dependency)
        lines.append(f"  %{name} = {expr}")

    visit(root)
    args = ", ".join(f"i64 %{name}" for name in sorted(inputs))
    return f"define i64 @{family}_live({args}) {{\nentry:\n" + "\n".join(lines) + f"\n  ret i64 %{root}\n}}"



def mutate_module(text, family):
    _, definitions, _ = shape_mix(text)
    start = text.index("define i64 @shape_mix(")
    end = text.index("\n}", start) + 2
    body = text[start:end]
    count = 0
    for name, expr in definitions.items():
        if not re.fullmatch(rf"obf\.mba\.zero\.{family}\d*", name):
            continue
        if family == "bit_partition_pair":
            result_type = re.match(r"xor (i\d+) ", expr)
        else:
            result_type = re.match(r"select i1 [^,]+, (i\d+) ", expr)
        if result_type is None:
            raise ValueError(f"cannot identify type of %{name}: {expr}")
        body, replaced = re.subn(
            rf"(?m)^  %{re.escape(name)} = .*$",
            f"  %{name} = add {result_type[1]} 0, 0",
            body,
        )
        count += replaced
    if count == 0:
        raise ValueError(f"no {family} roots were replaced")
    return text[:start] + body + text[end:]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zero-family", choices=FAMILIES)
    parser.add_argument("--mutate-module", action="store_true")
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.mutate_module:
        if not args.zero_family:
            parser.error("--mutate-module requires --zero-family")
        args.output.write_text(mutate_module(args.source.read_text(), args.zero_family))
        return
    lines, definitions, returns = shape_mix(args.source.read_text())
    live = set()
    for result in returns:
        dependencies(result, definitions, live)
    if not live:
        raise ValueError("shape_mix does not return a computed value")
    target = [line for line in lines if line.startswith(("target triple", "target datalayout"))]
    functions = [emit_family(family, definitions, live, args.zero_family) for family in FAMILIES]
    args.output.write_text("\n".join(target) + "\n\n" + "\n\n".join(functions) + "\n")


if __name__ == "__main__":
    main()
