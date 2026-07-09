#!/usr/bin/env python3

import pathlib
import re
import sys


def main() -> int:
    if len(sys.argv) not in (3, 4):
        raise SystemExit(
            "usage: tamper_string_auth_ir.py <ir-path> <descriptor-symbol> [version|length|state]"
        )

    path = pathlib.Path(sys.argv[1])
    symbol = sys.argv[2]
    mode = sys.argv[3] if len(sys.argv) == 4 else "version"
    lines = path.read_text(encoding="utf-8").splitlines()

    if mode == "state":
        call_re = re.compile(
            rf"^(?P<prefix>.*?call\s+ptr\s+@[^(]+\(\s*ptr @{re.escape(symbol)},\s*i32\s+(?P<cfg>(?:%[-A-Za-z$._0-9]+|[+-]?\d+))\s*,\s*i32\s+(?P<expected>[+-]?\d+),\s*i64\s+(?P<trusted>[+-]?\d+)\s*\)(?P<suffix>.*))$"
        )
        matches = []
        for index, line in enumerate(lines):
            match = call_re.match(line)
            if match is not None:
                matches.append((index, match))
        if not matches:
            raise SystemExit(
                f"no authenticated helper call for {symbol} found in {path} using state mode"
            )
        if len(matches) != 1:
            raise SystemExit(
                f"expected exactly one authenticated helper call for {symbol} in {path} using state mode, found {len(matches)}"
            )

        index, match = matches[0]
        line = lines[index]
        expected = int(match.group("expected"))
        replaced = (
            line[: match.start("expected")]
            + str(expected + 1)
            + line[match.end("expected") :]
        )
        if replaced == line:
            raise SystemExit(
                f"failed to tamper expected state for {symbol} in {path} using state mode"
            )
        lines[index] = replaced
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return 0

    for index, line in enumerate(lines):
        if not line.startswith(f"@{symbol} = "):
            continue

        if mode == "version":
            replaced = re.sub(r"i32 1, i32 1,", "i32 2, i32 1,", line, count=1)
        elif mode == "length":
            replaced = re.sub(
                r"i64 (\d+),",
                lambda match: f"i64 {int(match.group(1)) + 1},",
                line,
                count=1,
            )
        else:
            raise SystemExit(f"unsupported tamper mode: {mode}")

        if replaced == line:
            raise SystemExit(f"failed to tamper descriptor line for {symbol} using {mode}")
        lines[index] = replaced
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return 0

    raise SystemExit(f"descriptor {symbol} not found in {path}")


if __name__ == "__main__":
    raise SystemExit(main())
