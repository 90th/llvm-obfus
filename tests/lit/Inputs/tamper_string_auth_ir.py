#!/usr/bin/env python3

import pathlib
import re
import sys


MASK64 = (1 << 64) - 1
POOL_DESC_RE = re.compile(r"^@(?P<symbol>__obf_const_desc_[A-Za-z$._0-9]+) = ")
TAG_LITERAL_RE = re.compile(r'\[16 x i8\] c"(?P<data>(?:\\.|[^"\\])*)"')


def to_u64(value: int) -> int:
    return value & MASK64


def to_i64_string(value: int) -> str:
    value &= MASK64
    if value >= (1 << 63):
        value -= 1 << 64
    return str(value)


def parse_u64(token: str) -> int:
    return int(token) & MASK64


def require_exactly_one(matches, description: str):
    if not matches:
        raise SystemExit(f"no {description} found")
    if len(matches) != 1:
        raise SystemExit(f"expected exactly one {description}, found {len(matches)}")
    return matches[0]


def resolve_descriptor_symbol(lines: list[str], symbol: str, path: pathlib.Path) -> str:
    if symbol != "auto":
        return symbol

    matches = [POOL_DESC_RE.match(line) for line in lines]
    symbols = [match.group("symbol") for match in matches if match is not None]
    if not symbols:
        raise SystemExit(f"auto descriptor selection found no @__obf_const_desc_ lines in {path}")
    if len(symbols) != 1:
        raise SystemExit(
            f"auto descriptor selection expected exactly one @__obf_const_desc_ line in {path}, found {len(symbols)}"
        )
    return symbols[0]


def find_symbol_line(lines: list[str], symbol: str, path: pathlib.Path) -> int:
    matches = [index for index, line in enumerate(lines) if line.startswith(f"@{symbol} = ")]
    if not matches:
        raise SystemExit(f"descriptor {symbol} not found in {path}")
    if len(matches) != 1:
        raise SystemExit(f"expected exactly one descriptor line for {symbol} in {path}, found {len(matches)}")
    return matches[0]


def descriptor_ref_matches(line: str):
    matches = list(re.finditer(r"ptr @(?P<symbol>[-A-Za-z$._0-9]+)", line))
    if len(matches) < 4:
        raise SystemExit("descriptor line did not contain four reference operands")
    return matches[-4:]


def rewrite_spans(line: str, replacements: list[tuple[tuple[int, int], str]]) -> str:
    rebuilt: list[str] = []
    cursor = 0
    for (start, end), text in sorted(replacements, key=lambda entry: entry[0][0]):
        rebuilt.append(line[cursor:start])
        rebuilt.append(text)
        cursor = end
    rebuilt.append(line[cursor:])
    return "".join(rebuilt)


def mutate_descriptor_pointer(line: str, target_index: int, replacement_index: int) -> str:
    refs = descriptor_ref_matches(line)
    replacement = line[refs[replacement_index].start() : refs[replacement_index].end()]
    return rewrite_spans(line, [((refs[target_index].start(), refs[target_index].end()), replacement)])


def swap_descriptor_pointers(line: str, lhs_index: int, rhs_index: int) -> str:
    refs = descriptor_ref_matches(line)
    lhs_text = line[refs[lhs_index].start() : refs[lhs_index].end()]
    rhs_text = line[refs[rhs_index].start() : refs[rhs_index].end()]
    return rewrite_spans(
        line,
        [
            ((refs[lhs_index].start(), refs[lhs_index].end()), rhs_text),
            ((refs[rhs_index].start(), refs[rhs_index].end()), lhs_text),
        ],
    )


def state_ref_symbol_from_descriptor_line(line: str) -> str:
    return descriptor_ref_matches(line)[-1].group("symbol")


def find_state_ref_line(lines: list[str], descriptor_line: str, path: pathlib.Path) -> int:
    return find_symbol_line(lines, state_ref_symbol_from_descriptor_line(descriptor_line), path)


def mutate_version_line(line: str) -> str:
    match = re.match(
        r"^(?P<prefix>@[^=]+ = .*?\}\s+\{\s*i32\s+)(?P<version>[+-]?\d+)(?P<suffix>,\s*i32\s+[+-]?\d+,.+)$",
        line,
    )
    if match is None:
        raise SystemExit("failed to locate descriptor version field")
    version = int(match.group("version"))
    return f"{match.group('prefix')}{version + 1}{match.group('suffix')}"


def mutate_length_line(line: str) -> str:
    match = re.match(
        r"^(?P<prefix>@[^=]+ = .*?\}\s+\{\s*i32\s+[+-]?\d+,\s*i32\s+[+-]?\d+,\s*i64\s+)(?P<length>[+-]?\d+)(?P<suffix>,.*)$",
        line,
    )
    if match is None:
        raise SystemExit("failed to locate descriptor length field")
    length = int(match.group("length"))
    return f"{match.group('prefix')}{length + 1}{match.group('suffix')}"


def split_llvm_byte_tokens(data: str) -> list[str]:
    tokens: list[str] = []
    index = 0
    while index < len(data):
        if data[index] == "\\":
            if index + 2 >= len(data):
                raise SystemExit("malformed LLVM byte string escape")
            tokens.append(data[index : index + 3])
            index += 3
            continue
        tokens.append(data[index])
        index += 1
    return tokens


def llvm_byte_token_value(token: str) -> int:
    if token.startswith("\\"):
        return int(token[1:], 16)
    return ord(token)


def llvm_byte_token(value: int) -> str:
    value &= 0xFF
    if 32 <= value <= 126 and chr(value) not in {'"', '\\'}:
        return chr(value)
    return f"\\{value:02X}"


def mutate_tag_line(line: str) -> str:
    matches = list(TAG_LITERAL_RE.finditer(line))
    if len(matches) < 2:
        raise SystemExit("failed to locate descriptor tag literal")
    tag_match = matches[1]
    tokens = split_llvm_byte_tokens(tag_match.group("data"))
    if not tokens:
        raise SystemExit("descriptor tag literal was empty")
    tokens[0] = llvm_byte_token(llvm_byte_token_value(tokens[0]) ^ 0x01)
    return (
        line[: tag_match.start("data")]
        + "".join(tokens)
        + line[tag_match.end("data") :]
    )


def mutate_cache_status_line(line: str) -> str:
    match = re.match(
        r"^(?P<prefix>@[^=]+ = .*?\{\s*i64\s+[+-]?\d+,\s*i64\s+)(?P<status>[+-]?\d+)(?P<suffix>\s*\}.*)$",
        line,
    )
    if match is None:
        raise SystemExit("failed to locate state-reference status field")
    status = parse_u64(match.group("status"))
    mutated = (status ^ 0x6A09E667F3BCC909) & MASK64
    if mutated == 0:
        mutated = 1
    return f"{match.group('prefix')}{to_i64_string(mutated)}{match.group('suffix')}"


def mutate_state_call(lines: list[str], symbol: str, path: pathlib.Path) -> None:
    call_re = re.compile(
        rf"^(?P<prefix>.*?call\s+ptr\s+@[^(]+\(\s*ptr @{re.escape(symbol)},\s*i32\s+(?P<cfg>(?:%[-A-Za-z$._0-9]+|[+-]?\d+))\s*,\s*i32\s+(?P<expected>[+-]?\d+),\s*i64\s+(?P<trusted>[+-]?\d+)\s*,\s*i64\s+(?P<binding>[+-]?\d+)\s*\)(?P<suffix>.*))$"
    )
    matches = [(index, match) for index, line in enumerate(lines) if (match := call_re.match(line))]
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
    lines[index] = (
        line[: match.start("expected")] + str(expected + 1) + line[match.end("expected") :]
    )


def mutate_descriptor_callsite(lines: list[str], symbol: str, replacement_symbol: str, path: pathlib.Path) -> None:
    call_re = re.compile(
        rf"^(?P<prefix>.*?call\s+ptr\s+@[^(]+\(\s*ptr @)(?P<symbol>{re.escape(symbol)})(?P<suffix>,.*)$"
    )
    matches = [(index, match) for index, line in enumerate(lines) if (match := call_re.match(line))]
    if not matches:
        raise SystemExit(
            f"no descriptor callsite for {symbol} found in {path} using descriptor-callsite mode"
        )
    if len(matches) != 1:
        raise SystemExit(
            f"expected exactly one descriptor callsite for {symbol} in {path} using descriptor-callsite mode, found {len(matches)}"
        )
    replacement_index = find_symbol_line(lines, replacement_symbol, path)
    if replacement_index < 0:
        raise SystemExit(f"replacement descriptor {replacement_symbol} not found in {path}")
    index, match = matches[0]
    lines[index] = f"{match.group('prefix')}{replacement_symbol}{match.group('suffix')}"


def main() -> int:
    if len(sys.argv) not in (3, 4, 5):
        raise SystemExit(
            "usage: tamper_string_auth_ir.py <ir-path> <descriptor-symbol|auto> [version|length|state|cache-status|destination|ciphertext|build-key|state-ref|descriptor-swap|descriptor-callsite|tag] [replacement-symbol]"
        )

    path = pathlib.Path(sys.argv[1])
    symbol = sys.argv[2]
    mode = sys.argv[3] if len(sys.argv) == 4 else "version"
    replacement_symbol = sys.argv[4] if len(sys.argv) == 5 else None
    lines = path.read_text(encoding="utf-8").splitlines()

    symbol = resolve_descriptor_symbol(lines, symbol, path)

    if mode == "state":
        mutate_state_call(lines, symbol, path)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return 0

    if mode == "descriptor-callsite":
        if replacement_symbol is None:
            raise SystemExit("descriptor-callsite mode requires a replacement descriptor symbol")
        mutate_descriptor_callsite(lines, symbol, replacement_symbol, path)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return 0

    descriptor_index = find_symbol_line(lines, symbol, path)
    descriptor_line = lines[descriptor_index]

    if mode == "cache-status":
        state_index = find_state_ref_line(lines, descriptor_line, path)
        lines[state_index] = mutate_cache_status_line(lines[state_index])
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return 0

    if mode == "version":
        lines[descriptor_index] = mutate_version_line(descriptor_line)
    elif mode == "length":
        lines[descriptor_index] = mutate_length_line(descriptor_line)
    elif mode == "destination":
        lines[descriptor_index] = mutate_descriptor_pointer(descriptor_line, 0, 1)
    elif mode == "ciphertext":
        lines[descriptor_index] = mutate_descriptor_pointer(descriptor_line, 1, 0)
    elif mode == "build-key":
        lines[descriptor_index] = mutate_descriptor_pointer(descriptor_line, 2, 0)
    elif mode == "state-ref":
        lines[descriptor_index] = mutate_descriptor_pointer(descriptor_line, 3, 0)
    elif mode == "descriptor-swap":
        lines[descriptor_index] = swap_descriptor_pointers(descriptor_line, 0, 1)
    elif mode == "tag":
        lines[descriptor_index] = mutate_tag_line(descriptor_line)
    else:
        raise SystemExit(f"unsupported tamper mode: {mode}")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
