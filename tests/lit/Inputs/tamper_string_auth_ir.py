#!/usr/bin/env python3

import pathlib
import re
import sys


MASK64 = (1 << 64) - 1
SYMBOL_CHARS = r"[-A-Za-z$._0-9]+"
DESC_RE = re.compile(rf"^@(?P<symbol>__obf_(?:const|string)_desc_{SYMBOL_CHARS}) = ")
TAG_LITERAL_RE = re.compile(r'\[16 x i8\] c"(?P<data>(?:\\.|[^"\\])*)"')
I64_RE = re.compile(r"\bi64\s+([+-]?\d+)")
PTR_SYMBOL_RE = re.compile(rf"ptr @(?P<symbol>{SYMBOL_CHARS})")


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


def descriptor_symbols(lines: list[str]) -> list[str]:
    return [match.group("symbol") for line in lines if (match := DESC_RE.match(line))]


def resolve_descriptor_symbol(lines: list[str], symbol: str, path: pathlib.Path) -> str:
    if symbol != "auto":
        return symbol
    symbols = descriptor_symbols(lines)
    if not symbols:
        raise SystemExit(f"auto descriptor selection found no descriptor lines in {path}")
    if len(symbols) != 1:
        raise SystemExit(
            f"auto descriptor selection expected exactly one descriptor line in {path}, found {len(symbols)}"
        )
    return symbols[0]


def find_symbol_line(lines: list[str], symbol: str, path: pathlib.Path) -> int:
    matches = [index for index, line in enumerate(lines) if line.startswith(f"@{symbol} = ")]
    if not matches:
        raise SystemExit(f"descriptor or reference {symbol} not found in {path}")
    if len(matches) != 1:
        raise SystemExit(f"expected exactly one global line for {symbol} in {path}, found {len(matches)}")
    return matches[0]


def descriptor_ref_matches(line: str):
    matches = list(PTR_SYMBOL_RE.finditer(line))
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
    return line[: tag_match.start("data")] + "".join(tokens) + line[tag_match.end("data") :]


def i64_values(line: str) -> list[int]:
    return [int(match.group(1)) for match in I64_RE.finditer(line)]


def replace_i64_value(line: str, value_index: int, value: int) -> str:
    matches = list(I64_RE.finditer(line))
    if value_index >= len(matches):
        raise SystemExit(f"line has only {len(matches)} i64 values, cannot replace index {value_index}")
    match = matches[value_index]
    return line[: match.start(1)] + to_i64_string(value) + line[match.end(1) :]


def mutate_cache_status_line(line: str) -> str:
    values = i64_values(line)
    if len(values) < 3:
        raise SystemExit("failed to locate V3 state-reference status field")
    status = parse_u64(str(values[1]))
    mutated = (status ^ 0x3C6EF372FE94F82B) & MASK64
    if mutated in (0, status):
        mutated = (status ^ 0x510E527FADE682D1) & MASK64
    if mutated in (0, status):
        mutated = 1
    return replace_i64_value(line, 1, mutated)


def mutate_state_call(lines: list[str], symbol: str, path: pathlib.Path) -> None:
    call_re = re.compile(rf"^.*?\bcall\s+.*?\(\s*ptr @{re.escape(symbol)},(?P<args>.*)$")
    matches = [(index, match) for index, line in enumerate(lines) if (match := call_re.match(line))]
    if not matches:
        raise SystemExit(f"no authenticated helper call for {symbol} found in {path} using state mode")
    if len(matches) != 1:
        raise SystemExit(
            f"expected exactly one authenticated helper call for {symbol} in {path} using state mode, found {len(matches)}"
        )
    index, _ = matches[0]
    line = lines[index]
    expected_match = re.search(r"\bi32\s+(?P<expected>[+-]?\d+)\s*,\s*i64", line)
    if expected_match is None:
        raise SystemExit("authenticated helper call did not contain expected cfg state")
    expected = int(expected_match.group("expected"))
    lines[index] = line[: expected_match.start("expected")] + str(expected + 1) + line[expected_match.end("expected") :]


def mutate_descriptor_callsite(lines: list[str], symbol: str, replacement_symbol: str, path: pathlib.Path) -> None:
    call_re = re.compile(
        rf"^(?P<prefix>.*?call\s+ptr\s+@[^ (]+\(\s*ptr @)(?P<symbol>{re.escape(symbol)})(?P<suffix>,.*)$"
    )
    matches = [(index, match) for index, line in enumerate(lines) if (match := call_re.match(line))]
    if not matches:
        raise SystemExit(f"no descriptor callsite for {symbol} found in {path} using descriptor-callsite mode")
    if len(matches) != 1:
        raise SystemExit(
            f"expected exactly one descriptor callsite for {symbol} in {path} using descriptor-callsite mode, found {len(matches)}"
        )
    index, match = matches[0]
    lines[index] = f"{match.group('prefix')}{replacement_symbol}{match.group('suffix')}"


def reference_target_symbol(lines: list[str], reference_symbol: str, path: pathlib.Path) -> str:
    line = lines[find_symbol_line(lines, reference_symbol, path)]
    matches = list(PTR_SYMBOL_RE.finditer(line))
    if not matches:
        raise SystemExit(f"reference {reference_symbol} has no target pointer")
    return matches[-1].group("symbol")


def mutate_nested_target(
    lines: list[str], descriptor_line: str, replacement_descriptor_line: str, role: str, path: pathlib.Path
) -> None:
    role_indices = {"destination": 0, "ciphertext": 1, "build-key": 2}
    if role not in role_indices:
        raise SystemExit(f"nested-target role must be destination, ciphertext, or build-key, got {role}")
    role_index = role_indices[role]
    source_ref = descriptor_ref_matches(descriptor_line)[role_index].group("symbol")
    replacement_ref = descriptor_ref_matches(replacement_descriptor_line)[role_index].group("symbol")
    source_index = find_symbol_line(lines, source_ref, path)
    source_line = lines[source_index]
    replacement_target = reference_target_symbol(lines, replacement_ref, path)
    target_matches = list(PTR_SYMBOL_RE.finditer(source_line))
    if not target_matches:
        raise SystemExit(f"reference {source_ref} has no target pointer")
    target_match = target_matches[-1]
    lines[source_index] = rewrite_spans(
        source_line, [((target_match.start("symbol"), target_match.end("symbol")), replacement_target)]
    )


def find_topology_symbol(lines: list[str], descriptor_symbol: str, path: pathlib.Path) -> str:
    candidates = []
    prefix_re = re.compile(rf"^@(?P<symbol>{SYMBOL_CHARS}) = .*?\{{\s*ptr @{re.escape(descriptor_symbol)}\s*,\s*ptr @")
    for line in lines:
        match = prefix_re.match(line)
        if match:
            candidates.append(match.group("symbol"))
    return require_exactly_one(candidates, f"topology global for {descriptor_symbol}")


def mutate_topology_callsite(lines: list[str], descriptor_symbol: str, replacement_descriptor: str, path: pathlib.Path) -> None:
    topology = find_topology_symbol(lines, descriptor_symbol, path)
    replacement_topology = find_topology_symbol(lines, replacement_descriptor, path)
    call_re = re.compile(rf"^.*?\bcall\s+[^@]*@[^ (]+\(\s*ptr @{re.escape(descriptor_symbol)},.*$")
    matches = [index for index, line in enumerate(lines) if call_re.match(line)]
    if len(matches) != 1:
        raise SystemExit(
            f"expected exactly one topology callsite for {descriptor_symbol} in {path}, found {len(matches)}"
        )
    index = matches[0]
    line = lines[index]
    open_paren = line.find("(")
    close_paren = line.rfind(")")
    if open_paren < 0 or close_paren <= open_paren:
        raise SystemExit("malformed authenticated runtime call")
    args = line[open_paren:close_paren]
    topology_matches = list(PTR_SYMBOL_RE.finditer(args))
    if not topology_matches:
        raise SystemExit("authenticated runtime call has no topology pointer")
    target = topology_matches[-1]
    replacement = f"ptr @{replacement_topology}"
    lines[index] = line[: open_paren + target.start()] + replacement + line[open_paren + target.end() :]


def state_values_and_binding(descriptor_line: str, state_line: str) -> tuple[int, int]:
    descriptor_values = i64_values(descriptor_line)
    if len(descriptor_values) < 7:
        raise SystemExit("descriptor did not contain a binding id")
    state_values = i64_values(state_line)
    if len(state_values) < 3:
        raise SystemExit("state reference did not contain V3 cookie/status/completion fields")
    return parse_u64(str(descriptor_values[4])), parse_u64(str(state_values[1]))


def normalize_derived_word(value: int, binding_id: int, selector: int) -> int:
    value &= MASK64
    if value == 0:
        value = (0x9E3779B97F4A7C15 ^ binding_id ^ (selector << 32)) | 1
    return value & MASK64


def forged_status_tokens(cold: int, binding_id: int) -> tuple[int, int]:
    decoding = normalize_derived_word(cold ^ 0x6A09E667F3BCC909, binding_id, 1)
    decoded = normalize_derived_word(cold ^ 0xBB67AE8584CAA73B, binding_id, 2)
    if decoding == cold:
        decoding = normalize_derived_word(decoding ^ 0x3C6EF372FE94F82B, binding_id, 1)
    if decoded == cold or decoded == decoding:
        decoded = normalize_derived_word(decoded ^ 0x3C6EF372FE94F82B, binding_id, 2)
    return decoding, decoded


def mutate_forged_state(lines: list[str], descriptor_line: str, state_index: int, mode: str) -> None:
    state_line = lines[state_index]
    binding_id, cold = state_values_and_binding(descriptor_line, state_line)
    decoding, decoded = forged_status_tokens(cold, binding_id)
    token = decoded if mode == "forged-decoded" else decoding
    state_line = replace_i64_value(state_line, 1, token)
    state_line = replace_i64_value(state_line, 2, token)
    lines[state_index] = state_line


def mutate_descriptor_capacity(line: str, role: str) -> str:
    role_index = {"destination": 9, "ciphertext": 10, "build-key": 11}.get(role)
    if role_index is None:
        raise SystemExit(f"descriptor-capacity role must be destination, ciphertext, or build-key, got {role}")
    values = i64_values(line)
    if len(values) <= role_index:
        raise SystemExit("descriptor did not contain all V3 capacity fields")
    return replace_i64_value(line, role_index, values[role_index] + 1)


def mutate_state_clone(lines: list[str], descriptor_line: str, descriptor_index: int, path: pathlib.Path) -> None:
    state_symbol = state_ref_symbol_from_descriptor_line(descriptor_line)
    state_index = find_symbol_line(lines, state_symbol, path)
    clone_symbol = "__obf_tamper_state_clone"
    if any(line.startswith(f"@{clone_symbol} = ") for line in lines):
        raise SystemExit(f"state clone symbol already exists: {clone_symbol}")
    clone_line = re.sub(rf"^@{re.escape(state_symbol)}(?=\s*=)", f"@{clone_symbol}", lines[state_index])
    if clone_line == lines[state_index]:
        raise SystemExit("failed to clone state-reference global")
    lines.insert(state_index + 1, clone_line)
    if state_index < descriptor_index:
        descriptor_index += 1
    descriptor_line = lines[descriptor_index]
    refs = descriptor_ref_matches(descriptor_line)
    replacement = f"ptr @{clone_symbol}"
    lines[descriptor_index] = rewrite_spans(
        descriptor_line, [((refs[3].start(), refs[3].end()), replacement)]
    )


def mutate_clear_completion(lines: list[str], descriptor_symbol: str, path: pathlib.Path) -> None:
    descriptor_line = lines[find_symbol_line(lines, descriptor_symbol, path)]
    state_symbol = state_ref_symbol_from_descriptor_line(descriptor_line)
    state_index = find_symbol_line(lines, state_symbol, path)
    state_line = lines[state_index]
    type_match = re.search(r"\bglobal\s+(\{[^}]+\})\s+\{", state_line)
    state_type = type_match.group(1) if type_match else "{ i64, i64, i64 }"
    runtime_call_re = re.compile(
        rf"^.*?\bcall\s+ptr\s+@(?:rt_core_sd3|rt_core_cpd3)\(\s*ptr @{re.escape(descriptor_symbol)},.*$"
    )
    runtime_calls = [index for index, line in enumerate(lines) if runtime_call_re.match(line)]
    helper = None
    if len(runtime_calls) == 1:
        runtime_index = runtime_calls[0]
        for index in range(runtime_index, -1, -1):
            match = re.match(r"^define internal ptr @(?P<symbol>[-A-Za-z$._0-9]+)\(", lines[index])
            if match:
                helper = match.group("symbol")
                break
    elif len(runtime_calls) > 1:
        raise SystemExit(
            f"expected at most one direct runtime decoder call for {descriptor_symbol}, found {len(runtime_calls)}"
        )
    if helper is None:
        helper_call_re = re.compile(
            rf"^.*?\bcall\s+ptr\s+@(?P<helper>[-A-Za-z$._0-9]+)\(\s*ptr @{re.escape(descriptor_symbol)},.*$"
        )
        helper_calls = [(index, match.group("helper")) for index, line in enumerate(lines)
                        if (match := helper_call_re.match(line))]
        if not helper_calls:
            raise SystemExit(f"failed to find a generated helper call for {descriptor_symbol}")
        helper = helper_calls[0][1]
        helper_definition = next(
            (index for index, line in enumerate(lines)
             if re.match(rf"^define internal ptr @{re.escape(helper)}\(", line)),
            None,
        )
        if helper_definition is None:
            raise SystemExit(f"failed to find helper definition for {helper}")
    helper_call_re = re.compile(rf"^.*?\bcall\s+ptr\s+@{re.escape(helper)}\(")
    calls = [index for index, line in enumerate(lines) if helper_call_re.match(line)]
    if len(calls) < 2:
        raise SystemExit(
            f"clear-completion-before-second-call requires at least two calls to {helper} for {descriptor_symbol}"
        )
    second_call = calls[1]
    insertion = [
        f"  %__obf_tamper_completion_ptr = getelementptr inbounds {state_type}, ptr @{state_symbol}, i32 0, i32 2",
        "  store i64 0, ptr %__obf_tamper_completion_ptr, align 8",
    ]
    lines[second_call:second_call] = insertion


def main() -> int:
    if len(sys.argv) < 3 or len(sys.argv) > 6:
        raise SystemExit(
            "usage: tamper_string_auth_ir.py <ir-path> <descriptor-symbol|auto> [version|length|state|cache-status|destination|ciphertext|build-key|state-ref|descriptor-swap|descriptor-callsite|tag|nested-target|state-clone|descriptor-capacity|topology-callsite|forged-decoded|forged-decoding|clear-completion-before-second-call] [role|replacement-symbol] [replacement-symbol]"
        )

    path = pathlib.Path(sys.argv[1])
    lines = path.read_text(encoding="utf-8").splitlines()
    symbol = resolve_descriptor_symbol(lines, sys.argv[2], path)
    mode = sys.argv[3] if len(sys.argv) >= 4 else "version"
    mode_arg = sys.argv[4] if len(sys.argv) >= 5 else None
    replacement_symbol = sys.argv[5] if len(sys.argv) >= 6 else None

    if mode == "state":
        mutate_state_call(lines, symbol, path)
    elif mode == "descriptor-callsite":
        if mode_arg is None:
            raise SystemExit("descriptor-callsite mode requires a replacement descriptor symbol")
        mutate_descriptor_callsite(lines, symbol, mode_arg, path)
    elif mode == "topology-callsite":
        if mode_arg is None:
            raise SystemExit("topology-callsite mode requires a replacement descriptor symbol")
        mutate_topology_callsite(lines, symbol, mode_arg, path)
    else:
        descriptor_index = find_symbol_line(lines, symbol, path)
        descriptor_line = lines[descriptor_index]
        if mode == "cache-status":
            state_index = find_state_ref_line(lines, descriptor_line, path)
            lines[state_index] = mutate_cache_status_line(lines[state_index])
        elif mode == "state-clone":
            mutate_state_clone(lines, descriptor_line, descriptor_index, path)
        elif mode in ("forged-decoded", "forged-decoding"):
            state_index = find_state_ref_line(lines, descriptor_line, path)
            mutate_forged_state(lines, descriptor_line, state_index, mode)
        elif mode == "clear-completion-before-second-call":
            mutate_clear_completion(lines, symbol, path)
        elif mode == "nested-target":
            if mode_arg is None or replacement_symbol is None:
                raise SystemExit("nested-target mode requires <role> <replacement-descriptor>")
            replacement_index = find_symbol_line(lines, replacement_symbol, path)
            mutate_nested_target(lines, descriptor_line, lines[replacement_index], mode_arg, path)
        elif mode == "descriptor-capacity":
            if mode_arg is None:
                raise SystemExit("descriptor-capacity mode requires a role")
            lines[descriptor_index] = mutate_descriptor_capacity(descriptor_line, mode_arg)
        elif mode == "version":
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
