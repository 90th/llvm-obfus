import json
import math
import pathlib
import re
import runpy
import subprocess
import sys


# Plan: capture real decode rounds in a separate IR copy; reconstruct canonical
# payloads from every physical anchor's affine placement and byte mask; verify
# exact encoding roundtrips; mutate all mapped copies in the original IR; require
# native traps and exact effect prefixes, with independent return/store/effect
# oracles. No expected-value predicates are modified.
ADMISSION = runpy.run_path(str(pathlib.Path(__file__).with_name("vm-hidden-token-admission.py")))
FUNCTION = ADMISSION["FUNCTION"]
SYMBOL = ADMISSION["SYMBOL"]
VALUE = ADMISSION["VALUE"]
require = ADMISSION["require"]
bind_writer = ADMISSION["bind_fixture_writer"]
native_trap = ADMISSION["native_trap"]
replace_spans = ADMISSION["replace_spans"]
TARGETS = ("ordinary_integrity", "strong_integrity")
MASK = (1 << 64) - 1
GOLDEN = 0x9E3779B97F4A7C15
LLVM_BYTE = r'\\(?:[0-9A-Fa-f]{2}|\\)|[^"\\\n]'
GLOBALS = re.compile(rf'(?m)^@(?P<name>{SYMBOL}) = [^\n]*\[(?P<size>\d+) x i8\] c"(?P<data>(?:{LLVM_BYTE})*)"[^\n]*$')
GLOBAL_DEFINITION = re.compile(rf'(?m)^@(?P<name>{SYMBOL}) = (?P<body>[^\n]*)$')
METADATA = re.compile(r'(?m)^!(?P<id>\d+) = (?:distinct )?!\{(?P<data>[^\n]*)\}\s*$')
ANCHOR_ENCODING = re.compile(r'!obf\.vm\.anchor\.encoding\s+!(\d+)')
ENCODING_FIELDS = re.compile(r'\s*i32\s+(-?\d+)\s*,\s*i32\s+(-?\d+)\s*,\s*i64\s+(-?\d+)\s*')


def mix(seed, salt):
    return (seed ^ ((salt + GOLDEN + (seed << 6) + (seed >> 2)) & MASK)) & MASK


def rotr(value, bits):
    return ((value >> bits) | (value << (64 - bits))) & MASK


def invert_mix(value, salt):
    # Given the low two seed bits, bit n of the result determines seed bit n+2.
    # Check the complete result, not just the low-byte encryption key.
    candidates = []
    for low in range(4):
        seed, carry = low, 0
        for bit in range(62):
            base = ((salt + GOLDEN + (seed << 6)) >> bit) & 1
            shifted = ((value >> bit) ^ (seed >> bit) ^ base ^ carry) & 1
            seed |= shifted << (bit + 2)
            carry = (base + shifted + carry) >> 1
        if mix(seed, salt) == value:
            candidates.append(seed)
    return candidates


def decode_string(data):
    # LLVM prints byte 0x5c as \\ as well as accepting the hexadecimal \5C form.
    parts = re.findall(LLVM_BYTE, data)
    require("".join(parts) == data, "invalid LLVM byte-string escape")
    return bytes(92 if part == r"\\" else int(part[1:], 16) if part.startswith("\\") else ord(part)
                 for part in parts)


def anchor_mask(encoding, logical_offset):
    return mix(encoding["mask_seed"], logical_offset + 1) & 255 if encoding is not None else 0


def canonical_bytes(physical, encoding, positions):
    return bytes(physical[position] ^ anchor_mask(encoding, logical_offset)
                 for logical_offset, position in enumerate(positions))


def physical_bytes(canonical, encoding, positions):
    physical = bytearray(len(canonical))
    for logical_offset, position in enumerate(positions):
        physical[position] = canonical[logical_offset] ^ anchor_mask(encoding, logical_offset)
    return bytes(physical)


def payloads(text):
    metadata = {match["id"]: match["data"] for match in METADATA.finditer(text)}
    definitions = {match["name"]: match["body"] for match in GLOBAL_DEFINITION.finditer(text)}
    # Only unselected canonical construction globals may lack encoding metadata.
    # Follow pointer cells and tables transitively, rather than relying on direct
    # decoder-to-array references or treating llvm.used as an execution owner.
    pending = [name for function in FUNCTION.finditer(text)
               for name in re.findall(rf"@({SYMBOL})", function.group())]
    active = set()
    while pending:
        name = pending.pop()
        if name in active or name not in definitions:
            continue
        active.add(name)
        pending.extend(re.findall(rf"@({SYMBOL})", definitions[name]))
    result, represented, transformed = {}, set(), set()
    for match in GLOBALS.finditer(text):
        attachments = ANCHOR_ENCODING.findall(match.group())
        if int(match["size"]) < 100 and not attachments:
            continue
        name = match["name"]
        physical = decode_string(match["data"])
        length = int(match["size"])
        require(len(physical) == length and length > 0, f"{name}: invalid byte-array initializer")
        require(len(attachments) <= 1, f"{name}: duplicate anchor encoding metadata")
        encoding = None
        if attachments:
            require(attachments[0] in metadata, f"{name}: missing anchor encoding metadata node")
            fields = ENCODING_FIELDS.fullmatch(metadata[attachments[0]])
            require(fields is not None, f"{name}: invalid anchor encoding metadata fields")
            stride, bias, mask_seed = map(int, fields.groups())
            encoding = {"stride": stride & ((1 << 32) - 1),
                        "bias": bias & ((1 << 32) - 1), "mask_seed": mask_seed & MASK}
            require(encoding["stride"] > 0 and math.gcd(encoding["stride"], length) == 1,
                    f"{name}: anchor stride is not a positive bijection")
            require(encoding["bias"] < length, f"{name}: anchor bias is outside the payload")
            positions = tuple((logical_offset * encoding["stride"] + encoding["bias"]) % length
                              for logical_offset in range(length))
        else:
            require(name not in active, f"{name}: execution-bearing anchor lacks encoding metadata")
            positions = tuple(range(length))
        canonical = canonical_bytes(physical, encoding, positions)
        require(physical_bytes(canonical, encoding, positions) == physical,
                f"{name}: physical anchor does not roundtrip exactly")
        result.setdefault(canonical, []).append({
            "name": name, "physical": physical, "encoding": encoding, "positions": positions,
            "data_start": match.start("data"), "data_end": match.end("data")})
        represented.add(name)
        if encoding is not None:
            transformed.add(canonical)
    require(result and transformed, "missing complete transformed VM payloads")
    require(all(canonical in transformed for canonical in result),
            "raw construction payload has no corresponding transformed anchor pool")
    require(all(name in represented for name, body in definitions.items() if ANCHOR_ENCODING.search(body)),
            "encoded anchor is not represented by a complete byte-array initializer")
    return result


def instruction_label(label):
    if match := re.fullmatch(r"vm\.(\d+)", label):
        return int(match[1]), "header"
    if match := re.fullmatch(r"vm\.island\.(?:subhelper\.)?\d+\.\d+\.(\d+)", label):
        return int(match[1]), "header"
    if match := re.fullmatch(r"vm\.(?:island\.(?:subhelper\.)?exec\.\d+\.\d+|exec)\.(\d+)", label):
        return int(match[1]), "exec"
    if match := re.fullmatch(r"vm\.edge\.(?:true|false)\.(\d+)", label):
        return int(match[1]), "exec"
    if match := re.fullmatch(r"vm\.(?:call|store)\.exec\.(\d+)", label):
        return int(match[1]), "exec"
    return None


def discover(text):
    rounds, instructions, replacements = [], {}, []
    # Constant callee/store addresses are loaded through cells before pointer
    # entanglement, so their original fixture symbols are absent from the body.
    fixture_symbols = {"fixture_emit": "call", "fixture_value": "store"}
    for cell in re.finditer(rf"(?m)^@({SYMBOL}) = [^\n]*constant ptr @(fixture_emit|fixture_value)(?:,|$)", text):
        fixture_symbols[cell[1]] = fixture_symbols[cell[2]]
    for function in FUNCTION.finditer(text):
        name = function["name"]
        lines, output = function.group().splitlines(), []
        current, phase, offset = None, None, None
        before, mixed, pending = None, None, []
        decoded_ids = {}
        for line in lines:
            if label := re.match(rf"^({SYMBOL}):", line):
                found = instruction_label(label[1])
                if found is not None:
                    require(not pending, "decode span crossed an instruction label")
                    current, phase = found
                    instructions.setdefault(f"{name}/{current}", {
                        "function": name, "index": current, "header": [],
                        "segments": [], "probes": [], "kind": "scalar"})
                    if phase == "header":
                        instructions[f"{name}/{current}"]["header_label"] = label[1]
                elif not label[1].startswith("obf.vm.opcode.pred.merge"):
                    current, phase = None, None
            output.append(line)
            if current is None:
                continue
            instruction = instructions[f"{name}/{current}"]
            if phase == "exec":
                for symbol in re.findall(rf"@({SYMBOL})", line):
                    if symbol in fixture_symbols:
                        instruction["kind"] = fixture_symbols[symbol]
                if "obf.vm.ret.retkey" in line:
                    instruction["kind"] = "ret"
            if "obf.vm.integrity.ptr" in line and "getelementptr" in line:
                probe = re.search(r"i32 0, i32 (\d+)", line)
                require(probe is not None, "nonconstant integrity probe offset")
                instruction["probes"].append(int(probe[1]))
                phase = "successor"
            if re.match(r"\s*%obf\.vm\.bc\.(?:span\.ptr|slot)\d* = getelementptr", line):
                position = re.search(r"i32 0, i32 (\d+)", line)
                require(position is not None, "nonconstant byte-decode offset")
                offset = int(position[1])
            if match := re.match(rf"\s*%obf\.vm\.bc\.(?:span\.)?shr\d* = lshr i64 ({VALUE}),", line):
                before = match[1]
            if match := re.match(rf"\s*%obf\.vm\.bc\.(?:span\.)?key\.word\d* = xor i64 {VALUE}, ({VALUE})$", line):
                mixed = match[1]
            if match := re.match(rf"\s*(%obf\.vm\.bc\.(?:span\.)?state\.byte\d*) = zext i8 ({VALUE}) to i64$", line):
                require(offset is not None and before is not None and mixed is not None,
                        "incomplete byte-decode round; fixture uses zero-depth MBA for discovery")
                round_id = len(rounds)
                rounds.append({"offset": offset, "instruction": f"{name}/{current}"})
                pending.append(round_id)
                decoded_ids[match[2]] = round_id
                output.append(f"  call void @fixture_capture(i32 {round_id}, i64 {before}, i64 {mixed}, i64 {match[1]})")
                before, mixed, offset = None, None, None
            if match := re.match(rf"\s*%obf\.vm\.opcode\.wide\d* = zext i8 ({VALUE}) to i32$", line):
                require(match[1] in decoded_ids, "opcode is not a captured decoded byte")
                instruction["opcode_round"] = decoded_ids[match[1]]
            if pending and re.match(r"\s*store i64 %obf\.vm\.bc\.(?:span\.)?state\.next\d*,", line):
                field = "header" if phase == "header" else "segments"
                instruction[field].append(pending)
                pending = []
        require(not pending, "unterminated byte-decode span")
        replacements.append((function.start(), function.end(), "\n".join(output)))
    instructions = {key: row for key, row in instructions.items() if row["header"]}
    require(instructions and rounds, "missing generated decode rounds")
    for row in instructions.values():
        require("opcode_round" in row, "missing captured physical opcode")
        require(all(1 <= len(chunk) <= 4 for chunk in row["header"]), "invalid header chunk length")
        require(all(len(segment) == 12 for segment in row["segments"]), "invalid encoded successor length")
        if len(row["segments"]) == 2:
            row["kind"] = "branch"
    # Build unsigned decimal fields backwards without a libc formatter: Windows
    # lli does not resolve snprintf. Even full-width values need at most 78 bytes
    # (CAP prefix, ten-digit round, three twenty-digit fields, spaces, newline).
    # Emit each complete record in one unbuffered stderr write; stdout remains
    # reserved for the protected body's effect markers and acceptance oracle.
    capture = '''
define internal i32 @fixture_capture_uint(ptr %buffer, i32 %end, i64 %value) {
entry:
  br label %digit
digit:
  %offset = phi i32 [ %end, %entry ], [ %next, %digit ]
  %remaining = phi i64 [ %value, %entry ], [ %quotient, %digit ]
  %next = sub i32 %offset, 1
  %position = getelementptr i8, ptr %buffer, i32 %next
  %remainder = urem i64 %remaining, 10
  %quotient = udiv i64 %remaining, 10
  %byte = trunc i64 %remainder to i8
  %ascii = add i8 %byte, 48
  store i8 %ascii, ptr %position, align 1
  %more = icmp ne i64 %quotient, 0
  br i1 %more, label %digit, label %done
done:
  ret i32 %next
}
define void @fixture_capture(i32 %round, i64 %before, i64 %mixed, i64 %decoded) {
entry:
  %buffer = alloca [128 x i8], align 1
  %newline = getelementptr i8, ptr %buffer, i32 127
  store i8 10, ptr %newline, align 1
  %decoded.start = call i32 @fixture_capture_uint(ptr %buffer, i32 127, i64 %decoded)
  %mixed.end = sub i32 %decoded.start, 1
  %mixed.separator = getelementptr i8, ptr %buffer, i32 %mixed.end
  store i8 32, ptr %mixed.separator, align 1
  %mixed.start = call i32 @fixture_capture_uint(ptr %buffer, i32 %mixed.end, i64 %mixed)
  %before.end = sub i32 %mixed.start, 1
  %before.separator = getelementptr i8, ptr %buffer, i32 %before.end
  store i8 32, ptr %before.separator, align 1
  %before.start = call i32 @fixture_capture_uint(ptr %buffer, i32 %before.end, i64 %before)
  %round.end = sub i32 %before.start, 1
  %round.separator = getelementptr i8, ptr %buffer, i32 %round.end
  store i8 32, ptr %round.separator, align 1
  %round.wide = zext i32 %round to i64
  %round.start = call i32 @fixture_capture_uint(ptr %buffer, i32 %round.end, i64 %round.wide)
  %start = sub i32 %round.start, 4
  %record = getelementptr i8, ptr %buffer, i32 %start
  store i8 67, ptr %record, align 1
  %prefix.a = getelementptr i8, ptr %record, i32 1
  store i8 65, ptr %prefix.a, align 1
  %prefix.p = getelementptr i8, ptr %record, i32 2
  store i8 80, ptr %prefix.p, align 1
  %prefix.space = getelementptr i8, ptr %record, i32 3
  store i8 32, ptr %prefix.space, align 1
  %count = sub i32 128, %start
  %size = zext i32 %count to i64
  %written = call i64 @fixture_write(i32 2, ptr %record, i64 %size)
  %written.ok = icmp eq i64 %written, %size
  br i1 %written.ok, label %done, label %failed
failed:
  call void @llvm.trap()
  unreachable
done:
  ret void
}
'''
    return replace_spans(text, replacements) + capture, {"rounds": rounds, "instructions": instructions}


def oracle(target, x):
    base = (x ^ 23130) + 17
    value = base * 3 if x & 1 else base + 19
    if target == "strong_integrity":
        value += 300
    return value, 200 if x & 1 else 300, 39 if x & 1 else 44


def reachable_module(text):
    # Keep whole reachable bodies, including pointer-cell/table targets and
    # startup constructors. Drop only the unrelated target and its dead helpers.
    definitions = {function["name"]: function for function in FUNCTION.finditer(text)}
    definitions.update({global_value["name"]: global_value for global_value in
                        re.finditer(rf"(?m)^@(?P<name>{SYMBOL}) = [^\n]*$", text)})
    pending = ["main"] + [name for name in definitions if name.startswith("llvm.")]
    reachable = set()
    while pending:
        name = pending.pop()
        if name in reachable or name not in definitions:
            continue
        reachable.add(name)
        pending.extend(re.findall(rf"@({SYMBOL})", definitions[name].group()))
    return replace_spans(text, [(definition.start(), definition.end(), "")
                               for name, definition in definitions.items() if name not in reachable])


def scenario(text, target, x, trap_expect=None):
    value, stored, effects = oracle(target, x)
    main = next(function for function in FUNCTION.finditer(text) if function["name"] == "main")
    observer = ""
    setup = ""
    if trap_expect is not None and sys.platform != "win32":
        setup = (f"  store i32 {trap_expect}, ptr @fixture_trap_expect\n"
                 "  call ptr @signal(i32 4, ptr @fixture_trap_observer)\n"
                 "  call ptr @signal(i32 5, ptr @fixture_trap_observer)\n")
        observer = '''
declare ptr @signal(i32, ptr)
declare i32 @raise(i32)
define void @fixture_trap_observer(i32 %number) {
entry:
  %actual = load volatile i32, ptr @fixture_value
  %expected = load volatile i32, ptr @fixture_trap_expect
  %changed = icmp ne i32 %actual, %expected
  br i1 %changed, label %dirty, label %resume
dirty:
  call i64 @fixture_write(i32 1, ptr @fixture_dirty, i64 6)
  br label %resume
resume:
  call ptr @signal(i32 %number, ptr null)
  call i32 @raise(i32 %number)
  ret void
}
'''
    replacement = f'''define i32 @main() {{
entry:
  store i32 0, ptr @fixture_effect
  store i32 -1, ptr @fixture_value
{setup}  %result = call i32 @{target}(i32 {x})
  %result.ok = icmp eq i32 %result, {value}
  %stored = load i32, ptr @fixture_value
  %stored.ok = icmp eq i32 %stored, {stored}
  %effects = load i32, ptr @fixture_effect
  %effects.ok = icmp eq i32 %effects, {effects}
  %ok1 = and i1 %result.ok, %stored.ok
  %ok = and i1 %ok1, %effects.ok
  call i64 @fixture_write(i32 1, ptr @fixture_accept, i64 7)
  %exit = select i1 %ok, i32 0, i32 23
  ret i32 %exit
}}'''
    return reachable_module(bind_writer(replace_spans(text, [(main.start(), main.end(), replacement)]) + observer))


def invoke(command, path, label):
    try:
        return subprocess.run(command + [str(path)], capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired as error:
        raise SystemExit(f"{label}: child timed out after 30 seconds\n"
                         f"stdout={error.stdout!r}\nstderr={error.stderr!r}") from error


def capture(completed, layout, target, x):
    expected = ["E1", "E2" if x & 1 else "E3", "E4", "ACCEPT"]
    values, ordered = {}, []
    first_rounds = {row["header"][0][0]: key for key, row in layout["instructions"].items()}
    require(completed.stderr.endswith("\n"), "incomplete runtime decode capture")
    for line in completed.stderr.splitlines():
        record = re.fullmatch(r"CAP (\d+) (\d+) (\d+) (\d+)", line)
        require(record is not None, f"{target}/{x}: invalid runtime decode record {line!r}")
        identifier, before, mixed, plain = map(int, record.groups())
        require(0 <= identifier < len(layout["rounds"]) and 0 <= plain <= 255 and
                0 <= before <= MASK and 0 <= mixed <= MASK, "invalid captured decode round")
        require(identifier not in values, "fixture unexpectedly revisited an instruction")
        values[identifier] = {"before": before, "mixed": mixed, "plain": plain}
        if identifier in first_rounds:
            ordered.append(first_rounds[identifier])
    require(completed.returncode == 0 and completed.stdout.splitlines() == expected,
            f"{target}/{x}: discovery did not execute the full protected body/oracle\n"
            f"exit={completed.returncode}\n{completed.stdout}\n{completed.stderr}")
    require(ordered and values, "missing runtime decode capture")
    if target == "strong_integrity":
        require(any(".island." in layout["instructions"][key]["header_label"]
                    for key in ordered), "strong positive control did not traverse state-island decoding")
    return values, ordered


def reproduce(payload, seed, offset, initial, plain):
    encoded, state = bytearray(), initial
    for index, byte in enumerate(plain):
        key = (state ^ rotr(state, 13) ^ mix(seed, offset + index + 1)) & 255
        encoded.append(byte ^ key)
        state = ((state << 8) | byte) & MASK
    return bytes(encoded), state


def classify_padding(row, seed):
    header = row["header"]
    count = 1 + mix(seed, 0x4D4554410000 + row["index"]) % 3
    meaningful_count = len(header) - count
    require(meaningful_count >= 7 and (meaningful_count - 7) % 2 == 0,
            "invalid serialized metadata field count")
    operands = (meaningful_count - 7) // 2
    # Match the complete serializer ordering, not only padding byte values:
    # a one-byte padding value can equal operand/edge-count metadata.
    fields = [(1, 0x4100, None, True), (4, 0x4200, None, False),
              (4, 0x4300, None, False), (4, 0x4400, None, False),
              (4, 0x4500, None, False), (1, 0x4600, operands, False)]
    for operand in range(operands):
        fields.extend([(1, 0x4700 + operand * 2, None, False),
                       (4, 0x4701 + operand * 2, None, False)])
    fields.append((1, 0x4800, None, False))
    for junk in range(count):
        size = 1 + mix(seed, 0x4D4554411000 + row["index"] * 8 + junk) % 4
        plain = bytes(mix(seed, 0x4D4554413000 + row["index"] * 16 + junk * 4 + byte) & 255
                      for byte in range(size))
        fields.append((size, 0x4D4554412000 + junk, int.from_bytes(plain, "little"), False))
    candidates = {}
    for ordinal, (size, salt, expected, opcode) in enumerate(fields, 1):
        candidates[ordinal] = []
        for position, chunk in enumerate(header):
            if len(chunk["plain"]) != size or chunk["opcode"] != opcode:
                continue
            if expected is not None and chunk["expected_value"] != expected:
                continue
            chunk_salt = salt ^ chunk["expected_value"] if ordinal <= meaningful_count else salt
            order_key = mix(seed, chunk_salt ^ (((row["index"] + 1) * GOLDEN) & MASK) ^
                            ((ordinal * 0x517CC1B727220A95) & MASK))
            candidates[ordinal].append((position, (order_key, ordinal)))
        require(candidates[ordinal], f"{row['function']}/{row['index']}: missing serialized header field {ordinal}")
    field_order = sorted(candidates, key=lambda ordinal: len(candidates[ordinal]))
    classifications, assigned = set(), {}

    def match_fields(depth):
        if depth == len(field_order):
            classifications.add(tuple(sorted(position for ordinal, (position, _) in assigned.items()
                                             if ordinal > meaningful_count)))
            return
        ordinal = field_order[depth]
        for position, ordering in candidates[ordinal]:
            if any(position == other_position or
                   ((position < other_position) != (ordering < other_ordering))
                   for other_position, other_ordering in assigned.values()):
                continue
            assigned[ordinal] = position, ordering
            match_fields(depth + 1)
            del assigned[ordinal]

    match_fields(0)
    require(len(classifications) == 1,
            f"{row['function']}/{row['index']}: ambiguous deterministic padding classification")
    padding = set(next(iter(classifications)))
    for position, chunk in enumerate(header):
        chunk["is_padding"] = position in padding



def materialize(layout, values, arrays):
    matches = []
    for payload in arrays:
        if all(row["offset"] < len(payload) and
               payload[row["offset"]] == (values[index]["plain"] ^
                   ((values[index]["before"] ^ rotr(values[index]["before"], 13) ^ values[index]["mixed"]) & 255))
               for index, row in enumerate(layout["rounds"]) if index in values):
            matches.append(payload)
    require(len(matches) == 1, "runtime decode does not identify one exact complete payload")
    payload = matches[0]
    first_id = next(iter(values))
    first = values[first_id]
    seeds = [seed for seed in invert_mix(first["mixed"], layout["rounds"][first_id]["offset"] + 1)
             if all(mix(seed, layout["rounds"][index]["offset"] + 1) == value["mixed"]
                    for index, value in values.items())]
    require(len(seeds) == 1, "runtime round constants do not identify a consistent bytecode seed")
    seed, result = seeds[0], {}
    for key, original in layout["instructions"].items():
        ids = sum(original["header"] + original["segments"], [])
        if not all(index in values for index in ids):
            continue
        row = dict(original)
        row["header"] = []
        row["segments"] = []
        for field in ("header", "segments"):
            for ids in original[field]:
                offsets = [layout["rounds"][index]["offset"] for index in ids]
                require(offsets == list(range(offsets[0], offsets[0] + len(ids))), "noncontiguous decode span")
                plain = bytes(values[index]["plain"] for index in ids)
                before = values[ids[0]]["before"]
                encoded, after = reproduce(payload, seed, offsets[0], before, plain)
                require(encoded == payload[offsets[0]:offsets[0] + len(ids)], "encoder disagrees with original serialized bytes")
                chunk = {"offset": offsets[0], "plain": plain, "before": before, "after": after,
                         "expected_value": int.from_bytes(plain, "little"), "is_padding": False}
                if field == "header":
                    chunk["opcode"] = original["opcode_round"] in ids
                else:
                    chunk["dispatch"] = int.from_bytes(plain[:4], "little")
                    chunk["entry"] = int.from_bytes(plain[4:], "big")
                    require(after == chunk["entry"], "successor does not restore its complete entry state")
                row[field].append(chunk)
        row["segments"].sort(key=lambda chunk: chunk["offset"])
        classify_padding(row, seed)
        result[key] = row
    return payload, seed, result


def mutate(text, payload, offset, replacement):
    require(0 <= offset < len(payload) and 0 < len(replacement) <= len(payload) - offset,
            "mutation is outside the canonical payload")
    changed = payload[:offset] + replacement + payload[offset + len(replacement):]
    require(changed != payload and len(changed) == len(payload), "mutation did not change an exact byte range")
    arrays = payloads(text)
    require(payload in arrays, "mutation missed every complete payload copy")
    replacements = []
    for anchor in arrays[payload]:
        physical = physical_bytes(changed, anchor["encoding"], anchor["positions"])
        require(canonical_bytes(physical, anchor["encoding"], anchor["positions"]) == changed,
                f"{anchor['name']}: logical mutation does not roundtrip exactly")
        require(physical != anchor["physical"], f"{anchor['name']}: logical mutation missed a physical copy")
        encoded = "".join(f"\\{byte:02X}" for byte in physical)
        replacements.append((anchor["data_start"], anchor["data_end"], encoded))
    return replace_spans(text, replacements)


def header_mutation(payload, seed, row, chunk):
    header = row["header"]
    offset = header[0]["offset"]
    plain = bytearray(b"".join(part["plain"] for part in header))
    require(not chunk["opcode"], "metadata mutation changed physical opcode")
    original_plain = bytes(plain)
    plain[chunk["offset"] - offset] ^= 1
    encoded, after = reproduce(payload, seed, offset, header[0]["before"], plain)
    require(bytes(plain) != original_plain, "coherent decoded mutation was not constructed")
    require(encoded != payload[offset:offset + len(encoded)], "coherent mutation did not change ciphertext")
    # A state-washout witness must preserve every later decoded byte and the full
    # rolling state, despite changing a proven non-padding metadata chunk.
    require(after == header[-1]["after"], "selected early metadata did not wash out")
    return offset, encoded


def check(text, discovery, layout, prefix, command):
    if sys.platform != "win32":
        import resource
        _, hard = resource.getrlimit(resource.RLIMIT_CORE)
        resource.setrlimit(resource.RLIMIT_CORE, (0, hard))
    path = pathlib.Path(str(prefix) + ".scenario.ll")
    arrays = payloads(text)
    try:
        for target in TARGETS:
            combined, paths = {}, {}
            for x in (0, 1):
                path.write_text(scenario(discovery, target, x), encoding="utf-8")
                values, ordered = capture(invoke(command, path, f"{target}/{x}/discovery"), layout, target, x)
                for identifier, value in values.items():
                    require(identifier not in combined or combined[identifier] == value, "unstable captured decode state")
                    combined[identifier] = value
                paths[x] = ordered
            payload, seed, instructions = materialize(layout, combined, arrays)
            require(all(key in instructions for order in paths.values() for key in order), "incomplete executed-instruction layout")

            def run(module, x, label, rejected=None, stored=None):
                path.write_text(scenario(module, target, x, stored if rejected is not None else None), encoding="utf-8")
                completed = invoke(command, path, f"{target}/{x}/{label}")
                lines = completed.stdout.splitlines()
                if rejected is None:
                    wanted = ["E1", "E2" if x else "E3", "E4", "ACCEPT"]
                    require(completed.returncode == 0 and lines == wanted and not completed.stderr,
                            f"{target}/{x}/{label}: protected return/store/effect oracle failed\n"
                            f"exit={completed.returncode}\n{completed.stdout}\n{completed.stderr}")
                else:
                    require(native_trap(completed.returncode) and lines == rejected,
                            f"{target}/{x}/{label}: expected native trap before affected effect; "
                            "normal returns (including wrong-value exit 23), DIRTY stores, loader errors, and late effects are failures\n"
                            f"exit={completed.returncode}\n{completed.stdout}\n{completed.stderr}")

            def prefix_before(x, key):
                before = paths[x][:paths[x].index(key)]
                calls = sum(instructions[item]["kind"] == "call" for item in before)
                stages = ["E1", "E2" if x else "E3", "E4"][:calls]
                stored = oracle(target, x)[1] if any(instructions[item]["kind"] == "store" for item in before) else -1
                return stages, stored

            for x in (0, 1):
                run(text, x, "positive-original")
            first = instructions[paths[0][0]]
            require(first["kind"] == "call" and len(first["segments"]) == 1, "fixture did not begin with an external effectful call")
            meaningful = [chunk for chunk in first["header"] if not chunk["opcode"] and not chunk["is_padding"]]
            require(meaningful, "missing first-call meaningful metadata")
            position = meaningful[-1]["offset"]
            run(mutate(text, payload, position, bytes([payload[position] ^ 1])), 0, "first-call-header", [], -1)
            for delta in (0, 4, 11):
                position = first["segments"][0]["offset"] + delta
                run(mutate(text, payload, position, bytes([payload[position] ^ 1])), 0,
                    f"first-call-successor-{delta}", [], -1)

            branches = [(key, row) for key, row in instructions.items() if row["kind"] == "branch"]
            require(len(branches) == 1, "fixture requires one real conditional VM branch")
            branch_key, branch = branches[0]
            left, right = branch["segments"]
            require((left["dispatch"], left["entry"]) != (right["dispatch"], right["entry"]), "branch successors are not distinct valid targets")
            for selected, other in ((left, right), (right, left)):
                desired = other["dispatch"].to_bytes(4, "little") + other["entry"].to_bytes(8, "big")
                encoded, state = reproduce(payload, seed, selected["offset"], selected["before"], desired)
                require(state == other["entry"] and desired != selected["plain"], "coherent valid-edge substitution was not constructed")
                mutant = mutate(text, payload, selected["offset"], encoded)
                for x in (0, 1):
                    # Both selected and unselected edge substitutions reject at
                    # the branch, before either branch's controlled store/call.
                    stages, stored = prefix_before(x, branch_key)
                    run(mutant, x, f"coherent-edge-{selected['offset']}", stages, stored)

            washout = None
            for key in paths[0]:
                row = instructions[key]
                for chunk in row["header"]:
                    end = row["header"][-1]["offset"] + len(row["header"][-1]["plain"])
                    if chunk["opcode"] or chunk["is_padding"] or chunk["offset"] >= end - 8:
                        continue
                    offset, encoded = header_mutation(payload, seed, row, chunk)
                    changed = {offset + index for index, byte in enumerate(encoded) if byte != payload[offset + index]}
                    probes = {probe for item in paths[0] for probe in instructions[item]["probes"]}
                    if not changed.intersection(probes):
                        washout = key, offset, encoded
                        break
                if washout is not None:
                    break
            require(washout is not None, "missing meaningful early-metadata washout witness independent of sampled probes")
            key, offset, encoded = washout
            stages, stored = prefix_before(0, key)
            run(mutate(text, payload, offset, encoded), 0, "meaningful-exact-reencoding-washout", stages, stored)

            # Padding is inert semantically but participates in exact integrity.
            pad = next(chunk for chunk in first["header"] if chunk["is_padding"])
            position = pad["offset"]
            run(mutate(text, payload, position, bytes([payload[position] ^ 1])), 0, "consumed-padding", [], -1)

            for x in (0, 1):
                stores = [key for key in paths[x] if instructions[key]["kind"] == "store"]
                returns = [key for key in paths[x] if instructions[key]["kind"] == "ret"]
                require(len(stores) == 1 and len(returns) == 1, "missing executed controlled store/integer return")
                for key, label in ((stores[0], "store-header"), (returns[0], "integer-return-header")):
                    row = instructions[key]
                    eligible = [chunk for chunk in row["header"] if not chunk["opcode"] and not chunk["is_padding"]]
                    require(eligible, f"missing {label} metadata")
                    position = eligible[-1]["offset"]
                    stages, stored = prefix_before(x, key)
                    run(mutate(text, payload, position, bytes([payload[position] ^ 1])), x, label, stages, stored)
                store = instructions[stores[0]]
                require(len(store["segments"]) == 1, "store missing encoded fallthrough")
                position = store["segments"][0]["offset"] + 11
                stages, stored = prefix_before(x, stores[0])
                run(mutate(text, payload, position, bytes([payload[position] ^ 1])), x,
                    "store-successor-before-store", stages, stored)

            # A future header on the inactive arm is not eagerly consumed. Avoid
            # incidental sampled diffusion dependencies, prove the untouched arm
            # still runs in full, then execute the same mutated header and trap.
            inactive = [key for key in paths[1] if key not in paths[0]]
            future = None
            active_probes = {probe for key in paths[0] for probe in instructions[key]["probes"]}
            for key in inactive:
                for chunk in instructions[key]["header"]:
                    position = chunk["offset"]
                    if position not in active_probes and not chunk["opcode"] and not chunk["is_padding"]:
                        future = key, position
                        break
                if future is not None:
                    break
            require(future is not None, "missing meaningful inactive/future header control")
            key, position = future
            mutant = mutate(text, payload, position, bytes([payload[position] ^ 1]))
            run(mutant, 0, "future-header-inactive-positive")
            stages, stored = prefix_before(1, key)
            run(mutant, 1, "future-header-executed", stages, stored)
    finally:
        path.unlink(missing_ok=True)
    print("VM metadata integrity: exact header/successor rejection before effects; coherent mutations, stores, returns, and inactive/future controls passed")


def main():
    mode, *args = sys.argv[1:]
    if mode == "discover":
        require(len(args) == 3, "discover requires <IR> <discovery IR> <layout JSON>")
        text = pathlib.Path(args[0]).read_text(encoding="utf-8")
        instrumented, layout = discover(text)
        pathlib.Path(args[1]).write_text(instrumented, encoding="utf-8")
        pathlib.Path(args[2]).write_text(json.dumps(layout), encoding="utf-8")
    elif mode == "check":
        require(len(args) >= 6 and args[4] == "--", "check requires <IR> <discovery IR> <layout JSON> <prefix> -- <lli command>")
        check(pathlib.Path(args[0]).read_text(encoding="utf-8"),
              pathlib.Path(args[1]).read_text(encoding="utf-8"),
              json.loads(pathlib.Path(args[2]).read_text(encoding="utf-8")), args[3], args[5:])
    else:
        raise SystemExit(f"unknown mode: {mode}")


if __name__ == "__main__":
    main()
