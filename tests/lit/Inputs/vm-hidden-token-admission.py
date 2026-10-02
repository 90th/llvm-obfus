import pathlib
import re
import signal
import subprocess
import sys
import tempfile


TARGETS = ("ordinary_value", "ordinary_void", "strong_value", "strong_void")
EXPECTED_VALUES = {"ordinary_value": 115, "strong_value": 337}
SYMBOL = r"[-A-Za-z$._0-9]+"
VALUE = rf"(?:%{SYMBOL}|-?\d+)"
FUNCTION = re.compile(rf"^define[^\n]*@(?P<name>{SYMBOL})\([^\n]*\)[^\n]*\{{\n.*?^\}}", re.M | re.S)
EQUALITY = re.compile(rf"^(?P<prefix>\s*%{SYMBOL} = icmp eq i64 )(?P<lhs>{VALUE}), (?P<rhs>{VALUE})(?P<suffix>.*)$")
MASK64 = (1 << 64) - 1


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def signed(value):
    value &= MASK64
    return str(value if value < (1 << 63) else value - (1 << 64))


def roots(text):
    result = {}
    for function in FUNCTION.finditer(text):
        header = function.group().split("\n", 1)[0]
        for target in TARGETS:
            if f"%fixture_{target}_input," in header and "i64 %obf.hidden_token)" in header:
                # Forwarding entry thunks share this signature. Only the body
                # tests token membership and initializes admitted VM state.
                if state_initialization(function.group().splitlines()) is None:
                    continue
                require(target not in result, f"multiple generated roots for {target}")
                result[target] = function
    require(set(result) == set(TARGETS), "missing generated VM roots")
    return result


def token_operand(line):
    equality = EQUALITY.match(line)
    if equality is None:
        return None
    lhs, rhs = equality.group("lhs", "rhs")
    if lhs == "%obf.hidden_token":
        return equality, "rhs", rhs
    if rhs == "%obf.hidden_token":
        return equality, "lhs", lhs
    return None


def state_initialization(lines):
    # The bytecode state is field zero of the VM state struct, not an array
    # GEP into bytecode or a dispatch table.
    fields = [match.group(1) for line in lines if (match := re.match(
        rf"\s*(%{SYMBOL}) = getelementptr[^\{{]*\{{ i64, i32, i32, i64, [^}}]*\}}, "
        rf"ptr %{SYMBOL}, i32 0, i32 0(?:,.*)?$", line))]
    if len(fields) != 1:
        return None
    admitted = {"false"}
    accepted_block = None
    for line in lines:
        if token_operand(line) is not None:
            admitted.add(line.split(" = ", 1)[0].strip())
        merged = re.match(rf"\s*(%{SYMBOL}) = or i1 (%{SYMBOL}|false), (%{SYMBOL}|false)$", line)
        if merged is not None and merged[2] in admitted and merged[3] in admitted:
            admitted.add(merged[1])
        branch = re.match(rf"\s*br i1 (%{SYMBOL}), label %({SYMBOL}), label %{SYMBOL}(?:,.*)?$", line)
        if branch is not None and branch[1] in admitted:
            accepted_block = branch[2]
            break
    if accepted_block is None:
        return None
    state_store = re.compile(rf"\s*store i64 (?P<value>{VALUE}), ptr {re.escape(fields[0])}(?:,.*)?$")
    initializers = []
    in_accepted_block = False
    for index, line in enumerate(lines):
        label = re.match(rf"^({SYMBOL}):", line)
        if label is not None:
            in_accepted_block = label[1] == accepted_block
        store = state_store.match(line) if in_accepted_block else None
        if store is not None:
            initializers.append((index, store["value"]))
    return initializers[0] if len(initializers) == 1 else None


def return_key(text, target):
    # Trace the public wrapper's returned value, stopping at calls: the
    # remaining global i64 load is the key used to decode the VM result.
    wrapper = next(function for function in FUNCTION.finditer(text) if function.group("name") == target)
    definitions = {match[1]: match[2] for match in re.finditer(
        rf"(?m)^[ \t]*(%{SYMBOL}) = ([^\n]+)$", wrapper.group())}
    returned = re.findall(rf"(?m)^[ \t]*ret i32 ({VALUE})$", wrapper.group())
    require(len(returned) == 1, f"ambiguous wrapper return for {target}")
    pending, visited, keys = returned[:], set(), set()
    while pending:
        value = pending.pop()
        if value in visited:
            continue
        visited.add(value)
        expression = definitions.get(value, "")
        if re.match(r"(?:(?:tail|musttail|notail) )?call ", expression):
            continue
        key = re.match(rf"load i64, ptr @({SYMBOL})(?:,.*)?$", expression)
        if key is not None:
            keys.add(key[1])
        pending.extend(re.findall(rf"%{SYMBOL}", expression))
    require(len(keys) == 1, f"ambiguous VM return key for {target}")
    return next(iter(keys))


def replace_spans(text, replacements):
    for start, end, replacement in sorted(replacements, reverse=True):
        text = text[:start] + replacement + text[end:]
    return text


def wrapper_checks():
    # Introduce address-taking only after policy has admitted the VM targets.
    pointers = "".join(f"@{target}_pointer = global ptr @{target}\n" for target in TARGETS)
    lines = ["define i32 @fixture_check_wrappers(i32 %direct_exit) {", "entry:",
             "  %ok0 = icmp eq i32 %direct_exit, 0"]
    for index, target in enumerate(TARGETS):
        lines.append("  store i32 -1, ptr @fixture_effect")
        if target == "strong_void":
            lines.append("  store i32 -1, ptr @fixture_state")
        lines.append(f"  %pointer{index} = load ptr, ptr @{target}_pointer")
        if target in EXPECTED_VALUES:
            lines.append(f"  %result{index} = call i32 %pointer{index}(i32 37)")
            result_check = f"  %result.ok{index} = icmp eq i32 %result{index}, {EXPECTED_VALUES[target]}"
        else:
            lines.append(f"  call void %pointer{index}(i32 37)")
            result_check = None
        lines.extend([f"  %effect{index} = load i32, ptr @fixture_effect",
                      f"  %effect.ok{index} = icmp eq i32 %effect{index}, 37"])
        if target == "strong_void":
            lines.append(f"  %state{index} = load i32, ptr @fixture_state")
            result_check = f"  %result.ok{index} = icmp eq i32 %state{index}, 337"
        target_ok = f"%effect.ok{index}"
        if result_check is not None:
            lines.extend([result_check,
                          f"  %target.ok{index} = and i1 {target_ok}, %result.ok{index}"])
            target_ok = f"%target.ok{index}"
        lines.append(f"  %ok{index + 1} = and i1 %ok{index}, {target_ok}")
    lines.extend([f"  %exit = select i1 %ok{len(TARGETS)}, i32 0, i32 1",
                  "  ret i32 %exit", "}"])
    return pointers + "\n".join(lines) + "\n"


def bind_fixture_writer(text):
    # Use unbuffered writes: Windows lli can resolve stdio calls to different
    # CRT buffers, so fflush(NULL) does not prove that a side effect is visible.
    declaration = "declare i64 @fixture_write(i32, ptr, i64)"
    require(declaration in text, "missing fixture writer declaration")
    windows = sys.platform == "win32"
    symbol, width = ("_write", "i32") if windows else ("write", "i64")
    length = "  %length = trunc i64 %size to i32\n" if windows else ""
    result = "  %result = sext i32 %written to i64\n" if windows else ""
    writer = (f"declare {width} @{symbol}(i32, ptr, {width})\n"
              + "define i64 @fixture_write(i32 %fd, ptr %data, i64 %size) {\nentry:\n"
              + length
              + f"  %written = call {width} @{symbol}(i32 %fd, ptr %data, {width} "
              + ("%length" if windows else "%size") + ")\n"
              + result + "  ret i64 " + ("%result" if windows else "%written") + "\n}")
    return text.replace(declaration, writer, 1)


def discover(text):
    replacements = []
    root_functions = roots(text)
    for target_id, target in enumerate(TARGETS):
        function = root_functions[target]
        lines = function.group().splitlines()
        initializer = state_initialization(lines)
        require(initializer is not None, f"ambiguous admitted state initialization for {target}")
        state_index, state_value = initializer
        instrumented = []
        token_index, state_count = 0, 0
        for line_index, line in enumerate(lines):
            instrumented.append(line)
            token = token_operand(line)
            if token is not None:
                instrumented.append(f"  call void @fixture_capture(i32 0, i32 {target_id}, i32 {token_index}, i64 {token[2]})")
                token_index += 1
            if line_index == state_index:
                instrumented.append(f"  call void @fixture_capture(i32 1, i32 {target_id}, i32 0, i64 {state_value})")
                state_count += 1
        require(token_index >= 3 and state_count == 1, f"missing caller tokens/state initialization for {target}")
        replacements.append((function.start(), function.end(), "\n".join(instrumented)))
    main = next(function for function in FUNCTION.finditer(text) if function.group("name") == "main")
    exit = re.search(rf"(?m)^[ \t]*ret i32 (?P<value>{VALUE})$", main.group())
    require(exit is not None, "missing discovery main return")
    main_text = (main.group()[:exit.start()]
                 + f"  %fixture.wrapper.exit = call i32 @fixture_check_wrappers(i32 {exit.group('value')})\n"
                 + "  ret i32 %fixture.wrapper.exit" + main.group()[exit.end():])
    replacements.append((main.start(), main.end(), main_text))
    fmt = "CAP %d %d %d %llu\n\0"
    encoded = fmt.replace("\n", r"\0A").replace("\0", r"\00")
    capture = f'''
@fixture_capture_format = private constant [{len(fmt)} x i8] c"{encoded}"
define void @fixture_capture(i32 %kind, i32 %target, i32 %index, i64 %value) {{
entry:
  call i32 (ptr, ...) @printf(ptr @fixture_capture_format, i32 %kind, i32 %target, i32 %index, i64 %value)
  ret void
}}
'''
    return bind_fixture_writer(replace_spans(text, replacements) + capture + wrapper_checks())


def captured_values(path):
    tokens = [{} for _ in TARGETS]
    seeds = [set() for _ in TARGETS]
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("CAP "):
            continue
        _, kind, target, index, value = line.split()
        kind, target, index, value = map(int, (kind, target, index, value))
        require(0 <= target < len(TARGETS), "invalid capture target")
        if kind == 0:
            require(index not in tokens[target] or tokens[target][index] == value,
                    f"unstable opaque token for {TARGETS[target]}")
            tokens[target][index] = value
        else:
            require(kind == 1, "invalid capture kind")
            seeds[target].add(value)
    for target_id, target in enumerate(TARGETS):
        require(len(tokens[target_id]) >= 3 and len(seeds[target_id]) == 1,
                f"incomplete runtime capture for {target}")
    return tokens, [next(iter(values)) for values in seeds]


def reachable_module(text):
    # Follow globals as well as functions. Keep each reachable body intact.
    definitions = {function["name"]: function for function in FUNCTION.finditer(text)}
    definitions.update({global_value["name"]: global_value for global_value in
                        re.finditer(rf"(?m)^@(?P<name>{SYMBOL}) = [^\n]*$", text)})
    retention_lists = {"llvm.used", "llvm.compiler.used"}
    seed_ctor_name = "__obf_vm_seed_ctor"
    seed_ctor = definitions.get(seed_ctor_name)
    seed_stores = []
    if seed_ctor is not None:
        # This generated constructor contains only independent seed stores.
        # A store matters only if a reachable wrapper or resolver reads its seed.
        lines = seed_ctor.group().splitlines()
        require(lines[0] == f"define private void @{seed_ctor_name}() {{"
                and lines[1] == "entry:" and lines[-2:] == ["  ret void", "}"],
                "unexpected VM seed constructor structure")
        store_pattern = re.compile(
            rf"  store i64 xor \(i64 ptrtoint \(ptr @{SYMBOL} to i64\), i64 -?\d+\), "
            rf"ptr @(?P<destination>{SYMBOL}), align \d+")
        for line in lines[2:-2]:
            store = store_pattern.fullmatch(line)
            require(store is not None, "unexpected VM seed constructor instruction")
            destination = store["destination"]
            require(destination in definitions and re.fullmatch(
                rf"@{re.escape(destination)} = private global i64 0(?:, align \d+)?",
                definitions[destination].group()) is not None,
                "VM seed constructor destination is not a private zero-initialized seed")
            seed_stores.append((destination, line))

    pending = ["main"] + [name for name in definitions
                          if name.startswith("llvm.") and name not in retention_lists]
    reachable, retained_seeds = set(), set()
    while True:
        while pending:
            name = pending.pop()
            if name in reachable or name not in definitions:
                continue
            reachable.add(name)
            if name != seed_ctor_name and name not in retention_lists:
                pending.extend(re.findall(rf"@({SYMBOL})", definitions[name].group()))
        if seed_ctor_name not in reachable:
            break
        # Seed stores can retain wrappers with further resolver dependencies.
        selected = [(destination, line) for destination, line in seed_stores
                    if destination in reachable and destination not in retained_seeds]
        if not selected:
            break
        for destination, line in selected:
            retained_seeds.add(destination)
            pending.extend(re.findall(rf"@({SYMBOL})", line))

    replacements = {}
    if seed_ctor_name in reachable:
        replacements[seed_ctor_name] = "\n".join(
            lines[:2] + [line for destination, line in seed_stores if destination in retained_seeds]
            + lines[-2:])
    for name in retention_lists & definitions.keys():
        # llvm.used preserves existing dependencies, not unrelated VM targets.
        retention = re.fullmatch(
            rf"(?P<prefix>@{re.escape(name)} = appending global )\[\d+ x ptr\] "
            rf"\[(?P<operands>(?:ptr @{SYMBOL}(?:, ptr @{SYMBOL})*)?)\](?P<suffix>.*)",
            definitions[name].group())
        require(retention is not None, f"unexpected @{name} operand list")
        operands = [operand for operand in retention["operands"].split(", ") if operand
                    and (operand.removeprefix("ptr @") in reachable
                         or operand.removeprefix("ptr @") not in definitions)]
        if operands:
            reachable.add(name)
            replacements[name] = (f"{retention['prefix']}[{len(operands)} x ptr] "
                                  f"[{', '.join(operands)}]{retention['suffix']}")

    # Join once to avoid repeated copies of the unrelated protected bodies.
    pieces, cursor = [], 0
    for name, definition in sorted(definitions.items(), key=lambda item: item[1].start()):
        if name in reachable and name not in replacements:
            continue
        pieces.append(text[cursor:definition.start()])
        pieces.append(replacements.get(name, "") if name in reachable else "")
        cursor = definition.end()
    pieces.append(text[cursor:])
    return "".join(pieces)


def scenario(text, target, token):
    function = roots(text)[target]
    if target in EXPECTED_VALUES:
        call = f"  %result.raw = call i32 @{function.group('name')}(i32 37, i64 {signed(token)})"
        result_check = (f"  %return.key = load i64, ptr @{return_key(text, target)}\n"
                        + f"  %token.key = xor i64 %return.key, {signed(token)}\n"
                        + "  %return.mask = trunc i64 %token.key to i32\n"
                        + "  %result = xor i32 %result.raw, %return.mask\n"
                        + f"  %result.ok = icmp eq i32 %result, {EXPECTED_VALUES[target]}")
    else:
        call = f"  call void @{function.group('name')}(i32 37, i64 {signed(token)})"
        result_check = None
    if target == "strong_void":
        result_check = "  %state = load i32, ptr @fixture_state\n  %result.ok = icmp eq i32 %state, 337"
    checks = "  %ok = icmp eq i32 %effect, 37"
    if result_check is not None:
        checks = ("  %effect.ok = icmp eq i32 %effect, 37\n" + result_check
                  + "\n  %ok = and i1 %effect.ok, %result.ok")
    main = next(function for function in FUNCTION.finditer(text) if function.group("name") == "main")
    replacement = f'''define i32 @main() {{
entry:
  store i32 -1, ptr @fixture_effect
  store i32 -1, ptr @fixture_state
{call}
  %effect = load i32, ptr @fixture_effect
{checks}
  call i64 @fixture_write(i32 1, ptr @fixture_accept, i64 7)
  %exit = select i1 %ok, i32 0, i32 1
  ret i32 %exit
}}'''
    return reachable_module(bind_fixture_writer(replace_spans(text, [(main.start(), main.end(), replacement)])))


def register_tokens(text, target, values):
    function = roots(text)[target]
    lines = function.group().splitlines()
    index = 0
    for line_index, line in enumerate(lines):
        token = token_operand(line)
        if token is None:
            continue
        if index < len(values):
            equality, operand, _ = token
            start, end = equality.span(operand)
            lines[line_index] = line[:start] + signed(values[index]) + line[end:]
        index += 1
    require(index >= len(values), f"insufficient membership entries for {target}")
    return replace_spans(text, [(function.start(), function.end(), "\n".join(lines))])


def native_trap(returncode):
    if sys.platform == "win32":
        # LLVM lowers llvm.trap to an illegal instruction or breakpoint.
        # Normalize both signed and unsigned Windows exception exit codes.
        return (returncode & 0xFFFFFFFF) in (0xC000001D, 0x80000003)
    return returncode in (-signal.SIGILL, -signal.SIGTRAP)


def check(text, captures, prefix, command):
    if sys.platform != "win32":
        import resource

        # Rejection deliberately traps. Core collection can outlive the
        # subprocess deadline; disable dumps, not signals or trap checks.
        _, hard_limit = resource.getrlimit(resource.RLIMIT_CORE)
        resource.setrlimit(resource.RLIMIT_CORE, (0, hard_limit))
    tokens, seeds = captured_values(captures)
    prefix = pathlib.Path(prefix)

    def run(module, target, token, admitted, label):
        # A fresh directory also avoids overwriting an older interrupted lit
        # run's scenario while its lli process still has the file open.
        with tempfile.TemporaryDirectory(prefix=prefix.name + ".scenario-", dir=prefix.parent) as directory:
            path = pathlib.Path(directory) / f"{target}-{label}.ll"
            path.write_text(scenario(module, target, token), encoding="utf-8")
            try:
                # Invoke lli directly, not through a shell. subprocess.run
                # kills and waits for this child on timeout before cleanup.
                completed = subprocess.run(command + [str(path)], capture_output=True, text=True, timeout=30)
            except subprocess.TimeoutExpired as error:
                raise SystemExit(f"{target}/{label}: token {token:#018x} timed out\n"
                                 f"stdout={error.stdout!r}\nstderr={error.stderr!r}") from error
        if admitted:
            require(completed.returncode == 0 and completed.stdout.splitlines() == ["SIDE", "ACCEPT"],
                    f"{target}/{label}: registered token rejected or side effects incorrect\n"
                    f"exit={completed.returncode}\n{completed.stdout}\n{completed.stderr}")
        else:
            require(native_trap(completed.returncode) and completed.stdout == "",
                    f"{target}/{label}: expected native trap before protected side effects; "
                    f"normal exits and LLVM parse/loading failures are not rejection\n"
                    f"exit={completed.returncode}\n{completed.stdout}\n{completed.stderr}")

    for target_id, target in enumerate(TARGETS):
        membership_count = sum(token_operand(line) is not None
                               for line in roots(text)[target].group().splitlines())
        require(set(tokens[target_id]) == set(range(membership_count)),
                f"{target}: missing runtime capture for a registered token")
        registered = list(tokens[target_id].values())
        canonical = seeds[target_id]
        require(canonical not in registered and 0 not in registered,
                f"{target}: fixture requires unregistered canonical and zero tokens")
        for index, token in tokens[target_id].items():
            run(text, target, token, True, f"registered-{index}")
        other = 1
        while other in registered or other == canonical:
            other += 1
        for label, token in (("canonical-impostor", canonical), ("zero", 0), ("other-invalid", other)):
            run(text, target, token, False, label)
        # These membership-only fixture variants leave bytecode, target
        # encoding, and the full admission CFG unchanged.
        member_text = register_tokens(text, target, [canonical])
        run(member_text, target, canonical, True, "canonical-registered")
        duplicate_text = register_tokens(text, target, [registered[0], registered[0]])
        run(duplicate_text, target, registered[0], True, "duplicate-member")
        run(duplicate_text, target, other, False, "duplicate-nonmember")
    print("VM hidden-token admission: registered callers admitted; impostors trap before side effects")


def main():
    mode, *args = sys.argv[1:]
    if mode == "config":
        targets = "".join(f"  - match: {target}\n    level: {'strong_vm' if target.startswith('strong') else 'vm'}\n"
                          for target in TARGETS)
        pathlib.Path(args[0]).write_text(
            "seed: 2031\ndefault_level: none\ntargets:\n" + targets
            + "security:\n  fail_on_public_obf_symbol: true\n",
            encoding="utf-8")
    elif mode == "discover":
        pathlib.Path(args[1]).write_text(discover(pathlib.Path(args[0]).read_text(encoding="utf-8")), encoding="utf-8")
    elif mode == "check":
        require(len(args) >= 5 and args[3] == "--", "check requires <IR> <captures> <prefix> -- <lli command>")
        check(pathlib.Path(args[0]).read_text(encoding="utf-8"), pathlib.Path(args[1]), args[2], args[4:])
    else:
        raise SystemExit(f"unknown mode: {mode}")


if __name__ == "__main__":
    main()
