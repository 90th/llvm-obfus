import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

def run(command, *, succeeds=True, cwd=None):
    env = os.environ.copy()
    for key in ("OBF_CONFIG", "OBF_ENABLE", "OBF_SEED", "OBF_LTO_MODE", "OBF_LTO_INPUTS_VALIDATED"):
        env.pop(key, None)
    result = subprocess.run(command, env=env, cwd=cwd, capture_output=True, text=True, timeout=300)
    if (result.returncode == 0) != succeeds:
        raise RuntimeError(
            f"unexpected exit {result.returncode}: {command!r}\n{result.stdout}\n{result.stderr}"
        )
    return result


def expected_secret(value):
    return (((value ^ 0x5A5A) + 17) * 3) & 0xFFFFFFFF


def expected_branch(value):
    relay = expected_secret(value)
    if (relay & 0x40) == 0:
        return (relay + 0x1234) & 0xFFFFFFFF
    return (relay ^ 0x2468) & 0xFFFFFFFF


def expected_untouched(value):
    return ((value + 0x120) ^ 0x33) & 0xFFFFFFFF


def expected_output():
    result = 0
    for index in range(12):
        value = index * 97 + 5
        result ^= expected_secret(value)
        result ^= expected_branch(value)
        result ^= expected_untouched(value)
    return f"retained-promotion result={result & 0xFFFFFFFF}\n"


def disassemble(args, path):
    return run([args.dis, str(path), "-o", "-"]).stdout


def has_definition(module_text, name):
    return re.search(rf"^define [^\n]*@{re.escape(name)}\(", module_text, re.MULTILINE) is not None


def has_secret_definition(module_text):
    return re.search(r"^define [^\n]*@secret_vm(?:\.[^\s(]+)?\(", module_text, re.MULTILINE) is not None


def extract_definition_parts(module_text, name):
    match = re.search(
        rf"^(define [^\n]*?@{re.escape(name)}\([^\n]*\)[^\n]*?)\s*\{{(.*?)^\}}",
        module_text,
        re.MULTILINE | re.DOTALL,
    )
    if not match:
        raise RuntimeError(f"missing definition for {name}")
    return match.group(1), match.group(2)


def require_flattened_body(module_text, name):
    header, body = extract_definition_parts(module_text, name)
    if "!obf.flattened !" not in header:
        raise RuntimeError(f"promoted function {name} is missing flattened function metadata:\n{header}")

    annotated_blocks = re.findall(r"!obf\.flattened\.block !\d+", body)
    if len(annotated_blocks) < 3:
        raise RuntimeError(
            f"promoted function {name} is missing flattened branch metadata in the body:\n{body}"
        )

    state_phis = [line for line in body.splitlines() if " phi i32 " in line and line.count("[") >= 3]
    if not state_phis:
        raise RuntimeError(f"promoted function {name} is missing a multi-input flattened state phi:\n{body}")

    backedge_targets = re.findall(r"br label %([A-Za-z$._0-9]+), !obf\.flattened\.block !\d+", body)
    if not any(count >= 2 for count in Counter(backedge_targets).values()):
        annotated_targets = []
        for line in re.findall(r"^.*!obf\.flattened\.block !\d+.*$", body, re.MULTILINE):
            annotated_targets.extend(re.findall(r"label %([A-Za-z$._0-9]+)", line))
        if not any(count >= 3 for count in Counter(annotated_targets).values()):
            raise RuntimeError(
                f"promoted function {name} is missing a repeated flattened dispatch/backedge target:\n{body}"
            )


def require_native_body(module_text, name):
    header, body = extract_definition_parts(module_text, name)
    if "!obf.flattened !" in header or "!obf.flattened.block !" in body:
        raise RuntimeError(
            f"unrelated explicit none function {name} unexpectedly gained flattened protection:\n{header}\n{{{body}\n}}"
        )
    if " add i32 " not in body or " xor i32 " not in body:
        raise RuntimeError(f"native function {name} lost its direct arithmetic body:\n{body}")

def feature_report(args, config, module_path):
    result = run(
        [
            args.opt,
            "-load-pass-plugin",
            args.plugin,
            f"--obf-config={config}",
            "-passes=obf-feature-report",
            "-disable-output",
            str(module_path),
        ]
    )
    return json.loads(result.stdout)


def policy_map(report):
    return {entry["name"]: entry["policy"] for entry in report["functions"]}


def require_policy(policy, *, level, source):
    if policy["level"] != level or policy["source"] != source:
        raise RuntimeError(
            "unexpected policy: "
            f"level={policy['level']} source={policy['source']} detail={policy['detail']}"
        )


def case_modules(args, case, suffix):
    modules = {path: disassemble(args, path) for path in sorted(case.rglob(f"*.{suffix}.bc"))}
    if not modules:
        raise RuntimeError(f"no *.{suffix}.bc files under {case}")
    return modules



def unique_module_with_definition(modules, name):
    matches = [text for text in modules.values() if has_definition(text, name)]
    if len(matches) != 1:
        raise RuntimeError(f"expected one module defining {name}, found {len(matches)}")
    return matches[0]


def unique_path_with_definition(modules, name):
    matches = [path for path, text in modules.items() if has_definition(text, name)]
    if len(matches) != 1:
        raise RuntimeError(f"expected one module path defining {name}, found {len(matches)}")
    return matches[0]


def build_split(case, args, config, mode):
    target = case / "target.o"
    caller = case / "caller.o"
    binary = case / "program"
    common = [args.wrapper, f"--obf-config={config}", "-O0", f"-flto={mode}"]
    run(common + ["-c", str(args.inputs / "lto-retained-orchestrator-target.c"), "-o", str(target)])
    run(common + ["-c", str(args.inputs / "lto-retained-orchestrator-caller.c"), "-o", str(caller)])
    link = common + [
        "-Wl,--save-temps",
        "-Wl,--export-dynamic",
        str(caller),
        str(target),
        "-o",
        str(binary),
    ]
    if mode == "thin":
        link.insert(4, f"-Wl,--thinlto-cache-dir={case / 'cache'}")
    run(link)

    return binary


def build_direct(case, args, config):
    binary = case / "program"
    run(
        [
            args.wrapper,
            f"--obf-config={config}",
            "-O0",
            "-flto=full",
            "-Wl,--save-temps",
            "-Wl,--export-dynamic",
            str(args.inputs / "lto-retained-orchestrator-direct.c"),
            "-o",
            str(binary),
        ]
    )
    return binary


def require_output(binary):
    result = run([str(binary)])
    expected = expected_output()
    if result.stdout != expected:
        raise RuntimeError(f"incorrect native result from {binary}: {result.stdout!r} != {expected!r}")


def check_full_equivalence(args, config, split_case, direct_case):
    split_preopt = case_modules(args, split_case, "preopt")
    direct_preopt = case_modules(args, direct_case, "preopt")

    split_report = feature_report(args, config, unique_path_with_definition(split_preopt, "branch_none"))
    direct_report = feature_report(args, config, unique_path_with_definition(direct_preopt, "branch_none"))
    split_policies = policy_map(split_report)
    direct_policies = policy_map(direct_report)
    caller_prelink = policy_map(feature_report(args, config, split_case / "caller.o"))
    target_prelink = policy_map(feature_report(args, config, split_case / "target.o"))

    expected = {
        "secret_vm": {"level": "strong_vm", "source": "source_annotation"},
        "relay_none": {"level": "strong", "source": "source_annotation"},
        "branch_none": {"level": "strong", "source": "source_annotation"},
        "untouched_none": {"level": "none", "source": "source_annotation"},
    }

    for name, expectation in expected.items():
        if name not in direct_policies or name not in split_policies:
            raise RuntimeError(f"missing policy entry for {name}")
        require_policy(direct_policies[name], **expectation)
        require_policy(split_policies[name], **expectation)

    preserved_seed_source = {
        "secret_vm": target_prelink,
        "relay_none": caller_prelink,
        "branch_none": caller_prelink,
        "untouched_none": caller_prelink,
    }
    for name, source in preserved_seed_source.items():
        if name not in source:
            raise RuntimeError(f"missing prelink seed for {name}")
        if split_policies[name]["seed"] != source[name]["seed"]:
            raise RuntimeError(
                f"split postlink seed changed for {name}: {split_policies[name]['seed']} != {source[name]['seed']}"
            )

    split_opt = case_modules(args, split_case, "opt")
    direct_opt = case_modules(args, direct_case, "opt")
    require_flattened_body(unique_module_with_definition(split_opt, "branch_none"), "branch_none")
    require_native_body(unique_module_with_definition(split_opt, "untouched_none"), "untouched_none")
    require_native_body(unique_module_with_definition(direct_opt, "untouched_none"), "untouched_none")


def probe_thin_visibility(args, config, case):
    preopt = case_modules(args, case, "preopt")
    caller_path = unique_path_with_definition(preopt, "relay_none")
    caller_report = feature_report(args, config, caller_path)
    policies = policy_map(caller_report)
    relay = policies.get("relay_none")
    branch = policies.get("branch_none")
    if relay is None or branch is None:
        raise RuntimeError("missing ThinLTO caller policies")

    if relay["level"] == "strong" and branch["level"] == "strong":
        if relay["source"] != "source_annotation" or branch["source"] != "source_annotation":
            raise RuntimeError("ThinLTO promotion changed the retained source classification")
        opt_modules = case_modules(args, case, "opt")
        require_flattened_body(unique_module_with_definition(opt_modules, "branch_none"), "branch_none")
        require_native_body(unique_module_with_definition(opt_modules, "untouched_none"), "untouched_none")
        return "promoted"

    caller_text = preopt[caller_path]
    if has_secret_definition(caller_text):
        raise RuntimeError(
            "ThinLTO caller backend saw secret_vm but retained native caller was not promoted"
        )
    return "visibility-limited"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--wrapper", required=True)
    parser.add_argument("--opt", required=True)
    parser.add_argument("--plugin", required=True)
    parser.add_argument("--dis", default="llvm-dis")
    parser.add_argument("--work", required=True)
    args = parser.parse_args()

    args.inputs = Path(__file__).resolve().parent
    config = args.inputs / "lto-retained-orchestrator-promotion.yaml"
    work = Path(args.work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="retained-promotion-", dir=work))

    split_full = work / "split-full"
    direct_full = work / "direct-full"
    thin_case = work / "split-thin"
    split_full.mkdir()
    direct_full.mkdir()
    thin_case.mkdir()

    split_binary = build_split(split_full, args, config, "full")
    direct_binary = build_direct(direct_full, args, config)
    thin_binary = build_split(thin_case, args, config, "thin")

    require_output(split_binary)
    require_output(direct_binary)
    require_output(thin_binary)
    check_full_equivalence(args, config, split_full, direct_full)
    thin_status = probe_thin_visibility(args, config, thin_case)
    print(f"full-status: matched-same-tu")
    print(f"thin-status: {thin_status}")


if __name__ == "__main__":
    main()
