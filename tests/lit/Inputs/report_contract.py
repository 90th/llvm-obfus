import argparse
import json
from pathlib import Path
import re


FEATURE_KEYS = {
    "schema", "module", "function_count", "functions", "predictions", "observations"
}
COVERAGE_KEYS = {
    "schema", "module", "evidence", "requested_policy", "admission", "emission",
    "finalization", "roles", "capture", "absent_outcome"
}
EVENT_KEYS = {"mechanism", "owner", "target", "status", "reason", "count", "scope"}
PREDICTION_KEYS = {"pass", "target_kind", "target_name", "status", "evidence", "detail", "count"}
VALIDATION_CLAIMS = {
    "native_execution", "native_validation", "security_validation", "security_strength",
    "protection_strength", "native_validated", "security_validated", "runtime_validated"
}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def load(path):
    with Path(path).open() as stream:
        return json.load(stream)


def feature_contract(report):
    require(FEATURE_KEYS.issubset(report), "prediction contract fields missing")
    require(not ({"transforms", "admission", "emission", "finalization", "roles"} | VALIDATION_CLAIMS).intersection(report),
            "predictions must not expose obsolete outcomes or validation claims")
    require(report["schema"] == "obf.feature_report.v4", "wrong prediction schema")
    functions = {entry["name"]: entry for entry in report["functions"]}
    require(len(functions) == len(report["functions"]) == report["function_count"],
            "function identities/count disagree")
    predictions = {}
    for entry in report["predictions"]:
        require(PREDICTION_KEYS.issubset(entry), "prediction contract fields missing")
        require(not ({"emission", "emitted", "applied"} | VALIDATION_CLAIMS).intersection(entry),
                "prediction exposes outcome or validation claims")
        require(entry["evidence"] == "candidate_analysis", "prediction claims non-candidate evidence")
        require(entry["status"] in {"candidate", "not_candidate"}, "prediction claims an outcome")
        require(type(entry["count"]) is int and entry["count"] >= 0, "invalid prediction count")
        key = (entry["target_name"], entry["pass"])
        require(key not in predictions, f"duplicate prediction: {key}")
        predictions[key] = entry
    for entry in report["observations"]:
        require(entry["status"] == "observed" and entry["evidence"] == "structural_observation",
                "structural observation claims emission or validation")
    return functions, predictions


def coverage_contract(report):
    require(COVERAGE_KEYS.issubset(report), "coverage contract fields missing")
    require(not ({"transforms", "predictions"} | VALIDATION_CLAIMS).intersection(report),
            "coverage must not expose predictions or native/security claims")
    require(report["schema"] == "obf.coverage_report.v1", "wrong outcome schema")
    require(report["evidence"] == "compiler_report", "compiler outcomes claim stronger evidence")
    require(report["capture"] in {"enabled", "not_enabled"}, "outcome capture availability missing")
    require(report["absent_outcome"] == "not_observed", "absent events must not claim negative protection results")
    for stage in ("admission", "emission", "finalization"):
        require(isinstance(report[stage], list), f"{stage} is not an event array")
        for event in report[stage]:
            require(EVENT_KEYS.issubset(event), f"invalid {stage} event fields")
            require(not VALIDATION_CLAIMS.intersection(event), "compiler stage claims native/security validation")
            require(type(event["count"]) is int and event["count"] >= 0, "invalid outcome count")
            require(event["status"] not in {"candidate", "not_candidate", "applied"},
                    "outcome ledger contains a prediction or ambiguous status")
            require(all(isinstance(event[key], str) for key in EVENT_KEYS - {"count"}),
                    "invalid outcome identity/reason type")
            require(all(event[key] for key in ("mechanism", "target", "status", "scope")),
                    "missing outcome identity")
    for role in report["roles"]:
        require({"owner", "target", "role", "obligations"}.issubset(role), "invalid role fields")
        require(isinstance(role["obligations"], list), "role obligations are not an array")
    return report


def no_emission(report, capture="enabled"):
    coverage_contract(report)
    require(report["capture"] == capture, "ledger capture availability does not match the executed passes")
    require(all(not report[stage] for stage in ("admission", "emission", "finalization")),
            "policy selection or prediction was mistaken for an executed stage")


def prediction_contract(args):
    functions, predictions = feature_contract(load(args.report))
    require(set(functions) == {"split_me", "keep_plain", "first_char", "vm_me", "strong_vm_me", "main"},
            "prediction report lost a fixture function")
    for name in ("vm_me", "strong_vm_me"):
        event = predictions[(name, "vm")]
        require(event["target_kind"] == "function" and event["status"] == "candidate" and event["count"] > 0,
                f"eligible VM body not reported as a candidate: {name}")
        require(functions[name]["policy"]["allow_vm"], f"VM policy lost for {name}")
    for mechanism in ("block_split", "constant_encoding"):
        require(predictions[("split_me", mechanism)]["status"] == "candidate",
                f"eligible split_me {mechanism} not predicted")
    require(predictions[("keep_plain", "block_split")]["status"] == "not_candidate",
            "an unsplittable body was predicted as splittable")
    for name in (".secret", ".plain"):
        event = predictions[(name, "string_encoding")]
        require(event["target_kind"] == "global" and event["status"] == "candidate",
                f"string candidate identity lost: {name}")
    no_emission(load(args.coverage))
    no_emission(load(args.uncaptured), capture="not_enabled")


def abi_contract(args):
    report = coverage_contract(load(args.report))
    expected = "rejected" if args.strict else "skipped"
    events = [event for event in report["admission"]
              if event["mechanism"] == "vm" and event["owner"] == "abi_target"
              and event["target"] == "abi_target" and event["scope"] == "whole_function"]
    require(len(events) == 1 and events[0]["status"] == expected and events[0]["count"] == 0,
            "byval boundary rejection was not recorded as actual admission")
    require("ABI-affecting attribute" in events[0]["reason"], "byval rejection reason lost")
    require(not report["emission"], "ABI-rejected body claims emission")
    require(not any(role["role"] in {"public_wrapper", "regional_wrapper", "vm_implementation", "vm_entry_thunk"}
                    for role in report["roles"]), "ABI-rejected body claims generated VM roles")
    if args.predictions:
        _, predictions = feature_contract(load(args.predictions))
        require(predictions[("abi_target", "vm")]["status"] == "candidate",
                "byval fixture no longer exercises candidate versus actual boundary rejection")
    if args.ir:
        text = Path(args.ir).read_text()
        require("ptr byval(i32) %p" in text and "%a = xor i32 %x, 4660" in text,
                "ABI rejection changed the source body")
        require("__obf_vm_" not in text, "ABI rejection emitted VM artifacts")


def incoming_contract(args):
    report = coverage_contract(load(args.report))
    restrictions = [event for event in report["admission"]
                    if event["mechanism"] == "vm_incoming_site" and event["owner"] == "vm_target"]
    expected = {"caller_invoke": "invoke"}
    if not args.strict:
        expected.update({"caller_musttail": "musttail", "caller_bundle": "operand-bundle"})
    require(len(restrictions) == len(expected), "incoming restriction observations lost or duplicated")
    for caller, kind in expected.items():
        matches = [event for event in restrictions if caller in event["reason"] and kind in event["reason"]]
        require(len(matches) == 1 and matches[0]["status"] == ("rejected" if args.strict else "preserved"),
                "incoming restriction lost its caller, kind, or admission decision")
    emitted = [event for event in report["emission"]
               if event["mechanism"] == "vm" and event["status"] == "emitted"]
    require(not emitted if args.strict else len(emitted) == 1,
            "incoming restriction report disagrees with actual VM emission")


def region_contract(args):
    report = coverage_contract(load(args.report))
    owners = {"strong_vm_region", "strong_vm_two_regions"}
    roles = report["roles"]
    emitted = [event for event in report["emission"] if event["mechanism"] == "vm"]
    require(emitted and {event["owner"] for event in emitted} == owners,
            "regional emission lost original owner associations")
    if args.ir:
        text = Path(args.ir).read_text()
        definitions = set(re.findall(r'^define\b[^\n]*@([^\s(]+)\(', text, re.MULTILINE))
    for owner in owners:
        owner_events = [event for event in emitted if event["owner"] == owner]
        extracted = {event["target"] for event in report["admission"]
                     if event["owner"] == owner and event["mechanism"] == "vm_regional_extraction"
                     and event["status"] == "extracted"}
        require(owner_events and extracted, f"regional VM coverage missing for {owner}")
        for event in owner_events:
            target = event["target"]
            require(event["scope"] == "regional" and event["count"] > 0 and event["status"] == "emitted",
                    "regional coverage masquerades as whole-function coverage or admission")
            require(target != owner and target in extracted, "emitted region not associated with extraction")
            admitted = [item for item in report["admission"]
                        if item["mechanism"] == "vm" and item["owner"] == owner and item["target"] == target
                        and item["scope"] == "regional" and item["status"] == "admitted"]
            require(admitted, "emitted region lost its admission association")
            wrapper_roles = [role for role in roles if role["owner"] == owner
                             and role["target"] == target and role["role"] == "regional_wrapper"]
            require(wrapper_roles and {"vm_dispatch", "hidden_token_production"}.issubset(wrapper_roles[0]["obligations"]),
                    "emitted regional wrapper lost owner or obligations")
            if args.ir:
                require(target in definitions, "ledger claims a wrapper absent from actual output IR")
                body = re.search(r'^define\b[^\n]*@' + re.escape(target)
                                 + r'\([^\n]*\)[^\n]*\{\n(.*?)^\}', text, re.MULTILINE | re.DOTALL)
                require(body and re.search(r'\bcall\b[^\n]*%[^(\s]+\([^\n]*,\s*i64\s+[^)\n]+\)', body[1]),
                        "regional emission claims a wrapper without an indirect hidden-token VM call")
        for role_name, obligation in (("vm_implementation", "vm_execution"),
                                      ("vm_entry_thunk", "hidden_token_forwarding")):
            generated = [role for role in roles if role["owner"] == owner and role["role"] == role_name]
            require(generated and all(obligation in role["obligations"] for role in generated),
                    f"{owner} lost {role_name} association/obligation")
            require(len({role["target"] for role in generated}) >= len({event["target"] for event in owner_events}),
                    f"{owner} lost per-region generated {role_name} associations")
            if args.ir:
                require(all(role["target"] in definitions for role in generated),
                        "ledger claims generated roles absent from actual output IR")


def policy_snapshots(report):
    no_emission(report)
    snapshots = {}
    for event in report["requested_policy"]:
        key = (event["owner"], event["phase"])
        require(key not in snapshots, f"original selection was overwritten or repeated: {key}")
        require(event["owner"] == event["target"] and event["scope"] == "function",
                "policy snapshot lost original function identity")
        snapshots[key] = event["policy"]
    return snapshots


def selection_contract(args):
    functions, _ = feature_contract(load(args.report))
    snapshots = policy_snapshots(load(args.coverage))
    expected = {
        "override_me": ("none", "explicit_override", "override:override_me"),
        "annotated": ("strong", "source_annotation", "annotation:obf:strong"),
        "strong_vm_fn": ("strong_vm", "config_rule", "config match:strong_vm_fn"),
        "stringy": ("light", "automatic_analysis", "automatic:string-sensitive"),
        "default_fn": ("none", "default", "default"),
    }
    for name, (level, source, reason) in expected.items():
        policy = functions[name]["policy"]
        require((policy["level"], policy["source"], policy["detail"]) == (level, source, reason),
                f"selection provenance lost for {name}")
        require(snapshots[(name, "selected")] == policy, f"selected snapshot dropped policy fields for {name}")
        require(re.fullmatch(r"0x[0-9a-f]+", policy["seed"]), "selection seed representation changed")
        require(all(flag in policy for flag in ("allow_zero_comparison", "allow_opaque_gep", "allow_self_checksum")),
                "policy serialization dropped permission flags")
    require(functions["stringy"]["policy"]["minimum_security_floor"] == "light",
            "automatic selection lost its security floor request")


def promotion_contract(args):
    functions, _ = feature_contract(load(args.report))
    snapshots = policy_snapshots(load(args.coverage))
    core = functions["secret_core"]["policy"]
    require(core["level"] == "strong_vm" and core["source"] == "config_rule",
            "callee selection provenance changed")
    require(snapshots[("secret_core", "selected")] == core, "callee selection was not retained")
    for name, callee in (("relay", "secret_core"), ("main", "relay")):
        selected = snapshots[(name, "selected")]
        effective = snapshots[(name, "effective")]
        require((selected["level"], selected["source"], selected["detail"]) == ("none", "default", "default"),
                "promotion erased original default selection")
        require(effective == functions[name]["policy"] and effective["level"] == "strong",
                "effective promotion disagrees with feature policy")
        require(effective["source"] == selected["source"] and effective["seed"] == selected["seed"],
                "promotion changed retained selection source or seed")
        require(effective["detail"].startswith(selected["detail"] + ";")
                and "orchestrator promotion" in effective["detail"] and callee in effective["detail"],
                "promotion lost original selection or protected callee reason")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("case", choices=("predictions", "abi", "incoming", "region", "selection", "promotion"))
    parser.add_argument("report")
    parser.add_argument("--coverage")
    parser.add_argument("--uncaptured")
    parser.add_argument("--predictions")
    parser.add_argument("--ir")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()
    {"predictions": prediction_contract, "abi": abi_contract, "incoming": incoming_contract,
     "region": region_contract, "selection": selection_contract,
     "promotion": promotion_contract}[args.case](args)


if __name__ == "__main__":
    main()
