import argparse
from pathlib import Path
import re

from report_contract import coverage_contract, load, require


def resolve_owner(name, text):
    visited = set()
    while name not in visited:
        visited.add(name)
        alias = re.search(
            r'^@' + re.escape(name) + r'\s*=\s*[^\n]*\balias\b[^\n]*,\s*ptr\s+@([^\s,]+)',
            text,
            re.MULTILINE,
        )
        if not alias:
            return name
        name = alias[1].strip('"')
    raise AssertionError("cyclic fixture alias")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("report")
    parser.add_argument("--level", choices=("vm", "strong_vm"), required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--override", required=True)
    parser.add_argument("--baseline-ir")
    parser.add_argument("--escaped", action="append", default=[])
    args = parser.parse_args()
    report = coverage_contract(load(args.report))
    require(report["capture"] == "enabled", "frontend VM outcomes were not captured")
    baseline = Path(args.baseline_ir).read_text() if args.baseline_ir else ""
    expected = {
        resolve_owner(args.target, baseline): "config_rule",
        resolve_owner(args.override, baseline): "explicit_override",
    }
    require(len(expected) == 2, "target and override must select different functions")
    for owner, source in expected.items():
        selections = [event for event in report["requested_policy"]
                      if event["phase"] == "selected" and event["owner"] == owner]
        require(len(selections) == 1, f"missing unique policy selection for {owner}")
        selection = selections[0]
        require(selection["policy"]["level"] == args.level and
                selection["policy"]["allow_vm"] and selection["policy"]["source"] == source,
                f"{owner} lost its exact {source} {args.level} policy")
        for phase, status in (("admission", "admitted"), ("emission", "emitted")):
            events = [event for event in report[phase]
                      if event["owner"] == owner and event["mechanism"] == "vm" and
                      event["scope"] == "whole_function" and event["status"] == status]
            require(events and (phase != "emission" or all(event["count"] > 0 for event in events)),
                    f"{owner} has no {status} whole-function VM outcome")
    for name in args.escaped:
        owner = resolve_owner(name, baseline)
        selections = [event for event in report["requested_policy"]
                      if event["phase"] == "selected" and event["owner"] == owner]
        require(len(selections) == 1 and selections[0]["policy"]["level"] == "strong" and
                not selections[0]["policy"]["allow_vm"],
                f"{owner} lost its address-escape VM restriction")
    emitted = [event for event in report["emission"] if event["mechanism"] == "vm"]
    require({event["owner"] for event in emitted} == set(expected) and
            all(event["scope"] == "whole_function" for event in emitted),
            "frontend VM emission changed owners or used regional fallback")


if __name__ == "__main__":
    main()
