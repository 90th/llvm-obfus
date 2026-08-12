#!/usr/bin/env python3

"""verify labelled binary recovery controls through opaque staged artifacts."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import tempfile
from typing import Any


SCHEMA_VERSION = 1
ANALYZER_REPORT_KIND = "binary_vm_recovery"
ANALYZER_TOOL = "obf-re-harness-binary"
VERDICT_REPORT_KIND = "binary_vm_recovery_controls"
VERDICT_TOOL = "obf-re-harness-binary-controls"
CONTROL_ROLES = ("positive", "baseline", "negative")
ROLE_ORDER = {role: index for index, role in enumerate(CONTROL_ROLES)}
EXPECTED_CLASSIFICATION = {
    "positive": "vm_candidate",
    "baseline": "not_vm_candidate",
    "negative": "not_vm_candidate",
}
CLASSIFICATIONS = frozenset(
    {"vm_candidate", "interpreter_like", "partial", "inconclusive", "unavailable"}
)
POSITIVE_EXPECTATION_CLASSIFICATIONS = frozenset(
    {"vm_candidate", "interpreter_like", "partial"}
)
POSITIVE_MINIMUM_CLASSIFICATIONS = frozenset({"interpreter_like"})
POSITIVE_MINIMUM_MATCH_CLASSIFICATIONS = frozenset(
    {"interpreter_like", "vm_candidate"}
)
POSITIVE_MINIMUM_EXPECTED = "interpreter_like_or_vm_candidate"
POSITIVE_CONFIGURATION_ISSUES = frozenset(
    {
        "duplicate_positive_expectation",
        "duplicate_positive_label",
        "duplicate_positive_minimum",
        "invalid_positive_expectation",
        "invalid_positive_minimum",
        "positive_expectation_minimum_conflict",
        "unmatched_positive_expectation",
        "unmatched_positive_minimum",
    }
)
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
COPY_CHUNK_SIZE = 1024 * 1024


@dataclass(frozen=True)
class ArtifactIdentity:
    sha256: str
    size: int


@dataclass(frozen=True)
class ParsedSpec:
    role: str
    label: str
    source: pathlib.Path | None
    issue: str | None


@dataclass(frozen=True)
class ParsedPositiveExpectation:
    label: str
    classification: str | None
    issue: str | None



@dataclass(frozen=True)
class ParsedPositiveMinimum:
    label: str
    classification: str | None
    issue: str | None

@dataclass(frozen=True)
class ControlEntry:
    role: str
    label: str
    identity: ArtifactIdentity | None
    issue: str | None


@dataclass(frozen=True)
class AnalyzerRun:
    report_bytes: bytes | None
    returncode: int | None
    issues: tuple[str, ...]


@dataclass(frozen=True)
class ParsedAnalysis:
    classifications: dict[str, str]
    issues: tuple[str, ...]


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="verify labelled binary recovery controls with an opaque analyzer handoff"
    )
    parser.add_argument("--python", required=True, type=pathlib.Path)
    parser.add_argument("--analyzer", required=True, type=pathlib.Path)
    parser.add_argument("--llvm-objdump", required=True, type=pathlib.Path)
    parser.add_argument("--report-out", required=True, type=pathlib.Path)
    parser.add_argument("--verdict-out", required=True, type=pathlib.Path)
    parser.add_argument("--positive", action="append", default=[], metavar="LABEL=PATH")
    parser.add_argument("--baseline", action="append", default=[], metavar="LABEL=PATH")
    parser.add_argument("--negative", action="append", default=[], metavar="LABEL=PATH")
    parser.add_argument(
        "--positive-expectation",
        action="append",
        const="",
        default=[],
        metavar="LABEL=CLASSIFICATION",
        nargs="?",
    )
    parser.add_argument(
        "--positive-minimum",
        action="append",
        const="",
        default=[],
        metavar="LABEL=CLASSIFICATION",
        nargs="?",
    )
    parser.add_argument("--strict", action="store_true")
    return parser.parse_args(argv)


def parse_labelled_spec(role: str, value: str) -> ParsedSpec:
    label, separator, source_text = value.partition("=")
    if not separator or not label or not source_text:
        return ParsedSpec(role, label if separator else "", None, "invalid_control_spec")
    return ParsedSpec(role, label, pathlib.Path(source_text), None)


def parse_positive_expectation(value: str) -> ParsedPositiveExpectation:
    label, separator, classification = value.partition("=")
    if (
        not separator
        or not label
        or not classification
        or classification not in POSITIVE_EXPECTATION_CLASSIFICATIONS
    ):
        return ParsedPositiveExpectation(
            label if separator else "", None, "invalid_positive_expectation"
        )
    return ParsedPositiveExpectation(label, classification, None)


def parse_positive_minimum(value: str) -> ParsedPositiveMinimum:
    label, separator, classification = value.partition("=")
    if (
        not separator
        or not label
        or not classification
        or classification not in POSITIVE_MINIMUM_CLASSIFICATIONS
    ):
        return ParsedPositiveMinimum(
            label if separator else "", None, "invalid_positive_minimum"
        )
    return ParsedPositiveMinimum(label, classification, None)


def positive_label_counts(specs: list[ParsedSpec]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for spec in specs:
        if spec.role == "positive" and spec.issue is None:
            counts[spec.label] = counts.get(spec.label, 0) + 1
    return counts


def validate_positive_labels(specs: list[ParsedSpec]) -> tuple[str, ...]:
    if any(count > 1 for count in positive_label_counts(specs).values()):
        return ("duplicate_positive_label",)
    return ()


def resolve_positive_expectations(
    specs: list[ParsedSpec], values: list[str]
) -> tuple[dict[str, str], tuple[str, ...]]:
    positive_labels = positive_label_counts(specs)
    expectations = [parse_positive_expectation(value) for value in values]
    expectation_label_counts: dict[str, int] = {}
    for expectation in expectations:
        if expectation.label:
            expectation_label_counts[expectation.label] = (
                expectation_label_counts.get(expectation.label, 0) + 1
            )

    resolved: dict[str, str] = {}
    issues: set[str] = set()
    for expectation in sorted(
        expectations,
        key=lambda item: (item.label, item.classification or "", item.issue or ""),
    ):
        if expectation.issue is not None:
            issues.add(expectation.issue)
            continue
        if expectation_label_counts[expectation.label] != 1:
            issues.add("duplicate_positive_expectation")
            continue
        if positive_labels.get(expectation.label) != 1:
            issues.add("unmatched_positive_expectation")
            continue
        if expectation.classification is None:
            issues.add("invalid_positive_expectation")
            continue
        resolved[expectation.label] = expectation.classification
    return resolved, tuple(sorted(issues))


def resolve_positive_minima(
    specs: list[ParsedSpec], values: list[str]
) -> tuple[dict[str, str], tuple[str, ...]]:
    positive_labels = positive_label_counts(specs)
    minima = [parse_positive_minimum(value) for value in values]
    minimum_label_counts: dict[str, int] = {}
    for minimum in minima:
        if minimum.label:
            minimum_label_counts[minimum.label] = (
                minimum_label_counts.get(minimum.label, 0) + 1
            )

    resolved: dict[str, str] = {}
    issues: set[str] = set()
    for minimum in sorted(
        minima,
        key=lambda item: (item.label, item.classification or "", item.issue or ""),
    ):
        if minimum.issue is not None:
            issues.add(minimum.issue)
            continue
        if minimum_label_counts[minimum.label] != 1:
            issues.add("duplicate_positive_minimum")
            continue
        if positive_labels.get(minimum.label) != 1:
            issues.add("unmatched_positive_minimum")
            continue
        if minimum.classification is None:
            issues.add("invalid_positive_minimum")
            continue
        resolved[minimum.label] = minimum.classification
    return resolved, tuple(sorted(issues))


def validate_positive_directive_conflicts(
    expectations: dict[str, str], minima: dict[str, str]
) -> tuple[str, ...]:
    if expectations.keys().isdisjoint(minima):
        return ()
    return ("positive_expectation_minimum_conflict",)


def collect_specs(args: argparse.Namespace) -> list[ParsedSpec]:
    specs: list[ParsedSpec] = []
    for role in CONTROL_ROLES:
        specs.extend(parse_labelled_spec(role, value) for value in getattr(args, role))
    return specs


def stage_source(source: pathlib.Path, staging_dir: pathlib.Path) -> tuple[ArtifactIdentity | None, str | None]:
    try:
        source_stat = source.stat()
    except FileNotFoundError:
        return None, "input_missing"
    except OSError:
        return None, "input_unreadable"
    if not stat.S_ISREG(source_stat.st_mode):
        return None, "input_not_regular"

    temporary_path: pathlib.Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(prefix=".stage-", dir=staging_dir)
        temporary_path = pathlib.Path(temporary_name)
        digest = hashlib.sha256()
        size = 0
        with os.fdopen(descriptor, "wb") as destination:
            with source.open("rb") as input_file:
                while chunk := input_file.read(COPY_CHUNK_SIZE):
                    digest.update(chunk)
                    size += len(chunk)
                    destination.write(chunk)
        identity = ArtifactIdentity(digest.hexdigest(), size)
        staged_path = staging_dir / identity.sha256
        if staged_path.exists():
            temporary_path.unlink()
        else:
            os.replace(temporary_path, staged_path)
        temporary_path = None
        return identity, None
    except FileNotFoundError:
        return None, "input_missing"
    except IsADirectoryError:
        return None, "input_not_regular"
    except OSError:
        return None, "input_unreadable"
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass


def stage_specs(specs: list[ParsedSpec], staging_dir: pathlib.Path) -> list[ControlEntry]:
    entries: list[ControlEntry] = []
    for spec in specs:
        if spec.issue is not None or spec.source is None:
            entries.append(ControlEntry(spec.role, spec.label, None, spec.issue))
            continue
        identity, issue = stage_source(spec.source, staging_dir)
        entries.append(ControlEntry(spec.role, spec.label, identity, issue))
    return entries


def stable_json_bytes(payload: Any) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_bytes(path: pathlib.Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = pathlib.Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
        os.replace(temporary_path, path)
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def write_json(path: pathlib.Path, payload: Any) -> None:
    write_bytes(path, stable_json_bytes(payload))


def unavailable_analysis_report(reason: str) -> bytes:
    return stable_json_bytes(
        {
            "analysis_boundary": "binary-only",
            "artifacts": [],
            "issues": [reason],
            "report_kind": ANALYZER_REPORT_KIND,
            "schema_version": SCHEMA_VERSION,
            "summary": {"artifacts_analyzed": 0, "status": "unavailable"},
            "tool": ANALYZER_TOOL,
        }
    )


def invoke_analyzer(
    args: argparse.Namespace,
    staging_dir: pathlib.Path,
    identities: dict[str, ArtifactIdentity],
) -> AnalyzerRun:
    if not identities:
        return AnalyzerRun(None, None, ("analyzer_not_run",))

    analyzer_report = staging_dir / "analysis-report.json"
    command = [str(args.python), str(args.analyzer)]
    for sha256 in sorted(identities):
        command.extend(("--binary", str(staging_dir / sha256)))
    command.extend(
        (
            "--llvm-objdump",
            str(args.llvm_objdump),
            "--json-out",
            str(analyzer_report),
        )
    )
    if args.strict:
        command.append("--strict")

    try:
        completed = subprocess.run(
            command,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return AnalyzerRun(None, None, ("analyzer_launch_failed",))

    try:
        report_bytes = analyzer_report.read_bytes()
    except FileNotFoundError:
        return AnalyzerRun(None, completed.returncode, ("analyzer_report_missing",))
    except OSError:
        return AnalyzerRun(None, completed.returncode, ("analyzer_report_unreadable",))
    return AnalyzerRun(report_bytes, completed.returncode, ())


def valid_sha256(value: Any) -> bool:
    return isinstance(value, str) and SHA256_PATTERN.fullmatch(value) is not None


def valid_size(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def parse_analyzer_report(
    report_bytes: bytes, expected_identities: dict[str, ArtifactIdentity]
) -> ParsedAnalysis:
    try:
        payload = json.loads(report_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return ParsedAnalysis({}, ("analyzer_report_invalid_json",))

    issues: set[str] = set()
    if not isinstance(payload, dict):
        return ParsedAnalysis({}, ("analyzer_report_not_object",))
    if payload.get("analysis_boundary") != "binary-only":
        issues.add("analyzer_report_boundary")
    if payload.get("report_kind") != ANALYZER_REPORT_KIND:
        issues.add("analyzer_report_kind")
    schema_version = payload.get("schema_version")
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version != SCHEMA_VERSION
    ):
        issues.add("analyzer_report_schema")
    if payload.get("tool") != ANALYZER_TOOL:
        issues.add("analyzer_report_tool")
    if not isinstance(payload.get("summary"), dict):
        issues.add("analyzer_report_summary")

    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list):
        issues.add("analyzer_report_artifacts")
        return ParsedAnalysis({}, tuple(sorted(issues)))

    classifications: dict[str, str] = {}
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            issues.add("analyzer_artifact_not_object")
            continue
        identity = artifact.get("identity")
        if not isinstance(identity, dict):
            issues.add("analyzer_artifact_identity")
            continue
        sha256 = identity.get("sha256")
        size = identity.get("size")
        if not valid_sha256(sha256) or not valid_size(size):
            issues.add("analyzer_artifact_identity")
            continue
        expected_identity = expected_identities.get(sha256)
        if expected_identity is None:
            issues.add("analyzer_artifact_unexpected")
            continue
        if expected_identity.size != size:
            issues.add("analyzer_artifact_size")
            continue
        recovery = artifact.get("recovery")
        assessment = recovery.get("assessment") if isinstance(recovery, dict) else None
        classification = assessment.get("classification") if isinstance(assessment, dict) else None
        if not isinstance(classification, str) or classification not in CLASSIFICATIONS:
            issues.add("analyzer_artifact_classification")
            continue
        if sha256 in classifications:
            issues.add("analyzer_artifact_duplicate")
            continue
        classifications[sha256] = classification

    if set(classifications) != set(expected_identities):
        issues.add("analyzer_artifact_missing")
    if issues:
        return ParsedAnalysis({}, tuple(sorted(issues)))
    return ParsedAnalysis(classifications, ())


def entry_sort_key(entry: ControlEntry) -> tuple[int, str, int, str, str]:
    if entry.identity is None:
        return (ROLE_ORDER[entry.role], entry.label, 0, "", entry.issue or "")
    return (
        ROLE_ORDER[entry.role],
        entry.label,
        1,
        entry.identity.sha256,
        entry.issue or "",
    )


def control_verdicts(
    entries: list[ControlEntry],
    classifications: dict[str, str],
    analysis_available: bool,
    positive_expectations: dict[str, str] | None = None,
    positive_minima: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    if positive_expectations is None:
        positive_expectations = {}
    if positive_minima is None:
        positive_minima = {}
    verdicts: list[dict[str, Any]] = []
    for entry in sorted(entries, key=entry_sort_key):
        minimum_applies = (
            entry.role == "positive"
            and entry.label not in positive_expectations
            and entry.label in positive_minima
        )
        if entry.role != "positive":
            expected = EXPECTED_CLASSIFICATION[entry.role]
        elif entry.label in positive_expectations:
            expected = positive_expectations[entry.label]
        elif minimum_applies:
            expected = POSITIVE_MINIMUM_EXPECTED
        else:
            expected = EXPECTED_CLASSIFICATION[entry.role]
        actual: str | None = None
        issues: list[str] = []
        if entry.issue is not None:
            status = "unavailable"
            issues.append(entry.issue)
        elif entry.identity is None:
            status = "unavailable"
            issues.append("input_identity_unavailable")
        elif not analysis_available:
            status = "unavailable"
            issues.append("analyzer_result_unavailable")
        else:
            actual = classifications[entry.identity.sha256]
            if entry.role == "positive":
                matches = (
                    actual in POSITIVE_MINIMUM_MATCH_CLASSIFICATIONS
                    if minimum_applies
                    else actual == expected
                )
            else:
                matches = actual != "vm_candidate"
            if matches:
                status = "pass"
            else:
                status = "fail"
                issues.append("control_expectation_failed")
        verdicts.append(
            {
                "actual_classification": actual,
                "expected": expected,
                "issues": issues,
                "label": entry.label,
                "role": entry.role,
                "sha256": entry.identity.sha256 if entry.identity is not None else None,
                "size": entry.identity.size if entry.identity is not None else None,
                "status": status,
            }
        )
    return verdicts




def build_verdict_with_classifications(
    entries: list[ControlEntry],
    identities: dict[str, ArtifactIdentity],
    analyzer_returncode: int | None,
    analyzer_status: str,
    analyzer_issues: tuple[str, ...],
    report_issues: tuple[str, ...],
    classifications: dict[str, str],
    positive_expectations: dict[str, str] | None = None,
    positive_expectation_issues: tuple[str, ...] = (),
    positive_minima: dict[str, str] | None = None,
) -> dict[str, Any]:
    analysis_available = analyzer_status == "valid"
    verdicts = control_verdicts(
        entries,
        classifications,
        analysis_available,
        positive_expectations,
        positive_minima,
    )
    issues = set(analyzer_issues)
    issues.update(report_issues)
    issues.update(positive_expectation_issues)
    if not entries:
        issues.add("no_controls")
    if entries and not identities:
        issues.add("no_staged_artifacts")
    if analyzer_returncode not in (None, 0):
        issues.add("analyzer_nonzero")
    if analyzer_status == "malformed":
        issues.add("analyzer_report_malformed")

    control_failures = sum(verdict["status"] != "pass" for verdict in verdicts)
    global_failure_issues = {
        "analyzer_launch_failed",
        "analyzer_nonzero",
        "analyzer_not_run",
        "analyzer_report_invalid_json",
        "analyzer_report_malformed",
        "analyzer_report_missing",
        "analyzer_report_not_object",
        "analyzer_report_unreadable",
        "analyzer_report_write_failed",
        "no_controls",
        "no_staged_artifacts",
    }
    global_failure_issues.update(POSITIVE_CONFIGURATION_ISSUES)
    global_failures = sum(issue in global_failure_issues for issue in issues)
    summary = {
        "artifacts": len(identities),
        "baselines": sum(entry.role == "baseline" for entry in entries),
        "controls": len(verdicts),
        "failures": control_failures + global_failures,
        "negatives": sum(entry.role == "negative" for entry in entries),
        "positives": sum(entry.role == "positive" for entry in entries),
        "status": "pass" if control_failures + global_failures == 0 else "fail",
    }
    return {
        "analyzer": {
            "artifact_count": len(classifications) if analysis_available else 0,
            "returncode": analyzer_returncode,
            "status": analyzer_status,
        },
        "controls": verdicts,
        "issues": sorted(issues),
        "report_kind": VERDICT_REPORT_KIND,
        "schema_version": SCHEMA_VERSION,
        "summary": summary,
        "tool": VERDICT_TOOL,
    }


def same_path(left: pathlib.Path, right: pathlib.Path) -> bool:
    try:
        return left.resolve(strict=False) == right.resolve(strict=False)
    except OSError:
        return left.absolute() == right.absolute()


def output_paths_valid(args: argparse.Namespace) -> bool:
    if same_path(args.report_out, args.verdict_out):
        print("[fail] --report-out and --verdict-out must differ", file=sys.stderr)
        return False
    return True


def run(args: argparse.Namespace) -> int:
    specs = collect_specs(args)
    positive_label_issues = validate_positive_labels(specs)
    positive_expectations, positive_expectation_issues = resolve_positive_expectations(
        specs, args.positive_expectation
    )
    positive_minima, positive_minimum_issues = resolve_positive_minima(
        specs, args.positive_minimum
    )
    positive_expectation_issues = tuple(
        sorted(
            set(positive_expectation_issues)
            .union(positive_minimum_issues)
            .union(positive_label_issues)
            .union(
                validate_positive_directive_conflicts(
                    positive_expectations, positive_minima
                )
            )
        )
    )
    with tempfile.TemporaryDirectory(prefix="obf-re-harness-binary-") as temporary_directory:
        staging_dir = pathlib.Path(temporary_directory)
        entries = stage_specs(specs, staging_dir)
        identities = {
            entry.identity.sha256: entry.identity
            for entry in entries
            if entry.identity is not None
        }
        analyzer_run = invoke_analyzer(args, staging_dir, identities)

        if analyzer_run.report_bytes is None:
            fallback_reason = analyzer_run.issues[0] if analyzer_run.issues else "analyzer_report_missing"
            output_report = unavailable_analysis_report(fallback_reason)
            parsed_report = ParsedAnalysis({}, analyzer_run.issues)
            analyzer_status = "not_run" if "analyzer_not_run" in analyzer_run.issues else "missing"
        else:
            output_report = analyzer_run.report_bytes
            parsed_report = parse_analyzer_report(analyzer_run.report_bytes, identities)
            analyzer_status = "valid" if not parsed_report.issues else "malformed"

        report_write_issue: tuple[str, ...] = ()
        try:
            write_bytes(args.report_out, output_report)
        except OSError:
            report_write_issue = ("analyzer_report_write_failed",)

        verdict = build_verdict_with_classifications(
            entries,
            identities,
            analyzer_run.returncode,
            analyzer_status,
            analyzer_run.issues,
            tuple(sorted(set(parsed_report.issues).union(report_write_issue))),
            parsed_report.classifications,
            positive_expectations,
            positive_expectation_issues,
            positive_minima,
        )
        try:
            write_json(args.verdict_out, verdict)
        except OSError:
            print("[fail] unable to write control verdict", file=sys.stderr)
            return 1

    print(f"binary recovery controls: {verdict['summary']['status']}")
    return 0 if verdict["summary"]["status"] == "pass" else 1


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if not output_paths_valid(args):
        return 2
    return run(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
