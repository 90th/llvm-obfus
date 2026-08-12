#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import stat
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any


class FixtureError(RuntimeError):
    pass


CONTROL_SPECS = (
    ("large-switch", 1, 0),
    ("interpreter-loop", 2, 0),
    ("lookup-table", 3, 0),
    ("dispatch-normal", 4, 0),
    ("large-switch-variant", 1, 1),
)

EXPECTED_TOP_LEVEL = {
    "analysis_boundary": "binary-only",
    "report_kind": "binary_vm_recovery",
    "schema_version": 1,
    "tool": "obf-re-harness-binary",
}

EXPECTED_CLASSIFICATIONS = {
    "inconclusive",
    "interpreter_like",
    "partial",
    "unavailable",
    "vm_candidate",
}

INDIRECT_CALL_MAX_SCORE = 4
INDIRECT_CALL_POSITIVE_EVIDENCE = (
    "indirect_call",
    "mapped_pointer_table",
    "unknown_index",
    "potential_code_targets",
)


def fail(message: str) -> None:
    raise FixtureError(message)


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def opaque_name(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_bytes(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def stage_copy(source: Path, directory: Path, salt: str = "") -> tuple[Path, str]:
    digest = sha256_path(source)
    suffix = "" if not salt else f"\0{salt}"
    name = opaque_name((digest + suffix).encode("ascii"))
    destination = directory / name
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    return destination, digest


def stage_bytes(data: bytes, directory: Path) -> Path:
    return write_bytes(directory / opaque_name(data), data)


def run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            check=False,
        )
    except OSError as error:
        fail(f"unable to launch fixture command: {error.__class__.__name__}")


def compile_program(
    compiler: str,
    source: Path,
    output: Path,
    control_kind: int,
    structural_variant: int,
    object_file: bool = False,
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    command = [
        compiler,
        "-std=c11",
        "-O2",
        f"-DCONTROL_KIND={control_kind}",
        f"-DSTRUCTURAL_VARIANT={structural_variant}",
    ]
    if object_file:
        command.append("-c")
    command.extend((str(source), "-o", str(output)))
    completed = run_command(command)
    if completed.returncode != 0 or not output.is_file() or output.stat().st_size == 0:
        fail("native control compilation failed")


def strip_program(strip_tool: str, path: Path) -> None:
    completed = run_command([strip_tool, "--strip-all", str(path)])
    if completed.returncode != 0 or not path.is_file() or path.stat().st_size == 0:
        fail("native control stripping failed")


def invoke_analyzer(
    python: str,
    analyzer: Path,
    objdump: Path,
    report_path: Path,
    binaries: list[Path],
    strict: bool = False,
    max_score: int | None = None,
) -> tuple[int, dict[str, Any]]:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    command = [
        python,
        str(analyzer),
        "--llvm-objdump",
        str(objdump),
        "--json-out",
        str(report_path),
    ]
    if strict:
        command.append("--strict")
    if max_score is not None:
        command.extend(("--fail-max-recovery-score", str(max_score)))
    for binary in binaries:
        command.extend(("--binary", str(binary)))
    completed = run_command(command)
    if not report_path.is_file():
        fail("analyzer did not write a report")
    try:
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"analyzer report is unreadable: {error.__class__.__name__}")
    if not isinstance(payload, dict):
        fail("analyzer report is not an object")
    return completed.returncode, payload


def read_json_object(path: Path, context: str) -> dict[str, Any]:
    if not path.is_file():
        fail(f"{context} was not written")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"{context} is unreadable: {error.__class__.__name__}")
    if not isinstance(payload, dict):
        fail(f"{context} is not an object")
    return payload


def invoke_controller(
    python: str,
    controller: Path,
    analyzer: Path,
    objdump: Path,
    report_path: Path,
    verdict_path: Path,
    positive_label: str,
    positive_binary: Path,
    positive_expectation: str | None = None,
    positive_minima: tuple[str, ...] = (),
) -> tuple[int, dict[str, Any], dict[str, Any]]:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    verdict_path.parent.mkdir(parents=True, exist_ok=True)
    command = [
        python,
        str(controller),
        "--python",
        python,
        "--analyzer",
        str(analyzer),
        "--llvm-objdump",
        str(objdump),
        "--report-out",
        str(report_path),
        "--verdict-out",
        str(verdict_path),
        "--positive",
        f"{positive_label}={positive_binary}",
    ]
    if positive_expectation is not None:
        command.extend(
            ("--positive-expectation", f"{positive_label}={positive_expectation}")
        )
    for minimum in positive_minima:
        command.extend(("--positive-minimum", minimum))
    completed = run_command(command)
    return (
        completed.returncode,
        read_json_object(report_path, "controller analysis report"),
        read_json_object(verdict_path, "controller verdict"),
    )


def require_mapping(value: object, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{context} is not an object")
    return value


def require_list(value: object, context: str) -> list[Any]:
    if not isinstance(value, list):
        fail(f"{context} is not a list")
    return value


def require_report(payload: dict[str, Any], expected_artifacts: int) -> list[dict[str, Any]]:
    for key, expected in EXPECTED_TOP_LEVEL.items():
        if payload.get(key) != expected:
            fail(f"report field {key} is not stable")
    require_mapping(payload.get("summary"), "summary")
    artifacts = require_list(payload.get("artifacts"), "artifacts")
    if len(artifacts) != expected_artifacts:
        fail("report did not retain every requested artifact")

    checked: list[dict[str, Any]] = []
    for index, raw_artifact in enumerate(artifacts):
        artifact = require_mapping(raw_artifact, f"artifact {index}")
        identity = require_mapping(artifact.get("identity"), f"artifact {index} identity")
        if "sha256" not in identity or "size" not in identity:
            fail("artifact identity is incomplete")
        if not isinstance(identity["size"], int) or identity["size"] < 0:
            fail("artifact identity size is invalid")
        if not isinstance(artifact.get("status"), str):
            fail("artifact status is missing")
        require_mapping(artifact.get("capabilities"), f"artifact {index} capabilities")
        require_list(artifact.get("issues"), f"artifact {index} issues")
        require_mapping(artifact.get("metadata_exposure"), f"artifact {index} metadata exposure")
        recovery = require_mapping(artifact.get("recovery"), f"artifact {index} recovery")
        for field in ("function_regions", "data_regions", "candidates", "relationships"):
            require_list(recovery.get(field), f"artifact {index} recovery {field}")
        scores = require_mapping(recovery.get("scores"), f"artifact {index} recovery scores")
        for family in ("control", "handlers", "state", "data", "structural"):
            score = scores.get(family)
            if not isinstance(score, int) or not 0 <= score <= 100:
                fail(f"artifact recovery score {family} is invalid")
        assessment = require_mapping(recovery.get("assessment"), f"artifact {index} assessment")
        classification = assessment.get("classification")
        if classification not in EXPECTED_CLASSIFICATIONS:
            fail("artifact classification is invalid")
        if assessment.get("semantic_recovery") != "unavailable":
            fail("semantic recovery must remain unavailable")
        checked.append(artifact)
    return checked


def artifact_hash(artifact: dict[str, Any]) -> str:
    identity = require_mapping(artifact.get("identity"), "artifact identity")
    digest = identity.get("sha256")
    if not isinstance(digest, str) or len(digest) != 64:
        fail("present artifact does not have a sha256 identity")
    return digest


def artifact_index(artifacts: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for artifact in artifacts:
        digest = artifact_hash(artifact)
        if digest in indexed:
            fail("report has duplicate artifact identities")
        indexed[digest] = artifact
    return indexed


def artifact_for_hash(
    artifacts: list[dict[str, Any]], digest: str, context: str
) -> dict[str, Any]:
    indexed = artifact_index(artifacts)
    if digest not in indexed:
        fail(f"{context} is missing")
    return indexed[digest]


def assert_dispatch_normal_observation(artifact: dict[str, Any]) -> int:
    if assessment(artifact).get("classification") != "partial":
        fail("dispatch-normal indirect-call observation is not partial")
    recovery = require_mapping(artifact.get("recovery"), "dispatch-normal recovery")
    scores = require_mapping(recovery.get("scores"), "dispatch-normal scores")
    control_score = scores.get("control")
    structural_score = scores.get("structural")
    if (
        not isinstance(control_score, int)
        or not isinstance(structural_score, int)
        or not 0 < control_score <= INDIRECT_CALL_MAX_SCORE
        or not 0 < structural_score <= INDIRECT_CALL_MAX_SCORE
        or structural_score != control_score
    ):
        fail("dispatch-normal indirect-call score is not bounded")

    indirect_calls: list[dict[str, Any]] = []
    for candidate in require_list(recovery.get("candidates"), "dispatch-normal candidates"):
        mapped_candidate = require_mapping(candidate, "dispatch-normal candidate")
        if mapped_candidate.get("kind") == "indirect_call":
            indirect_calls.append(mapped_candidate)
    if len(indirect_calls) != 1:
        fail("dispatch-normal did not retain one generic indirect-call observation")

    indirect_call = indirect_calls[0]
    if indirect_call.get("confidence") != "candidate":
        fail("dispatch-normal indirect-call observation is overconfident")
    evidence = require_mapping(indirect_call.get("evidence"), "dispatch-normal indirect-call evidence")
    if require_list(evidence.get("positive"), "dispatch-normal indirect-call positive evidence") != list(
        INDIRECT_CALL_POSITIVE_EVIDENCE
    ):
        fail("dispatch-normal indirect-call evidence is incomplete")
    if require_list(evidence.get("missing"), "dispatch-normal indirect-call missing evidence") != [
        "dispatcher_handler_state_data_graph"
    ]:
        fail("dispatch-normal indirect-call observation is not generic")
    if evidence.get("pointer_width") != 8:
        fail("dispatch-normal indirect-call table width is invalid")
    if "resolved_target_block_count" in evidence or "resolved_target_block_ids" in evidence:
        fail("dispatch-normal indirect-call targets are overstated as resolved")
    table_access = require_mapping(evidence.get("table_access"), "dispatch-normal table access")
    if table_access.get("index_provenance") != "unknown_index":
        fail("dispatch-normal indirect-call index is not unknown")
    if table_access.get("operand_provenance") not in {
        "direct_memory_operand",
        "same_block_lea",
    }:
        fail("dispatch-normal indirect-call operand provenance is invalid")
    table_access_address = table_access.get("address_id")
    if not isinstance(table_access_address, str) or not table_access_address.startswith("va:"):
        fail("dispatch-normal indirect-call table access address is invalid")
    for field in ("pointer_table_target_count", "potential_code_target_block_count"):
        target_count = evidence.get(field)
        if not isinstance(target_count, int) or target_count < 2:
            fail(f"dispatch-normal indirect-call {field} is incomplete")
    potential_target_ids = require_list(
        evidence.get("potential_code_target_block_ids"),
        "dispatch-normal indirect-call potential target ids",
    )
    if (
        len(potential_target_ids) != evidence["potential_code_target_block_count"]
        or len(set(potential_target_ids)) != len(potential_target_ids)
        or any(
            not isinstance(target_id, str) or not target_id.startswith("block:")
            for target_id in potential_target_ids
        )
    ):
        fail("dispatch-normal indirect-call potential targets are invalid")
    return structural_score


def assert_score_gate(
    payload: dict[str, Any],
    artifact: dict[str, Any],
    maximum_score: int,
    expected_failure: bool,
) -> None:
    summary = require_mapping(payload.get("summary"), "score-gate summary")
    if summary.get("fail_max_recovery_score") != maximum_score:
        fail("score gate threshold was not recorded")
    if summary.get("failures") != int(expected_failure):
        fail("score gate failure count is invalid")
    expected_status = "failed" if expected_failure else "passed"
    if summary.get("status") != expected_status:
        fail("score gate status is invalid")
    gate = require_mapping(artifact.get("gate"), "dispatch-normal score gate")
    if gate.get("score_threshold_failed") is not expected_failure:
        fail("score gate threshold result is invalid")
    if gate.get("strict_failed") is not False:
        fail("score gate unexpectedly entered strict failure")


def assessment(artifact: dict[str, Any]) -> dict[str, Any]:
    return require_mapping(
        require_mapping(artifact.get("recovery"), "artifact recovery").get("assessment"),
        "artifact assessment",
    )


def assert_controller_positive_verdict(
    analyzer_payload: dict[str, Any],
    verdict_payload: dict[str, Any],
    digest: str,
    expected_classification: str,
    expected_status: str,
    expected_global_issues: tuple[str, ...] = (),
    expected_actual_classification: str = "interpreter_like",
) -> None:
    artifacts = require_report(analyzer_payload, 1)
    artifact = artifact_for_hash(artifacts, digest, "controller interpreter-loop artifact")
    actual_classification = assessment(artifact).get("classification")
    if actual_classification != expected_actual_classification:
        fail("controller positive artifact classification is invalid")

    if (
        verdict_payload.get("report_kind") != "binary_vm_recovery_controls"
        or verdict_payload.get("schema_version") != 1
        or verdict_payload.get("tool") != "obf-re-harness-binary-controls"
    ):
        fail("controller verdict top-level fields are invalid")
    analyzer = require_mapping(verdict_payload.get("analyzer"), "controller analyzer")
    if (
        analyzer.get("artifact_count") != 1
        or analyzer.get("returncode") != 0
        or analyzer.get("status") != "valid"
    ):
        fail("controller analyzer status is invalid")

    expected_control_status = "pass" if expected_global_issues else expected_status
    expected_failures = (
        (0 if expected_control_status == "pass" else 1)
        + len(expected_global_issues)
    )
    summary = require_mapping(verdict_payload.get("summary"), "controller summary")
    expected_summary = {
        "artifacts": 1,
        "baselines": 0,
        "controls": 1,
        "failures": expected_failures,
        "negatives": 0,
        "positives": 1,
        "status": expected_status,
    }
    for field, expected_value in expected_summary.items():
        if summary.get(field) != expected_value:
            fail(f"controller summary {field} is invalid")

    controls = require_list(verdict_payload.get("controls"), "controller controls")
    if len(controls) != 1:
        fail("controller did not record one positive control")
    control = require_mapping(controls[0], "controller positive control")
    if (
        control.get("actual_classification") != actual_classification
        or control.get("expected") != expected_classification
        or control.get("label") != "interpreter-loop"
        or control.get("role") != "positive"
        or control.get("sha256") != digest
        or control.get("status") != expected_control_status
    ):
        fail("controller positive verdict is invalid")
    expected_issues = (
        []
        if expected_control_status == "pass"
        else ["control_expectation_failed"]
    )
    if require_list(control.get("issues"), "controller positive issues") != expected_issues:
        fail("controller positive issues are invalid")
    if require_list(verdict_payload.get("issues"), "controller issues") != sorted(
        expected_global_issues
    ):
        fail("controller reported unexpected global issues")


def assert_native_controls(
    artifacts: list[dict[str, Any]],
    expected_hashes: dict[str, str],
) -> None:
    indexed = artifact_index(artifacts)
    if set(indexed) != set(expected_hashes.values()):
        fail("native control identities changed during analysis")
    for label, digest in expected_hashes.items():
        classification = assessment(indexed[digest]).get("classification")
        if classification == "vm_candidate":
            fail(f"native control {label} became a vm candidate")
        if classification == "unavailable":
            fail(f"native control {label} was not analyzed")


def assert_unavailable_artifacts(artifacts: list[dict[str, Any]]) -> None:
    for artifact in artifacts:
        if assessment(artifact).get("classification") != "unavailable":
            fail("invalid artifact did not become unavailable")
        issues = require_list(artifact.get("issues"), "artifact issues")
        if not issues:
            fail("invalid artifact has no issue record")


def recovery_view(artifacts: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {
        artifact_hash(artifact): require_mapping(artifact.get("recovery"), "artifact recovery")
        for artifact in artifacts
    }


def make_invalid_inputs(
    compiler: str,
    source: Path,
    valid_control: Path,
    root: Path,
) -> list[Path]:
    missing = root / opaque_name(b"missing-artifact")
    empty = stage_bytes(b"", root)
    non_elf = stage_bytes(b"not an elf artifact\n", root)
    valid_bytes = valid_control.read_bytes()
    truncated = stage_bytes(valid_bytes[:48], root)
    malformed_bytes = bytearray(valid_bytes)
    if len(malformed_bytes) < 64:
        fail("compiled native control is too small for ELF fixture mutation")
    struct.pack_into("<Q", malformed_bytes, 32, len(malformed_bytes) + 4096)
    malformed = stage_bytes(bytes(malformed_bytes), root)
    unsupported_bytes = bytearray(valid_bytes)
    struct.pack_into("<H", unsupported_bytes, 18, 183)
    unsupported_machine = stage_bytes(bytes(unsupported_bytes), root)
    relocatable = root / opaque_name(b"relocatable-native-control")
    compile_program(compiler, source, relocatable, 1, 0, object_file=True)
    return [
        missing,
        empty,
        non_elf,
        truncated,
        malformed,
        relocatable,
        unsupported_machine,
    ]


def make_failing_objdump(root: Path) -> Path:
    path = root / opaque_name(b"fixture-objdump-failure")
    write_bytes(path, b"#!/bin/sh\nexit 23\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path

def make_vm_candidate_analyzer(root: Path) -> Path:
    path = root / opaque_name(b"fixture-vm-candidate-analyzer")
    script = """\
import argparse
import hashlib
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--binary", action="append", required=True)
parser.add_argument("--json-out", required=True)
parser.add_argument("--llvm-objdump", required=True)
arguments = parser.parse_args()
if len(arguments.binary) != 1:
    raise SystemExit(2)
binary = Path(arguments.binary[0])
data = binary.read_bytes()
digest = hashlib.sha256(data).hexdigest()
if binary.name != digest:
    raise SystemExit(2)
artifact = {
    "capabilities": {
        "cfg_recovery": "unavailable",
        "disassembly": "unavailable",
        "dynamic": "unavailable",
        "elf": "unavailable",
        "instruction_recovery": "unavailable",
        "load_layout": "unavailable",
        "relocations": "unavailable",
        "sections": "unavailable",
        "semantic_recovery": "unavailable",
        "symbols": "unavailable",
    },
    "elf": {
        "class": "unavailable",
        "endianness": "unavailable",
        "entry_point": None,
        "load_segments": [],
        "machine": "unavailable",
        "type": "unavailable",
    },
    "identity": {"sha256": digest, "size": len(data)},
    "issues": [],
    "metadata_exposure": {
        "dynamic": {"entry_count": 0, "table_count": 0},
        "names_used_for_recovery": False,
        "relocations": {"entry_count": 0, "table_count": 0},
        "score_contribution": 0,
        "section_header_count": 0,
        "symbols": {"dynamic_entry_count": 0, "static_entry_count": 0},
    },
    "recovery": {
        "assessment": {
            "classification": "vm_candidate",
            "semantic_recovery": "unavailable",
        },
        "basic_blocks": [],
        "candidates": [],
        "data_regions": [],
        "function_regions": [],
        "indirect_transfer_recovery": {
            "immediate_selection_branch_count": 0,
            "resolved_branch_count": 0,
            "unknown_successor_branch_count": 0,
        },
        "relationships": [],
        "sccs": [],
        "score_caps": {
            "control": 30,
            "data": 20,
            "handlers": 25,
            "state": 25,
            "structural": 100,
        },
        "scores": {
            "control": 0,
            "data": 0,
            "handlers": 0,
            "state": 0,
            "structural": 0,
        },
    },
    "status": "analyzed",
}
payload = {
    "analysis_boundary": "binary-only",
    "artifacts": [artifact],
    "report_kind": "binary_vm_recovery",
    "schema_version": 1,
    "summary": {
        "artifact_count": 1,
        "classifications": {"vm_candidate": 1},
        "fail_max_recovery_score": None,
        "failures": 0,
        "max_structural_score": 0,
        "status": "passed",
        "statuses": {"analyzed": 1},
        "strict": False,
    },
    "tool": "obf-re-harness-binary",
}
output = Path(arguments.json_out)
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\\n", encoding="utf-8")
"""
    return write_bytes(path, script.encode("utf-8"))


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--python", required=True)
    parser.add_argument("--analyzer", required=True)
    parser.add_argument("--controller", required=True)
    parser.add_argument("--compiler", required=True)
    parser.add_argument("--llvm-objdump", required=True)
    parser.add_argument("--llvm-strip", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--work", required=True)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    analyzer = Path(arguments.analyzer)
    controller = Path(arguments.controller)
    source = Path(arguments.source)
    work = Path(arguments.work)
    if not analyzer.is_file() or not controller.is_file() or not source.is_file():
        fail("fixture input is unavailable")
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)

    raw_root = work / "r"
    first_root = work / "a"
    renamed_root = work / "b"
    invalid_root = work / "c"
    report_root = work / "d"
    expected_hashes: dict[str, str] = {}
    staged_controls: list[Path] = []
    staged_controls_by_label: dict[str, Path] = {}
    raw_controls: dict[str, Path] = {}

    for index, (label, control_kind, structural_variant) in enumerate(CONTROL_SPECS):
        raw_path = raw_root / str(index)
        compile_program(
            arguments.compiler,
            source,
            raw_path,
            control_kind,
            structural_variant,
        )
        stripped_path = raw_root / f"{index}.s"
        shutil.copyfile(raw_path, stripped_path)
        strip_program(arguments.llvm_strip, stripped_path)
        staged_path, digest = stage_copy(stripped_path, first_root)
        staged_controls.append(staged_path)
        expected_hashes[label] = digest
        raw_controls[label] = raw_path
        staged_controls_by_label[label] = staged_path

    baseline_code, baseline_payload = invoke_analyzer(
        arguments.python,
        analyzer,
        Path(arguments.llvm_objdump),
        report_root / "0.json",
        staged_controls,
    )
    if baseline_code != 0:
        fail("non-strict native control analysis failed")
    baseline_artifacts = require_report(baseline_payload, len(staged_controls))
    assert_native_controls(baseline_artifacts, expected_hashes)
    dispatch_normal_hash = expected_hashes["dispatch-normal"]
    dispatch_normal_staged = staged_controls_by_label["dispatch-normal"]
    baseline_dispatch_normal = artifact_for_hash(
        baseline_artifacts, dispatch_normal_hash, "baseline dispatch-normal artifact"
    )
    dispatch_normal_score = assert_dispatch_normal_observation(baseline_dispatch_normal)

    interpreter_loop_hash = expected_hashes["interpreter-loop"]
    interpreter_loop_staged = staged_controls_by_label["interpreter-loop"]
    (
        controller_exact_code,
        controller_exact_payload,
        controller_exact_verdict,
    ) = invoke_controller(
        arguments.python,
        controller,
        analyzer,
        Path(arguments.llvm_objdump),
        report_root / "10.json",
        report_root / "10.verdict.json",
        "interpreter-loop",
        interpreter_loop_staged,
        "interpreter_like",
    )
    if controller_exact_code != 0:
        fail("exact interpreter-like controller expectation failed")
    assert_controller_positive_verdict(
        controller_exact_payload,
        controller_exact_verdict,
        interpreter_loop_hash,
        "interpreter_like",
        "pass",
    )

    (
        controller_mismatch_code,
        controller_mismatch_payload,
        controller_mismatch_verdict,
    ) = invoke_controller(
        arguments.python,
        controller,
        analyzer,
        Path(arguments.llvm_objdump),
        report_root / "11.json",
        report_root / "11.verdict.json",
        "interpreter-loop",
        interpreter_loop_staged,
        "partial",
    )
    if controller_mismatch_code == 0:
        fail("partial controller expectation accepted interpreter-like evidence")
    assert_controller_positive_verdict(
        controller_mismatch_payload,
        controller_mismatch_verdict,
        interpreter_loop_hash,
        "partial",
        "fail",
    )

    (
        controller_default_code,
        controller_default_payload,
        controller_default_verdict,
    ) = invoke_controller(
        arguments.python,
        controller,
        analyzer,
        Path(arguments.llvm_objdump),
        report_root / "12.json",
        report_root / "12.verdict.json",
        "interpreter-loop",
        interpreter_loop_staged,
    )
    if controller_default_code == 0:
        fail("default vm-candidate expectation accepted interpreter-like evidence")
    assert_controller_positive_verdict(
        controller_default_payload,
        controller_default_verdict,
        interpreter_loop_hash,
        "vm_candidate",
        "fail",
    )

    (
        controller_minimum_code,
        controller_minimum_payload,
        controller_minimum_verdict,
    ) = invoke_controller(
        arguments.python,
        controller,
        analyzer,
        Path(arguments.llvm_objdump),
        report_root / "13.json",
        report_root / "13.verdict.json",
        "interpreter-loop",
        interpreter_loop_staged,
        positive_minima=("interpreter-loop=interpreter_like",),
    )
    if controller_minimum_code != 0:
        fail("minimum interpreter-like controller expectation failed")
    assert_controller_positive_verdict(
        controller_minimum_payload,
        controller_minimum_verdict,
        interpreter_loop_hash,
        "interpreter_like_or_vm_candidate",
        "pass",
    )

    vm_candidate_analyzer = make_vm_candidate_analyzer(work / "h")
    (
        controller_minimum_vm_candidate_code,
        controller_minimum_vm_candidate_payload,
        controller_minimum_vm_candidate_verdict,
    ) = invoke_controller(
        arguments.python,
        controller,
        vm_candidate_analyzer,
        Path(arguments.llvm_objdump),
        report_root / "18.json",
        report_root / "18.verdict.json",
        "interpreter-loop",
        interpreter_loop_staged,
        positive_minima=("interpreter-loop=interpreter_like",),
    )
    if controller_minimum_vm_candidate_code != 0:
        fail("minimum interpreter-like controller expectation rejected vm candidate")
    assert_controller_positive_verdict(
        controller_minimum_vm_candidate_payload,
        controller_minimum_vm_candidate_verdict,
        interpreter_loop_hash,
        "interpreter_like_or_vm_candidate",
        "pass",
        expected_actual_classification="vm_candidate",
    )

    (
        controller_minimum_malformed_code,
        controller_minimum_malformed_payload,
        controller_minimum_malformed_verdict,
    ) = invoke_controller(
        arguments.python,
        controller,
        analyzer,
        Path(arguments.llvm_objdump),
        report_root / "14.json",
        report_root / "14.verdict.json",
        "interpreter-loop",
        interpreter_loop_staged,
        "interpreter_like",
        positive_minima=("interpreter-loop=partial",),
    )
    if controller_minimum_malformed_code == 0:
        fail("partial positive minimum was accepted")
    assert_controller_positive_verdict(
        controller_minimum_malformed_payload,
        controller_minimum_malformed_verdict,
        interpreter_loop_hash,
        "interpreter_like",
        "fail",
        ("invalid_positive_minimum",),
    )

    (
        controller_minimum_duplicate_code,
        controller_minimum_duplicate_payload,
        controller_minimum_duplicate_verdict,
    ) = invoke_controller(
        arguments.python,
        controller,
        analyzer,
        Path(arguments.llvm_objdump),
        report_root / "15.json",
        report_root / "15.verdict.json",
        "interpreter-loop",
        interpreter_loop_staged,
        "interpreter_like",
        positive_minima=(
            "interpreter-loop=interpreter_like",
            "interpreter-loop=interpreter_like",
        ),
    )
    if controller_minimum_duplicate_code == 0:
        fail("duplicate positive minimum was accepted")
    assert_controller_positive_verdict(
        controller_minimum_duplicate_payload,
        controller_minimum_duplicate_verdict,
        interpreter_loop_hash,
        "interpreter_like",
        "fail",
        ("duplicate_positive_minimum",),
    )

    (
        controller_minimum_unmatched_code,
        controller_minimum_unmatched_payload,
        controller_minimum_unmatched_verdict,
    ) = invoke_controller(
        arguments.python,
        controller,
        analyzer,
        Path(arguments.llvm_objdump),
        report_root / "16.json",
        report_root / "16.verdict.json",
        "interpreter-loop",
        interpreter_loop_staged,
        "interpreter_like",
        positive_minima=("unmatched=interpreter_like",),
    )
    if controller_minimum_unmatched_code == 0:
        fail("unmatched positive minimum was accepted")
    assert_controller_positive_verdict(
        controller_minimum_unmatched_payload,
        controller_minimum_unmatched_verdict,
        interpreter_loop_hash,
        "interpreter_like",
        "fail",
        ("unmatched_positive_minimum",),
    )

    (
        controller_minimum_conflict_code,
        controller_minimum_conflict_payload,
        controller_minimum_conflict_verdict,
    ) = invoke_controller(
        arguments.python,
        controller,
        analyzer,
        Path(arguments.llvm_objdump),
        report_root / "17.json",
        report_root / "17.verdict.json",
        "interpreter-loop",
        interpreter_loop_staged,
        "interpreter_like",
        positive_minima=("interpreter-loop=interpreter_like",),
    )
    if controller_minimum_conflict_code == 0:
        fail("conflicting positive expectation and minimum were accepted")
    assert_controller_positive_verdict(
        controller_minimum_conflict_payload,
        controller_minimum_conflict_verdict,
        interpreter_loop_hash,
        "interpreter_like",
        "fail",
        ("positive_expectation_minimum_conflict",),
    )


    reverse_code, reverse_payload = invoke_analyzer(
        arguments.python,
        analyzer,
        Path(arguments.llvm_objdump),
        report_root / "1.json",
        list(reversed(staged_controls)),
    )
    if reverse_code != 0:
        fail("reverse-order control analysis failed")
    reverse_artifacts = require_report(reverse_payload, len(staged_controls))
    assert_native_controls(reverse_artifacts, expected_hashes)
    if reverse_payload != baseline_payload:
        fail("reverse-order analysis changed the report")

    renamed_controls: list[Path] = []
    for index, (_, digest) in enumerate(expected_hashes.items()):
        source_path = staged_controls[index]
        renamed_path, renamed_digest = stage_copy(source_path, renamed_root, f"{index}:{digest}")
        if renamed_digest != digest:
            fail("renamed artifact content changed")
        renamed_controls.append(renamed_path)
    renamed_code, renamed_payload = invoke_analyzer(
        arguments.python,
        analyzer,
        Path(arguments.llvm_objdump),
        report_root / "2.json",
        renamed_controls,
    )
    if renamed_code != 0:
        fail("renamed control analysis failed")
    renamed_artifacts = require_report(renamed_payload, len(staged_controls))
    assert_native_controls(renamed_artifacts, expected_hashes)
    if renamed_payload != baseline_payload:
        fail("renamed analysis changed the report")

    unstripped_source = raw_controls["dispatch-normal"]
    unstripped_staged, unstripped_digest = stage_copy(unstripped_source, work / "e")
    if unstripped_digest == dispatch_normal_hash:
        fail("symbol stripping did not change the dispatch-normal artifact")
    unstripped_code, unstripped_payload = invoke_analyzer(
        arguments.python,
        analyzer,
        Path(arguments.llvm_objdump),
        report_root / "3.json",
        [unstripped_staged],
    )
    if unstripped_code != 0:
        fail("unstripped dispatch-normal analysis failed")
    unstripped_artifacts = require_report(unstripped_payload, 1)
    unstripped_dispatch_normal = artifact_for_hash(
        unstripped_artifacts, unstripped_digest, "unstripped dispatch-normal artifact"
    )
    assert_dispatch_normal_observation(unstripped_dispatch_normal)
    if require_mapping(
        unstripped_dispatch_normal.get("recovery"), "unstripped dispatch-normal recovery"
    ) != require_mapping(
        baseline_dispatch_normal.get("recovery"), "stripped dispatch-normal recovery"
    ):
        fail("symbol stripping changed dispatch-normal structural recovery")

    exact_gate_code, exact_gate_payload = invoke_analyzer(
        arguments.python,
        analyzer,
        Path(arguments.llvm_objdump),
        report_root / "4.json",
        [dispatch_normal_staged],
        max_score=dispatch_normal_score,
    )
    if exact_gate_code != 0:
        fail("exact recovery score gate failed")
    exact_gate_artifacts = require_report(exact_gate_payload, 1)
    exact_gate_dispatch_normal = artifact_for_hash(
        exact_gate_artifacts, dispatch_normal_hash, "exact-gate dispatch-normal artifact"
    )
    if assert_dispatch_normal_observation(exact_gate_dispatch_normal) != dispatch_normal_score:
        fail("exact recovery score gate changed the dispatch-normal score")
    assert_score_gate(
        exact_gate_payload, exact_gate_dispatch_normal, dispatch_normal_score, False
    )
    if require_mapping(
        exact_gate_dispatch_normal.get("recovery"), "exact-gate dispatch-normal recovery"
    ) != require_mapping(
        baseline_dispatch_normal.get("recovery"), "baseline dispatch-normal recovery"
    ):
        fail("exact recovery score gate changed structural recovery")

    below_maximum_score = dispatch_normal_score - 1
    below_gate_code, below_gate_payload = invoke_analyzer(
        arguments.python,
        analyzer,
        Path(arguments.llvm_objdump),
        report_root / "5.json",
        [dispatch_normal_staged],
        max_score=below_maximum_score,
    )
    below_gate_artifacts = require_report(below_gate_payload, 1)
    below_gate_dispatch_normal = artifact_for_hash(
        below_gate_artifacts, dispatch_normal_hash, "below-gate dispatch-normal artifact"
    )
    if assert_dispatch_normal_observation(below_gate_dispatch_normal) != dispatch_normal_score:
        fail("below-max recovery score gate changed the dispatch-normal score")
    assert_score_gate(
        below_gate_payload, below_gate_dispatch_normal, below_maximum_score, True
    )
    if below_gate_code == 0:
        fail("below-max recovery score gate did not fail after reporting")
    if require_mapping(
        below_gate_dispatch_normal.get("recovery"), "below-gate dispatch-normal recovery"
    ) != require_mapping(
        baseline_dispatch_normal.get("recovery"), "baseline dispatch-normal recovery"
    ):
        fail("below-max recovery score gate changed structural recovery")

    invalid_inputs = make_invalid_inputs(
        arguments.compiler,
        source,
        staged_controls[0],
        invalid_root,
    )
    invalid_code, invalid_payload = invoke_analyzer(
        arguments.python,
        analyzer,
        Path(arguments.llvm_objdump),
        report_root / "6.json",
        invalid_inputs,
    )
    if invalid_code != 0:
        fail("non-strict invalid-artifact analysis failed")
    invalid_artifacts = require_report(invalid_payload, len(invalid_inputs))
    assert_unavailable_artifacts(invalid_artifacts)

    strict_invalid_code, strict_invalid_payload = invoke_analyzer(
        arguments.python,
        analyzer,
        Path(arguments.llvm_objdump),
        report_root / "7.json",
        invalid_inputs,
        strict=True,
    )
    strict_invalid_artifacts = require_report(strict_invalid_payload, len(invalid_inputs))
    assert_unavailable_artifacts(strict_invalid_artifacts)
    if strict_invalid_code == 0:
        fail("strict invalid-artifact analysis did not fail after reporting")

    failing_objdump = make_failing_objdump(work / "g")
    objdump_code, objdump_payload = invoke_analyzer(
        arguments.python,
        analyzer,
        failing_objdump,
        report_root / "8.json",
        [staged_controls[0]],
    )
    if objdump_code != 0:
        fail("non-strict objdump failure did not complete")
    objdump_artifacts = require_report(objdump_payload, 1)
    assert_unavailable_artifacts(objdump_artifacts)

    strict_objdump_code, strict_objdump_payload = invoke_analyzer(
        arguments.python,
        analyzer,
        failing_objdump,
        report_root / "9.json",
        [staged_controls[0]],
        strict=True,
    )
    strict_objdump_artifacts = require_report(strict_objdump_payload, 1)
    assert_unavailable_artifacts(strict_objdump_artifacts)
    if strict_objdump_code == 0:
        fail("strict objdump failure did not fail after reporting")

    print(f"controls={len(CONTROL_SPECS)}")
    print("native_controls=not_vm_candidate")
    print("positive_expectation_override=exact_interpreter_like")
    print("positive_expectation_mismatch=partial_rejected")
    print("positive_expectation_default=exact_vm_candidate_rejected")
    print("positive_minimum=interpreter_like_or_vm_candidate")
    print("positive_minimum_malformed=partial_rejected")
    print("positive_minimum_duplicate=rejected")
    print("positive_minimum_unmatched=rejected")
    print("positive_expectation_minimum_conflict=rejected")
    print("structural_invariance=pass")
    print("score_gate=pass")
    print(f"invalid_nonstrict={len(invalid_inputs)}")
    print("invalid_strict=report_before_fail")
    print("objdump_failure=report_before_fail")
    print("binary_control_fixtures=pass")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FixtureError as error:
        print(f"binary control fixture failed: {error}", file=sys.stderr)
        raise SystemExit(1)
