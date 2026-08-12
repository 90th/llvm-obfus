#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, BinaryIO, Sequence


BINARY_REPORT_NAME = "binary-recovery.json"
CONTROL_REPORT_NAME = "binary-recovery-controls.json"
COMMAND_TIMEOUT_SECONDS = 900
COMMAND_OUTPUT_LIMIT = 8192
REPORT_SIZE_LIMIT = 16 * 1024 * 1024
SEED_PATTERN = re.compile(r"[1-9][0-9]*")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
CLASSIFICATIONS = frozenset(
    {
        "vm_candidate",
        "interpreter_like",
        "partial",
        "inconclusive",
        "unavailable",
    }
)
CONTROL_ROLES = frozenset({"positive", "baseline", "negative"})
POSITIVE_EXPECTATIONS = frozenset({"vm_candidate", "interpreter_like", "partial"})
BOUNDED_POSITIVE_EXPECTATION = "interpreter_like_or_vm_candidate"
BOUNDED_POSITIVE_CLASSIFICATIONS = frozenset({"interpreter_like", "vm_candidate"})
NON_POSITIVE_EXPECTATION = "not_vm_candidate"


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="verify binary recovery controls across isolated fixed-seed builds"
    )
    parser.add_argument("--cmake", type=Path, required=True)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--llvm-dir", type=Path, required=True)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--llvm-objdump", type=Path, required=True)
    parser.add_argument("--analyzer", type=Path, required=True)
    parser.add_argument("--controller", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--report-out", type=Path, required=True)
    parser.add_argument("--seeds", default="10101,20202,30303")
    return parser.parse_args(argv)


def parse_seeds(value: str) -> tuple[str, ...]:
    seeds = [seed.strip() for seed in value.split(",") if seed.strip()]
    if len(seeds) != 3:
        raise ValueError("expected exactly three fixed seeds")
    if len(set(seeds)) != len(seeds):
        raise ValueError("fixed seeds must be distinct")
    invalid = [seed for seed in seeds if SEED_PATTERN.fullmatch(seed) is None]
    if invalid:
        raise ValueError(
            "fixed seeds must be non-zero base-10 integers without leading zeroes: "
            + ", ".join(sorted(invalid))
        )
    return tuple(sorted(seeds, key=int))


def is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def normalized_text(text: str, replacements: Sequence[tuple[Path, str]]) -> str:
    normalized = ANSI_ESCAPE_PATTERN.sub("", text.replace("\r\n", "\n").replace("\r", "\n"))
    candidates: list[tuple[str, str]] = []
    for path, label in replacements:
        raw = str(path)
        resolved = str(path.resolve(strict=False))
        candidates.append((raw, label))
        if resolved != raw:
            candidates.append((resolved, label))
    for raw, label in sorted(set(candidates), key=lambda item: len(item[0]), reverse=True):
        if raw:
            normalized = normalized.replace(raw, label)
    lines = [line.rstrip() for line in normalized.split("\n")]
    while lines and not lines[0]:
        lines.pop(0)
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines)


def bounded_text(stream: BinaryIO) -> str:
    stream.flush()
    stream.seek(0, os.SEEK_END)
    size = stream.tell()
    if size <= COMMAND_OUTPUT_LIMIT:
        stream.seek(0)
        data = stream.read()
    else:
        marker = f"\n... <truncated {size - COMMAND_OUTPUT_LIMIT} bytes> ...\n".encode("utf-8")
        captured_size = COMMAND_OUTPUT_LIMIT - len(marker)
        prefix_size = captured_size // 2
        suffix_size = captured_size - prefix_size
        stream.seek(0)
        prefix = stream.read(prefix_size)
        stream.seek(max(0, size - suffix_size))
        suffix = stream.read(suffix_size)
        data = prefix + marker + suffix
    return data.decode("utf-8", errors="replace")


def run_command(
    argv: Sequence[str], replacements: Sequence[tuple[Path, str]]
) -> dict[str, Any]:
    environment = os.environ.copy()
    environment["LC_ALL"] = "C"
    environment["LANG"] = "C"
    environment["TZ"] = "UTC"
    with tempfile.TemporaryFile(mode="w+b") as stdout, tempfile.TemporaryFile(mode="w+b") as stderr:
        try:
            completed = subprocess.run(
                list(argv),
                check=False,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                timeout=COMMAND_TIMEOUT_SECONDS,
            )
            returncode: int | None = completed.returncode
            execution_error: str | None = None
            timed_out = False
        except subprocess.TimeoutExpired:
            returncode = None
            execution_error = f"timed out after {COMMAND_TIMEOUT_SECONDS} seconds"
            timed_out = True
        except OSError as error:
            returncode = None
            execution_error = f"{type(error).__name__}: {error}"
            timed_out = False
        failed = returncode != 0 or execution_error is not None
        record: dict[str, Any] = {
            "returncode": returncode,
            "status": "fail" if failed else "pass",
        }
        if failed:
            detail: dict[str, Any] = {
                "argv": [normalized_text(argument, replacements) for argument in argv],
                "stderr": normalized_text(bounded_text(stderr), replacements),
                "stdout": normalized_text(bounded_text(stdout), replacements),
            }
            if execution_error is not None:
                detail["error"] = normalized_text(execution_error, replacements)
            if timed_out:
                detail["timed_out"] = True
            record["detail"] = detail
        return record


def clean_build_directory(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=False)


def load_json_object(path: Path, replacements: Sequence[tuple[Path, str]]) -> tuple[dict[str, Any] | None, str | None]:
    try:
        size = path.stat().st_size
    except OSError as error:
        return None, normalized_text(f"{type(error).__name__}: {error}", replacements)
    if size > REPORT_SIZE_LIMIT:
        return None, f"report exceeds {REPORT_SIZE_LIMIT} bytes"
    try:
        with path.open("r", encoding="utf-8") as report_file:
            loaded = json.load(report_file)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        return None, normalized_text(f"{type(error).__name__}: {error}", replacements)
    if not isinstance(loaded, dict):
        return None, "top-level JSON value is not an object"
    return loaded, None


def validate_binary_report(report: dict[str, Any]) -> tuple[list[str], list[dict[str, Any]]]:
    issues: list[str] = []
    expected_values = {
        "analysis_boundary": "binary-only",
        "report_kind": "binary_vm_recovery",
        "schema_version": 1,
        "tool": "obf-re-harness-binary",
    }
    for key, expected in expected_values.items():
        if report.get(key) != expected:
            issues.append(f"unexpected {key}")
    if not isinstance(report.get("summary"), dict):
        issues.append("summary must be an object")
    artifacts_value = report.get("artifacts")
    if not isinstance(artifacts_value, list) or not artifacts_value:
        issues.append("artifacts must be a non-empty list")
        return issues, []

    artifacts: list[dict[str, Any]] = []
    classifications_by_hash: dict[str, str] = {}
    for index, artifact in enumerate(artifacts_value):
        prefix = f"artifact {index}"
        if not isinstance(artifact, dict):
            issues.append(f"{prefix} is not an object")
            continue
        identity = artifact.get("identity")
        if not isinstance(identity, dict):
            issues.append(f"{prefix} has no identity object")
            continue
        sha256 = identity.get("sha256")
        size = identity.get("size")
        if not isinstance(sha256, str) or SHA256_PATTERN.fullmatch(sha256) is None:
            issues.append(f"{prefix} has invalid SHA-256")
            continue
        if not is_int(size) or size < 0:
            issues.append(f"{prefix} has invalid size")
            continue
        if artifact.get("status") not in {"analyzed", "partial", "unavailable"}:
            issues.append(f"{prefix} has invalid status")
        if not isinstance(artifact.get("capabilities"), dict):
            issues.append(f"{prefix} has invalid capabilities")
        if not isinstance(artifact.get("issues"), list):
            issues.append(f"{prefix} has invalid issues")
        if not isinstance(artifact.get("metadata_exposure"), dict):
            issues.append(f"{prefix} has invalid metadata exposure")
        recovery = artifact.get("recovery")
        if not isinstance(recovery, dict):
            issues.append(f"{prefix} has no recovery object")
            continue
        for key in ("function_regions", "data_regions", "candidates", "relationships"):
            if not isinstance(recovery.get(key), list):
                issues.append(f"{prefix} has invalid {key}")
        scores = recovery.get("scores")
        if not isinstance(scores, dict):
            issues.append(f"{prefix} has invalid scores")
        else:
            for score_name in ("control", "handlers", "state", "data", "structural"):
                score = scores.get(score_name)
                if not isinstance(score, (int, float)) or isinstance(score, bool):
                    issues.append(f"{prefix} has invalid {score_name} score")
        assessment = recovery.get("assessment")
        if not isinstance(assessment, dict):
            issues.append(f"{prefix} has invalid assessment")
            continue
        classification = assessment.get("classification")
        if classification not in CLASSIFICATIONS:
            issues.append(f"{prefix} has invalid classification")
            continue
        if assessment.get("semantic_recovery") != "unavailable":
            issues.append(f"{prefix} has invalid semantic recovery")
        previous = classifications_by_hash.get(sha256)
        if previous is not None and previous != classification:
            issues.append(f"artifact hash {sha256} has conflicting classifications")
            continue
        classifications_by_hash[sha256] = classification
        artifacts.append(
            {
                "classification": classification,
                "sha256": sha256,
                "size": size,
                "status": artifact.get("status"),
            }
        )
    return issues, sorted(artifacts, key=lambda artifact: (artifact["sha256"], artifact["size"]))


def canonical_control_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "actual_classification": row.get("actual_classification"),
        "expected": row.get("expected"),
        "label": row.get("label"),
        "role": row.get("role"),
        "sha256": row.get("sha256"),
        "size": row.get("size"),
        "status": row.get("status"),
    }


def control_sort_key(row: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(row.get("role", "")),
        str(row.get("label", "")),
        str(row.get("sha256", "")),
    )


def validate_control_report(
    report: dict[str, Any], artifacts: Sequence[dict[str, Any]]
) -> tuple[list[str], list[dict[str, Any]]]:
    issues: list[str] = []
    expected_values = {
        "report_kind": "binary_vm_recovery_controls",
        "schema_version": 1,
        "tool": "obf-re-harness-binary-controls",
    }
    for key, expected in expected_values.items():
        if report.get(key) != expected:
            issues.append(f"unexpected {key}")
    if not isinstance(report.get("issues"), list):
        issues.append("issues must be a list")
    analyzer = report.get("analyzer")
    if not isinstance(analyzer, dict):
        issues.append("analyzer must be an object")
    else:
        if analyzer.get("status") != "valid":
            issues.append("analyzer status is not valid")
        artifact_count = analyzer.get("artifact_count")
        if not is_int(artifact_count) or artifact_count != len(artifacts):
            issues.append("analyzer artifact count does not match binary report")
        returncode = analyzer.get("returncode")
        if returncode is not None and not is_int(returncode):
            issues.append("analyzer return code is invalid")
    summary = report.get("summary")
    if not isinstance(summary, dict):
        issues.append("summary must be an object")
    elif summary.get("status") != "pass":
        issues.append("control summary status is not pass")
    controls_value = report.get("controls")
    if not isinstance(controls_value, list) or not controls_value:
        issues.append("controls must be a non-empty list")
        return issues, []

    classifications = {artifact["sha256"]: artifact["classification"] for artifact in artifacts}
    controls: list[dict[str, Any]] = []
    positive_count = 0
    vm_candidate_positive_count = 0
    for index, control in enumerate(controls_value):
        prefix = f"control {index}"
        if not isinstance(control, dict):
            issues.append(f"{prefix} is not an object")
            continue
        if not isinstance(control.get("issues"), list):
            issues.append(f"{prefix} has invalid issues")
        canonical = canonical_control_row(control)
        role = canonical["role"]
        expected = canonical["expected"]
        sha256 = canonical["sha256"]
        classification = canonical["actual_classification"]
        if role not in CONTROL_ROLES:
            issues.append(f"{prefix} has invalid role")
        if role == "positive":
            if (
                expected not in POSITIVE_EXPECTATIONS
                and expected != BOUNDED_POSITIVE_EXPECTATION
            ):
                issues.append(f"{prefix} has invalid positive expectation")
        elif expected != NON_POSITIVE_EXPECTATION:
            issues.append(f"{prefix} has invalid non-positive expectation")
        if not isinstance(canonical["label"], str) or not canonical["label"]:
            issues.append(f"{prefix} has invalid label")
        if not isinstance(sha256, str) or SHA256_PATTERN.fullmatch(sha256) is None:
            issues.append(f"{prefix} has invalid SHA-256")
        if classification not in CLASSIFICATIONS:
            issues.append(f"{prefix} has invalid classification")
        if canonical["status"] != "pass":
            issues.append(f"{prefix} did not pass")
        size = canonical["size"]
        if not is_int(size) or size < 0:
            issues.append(f"{prefix} has invalid size")
        if isinstance(sha256, str) and sha256 in classifications:
            if classifications[sha256] != classification:
                issues.append(f"{prefix} classification does not match binary report")
        else:
            issues.append(f"{prefix} does not map to binary report")
        if role == "positive":
            positive_count += 1
            if expected == BOUNDED_POSITIVE_EXPECTATION:
                matches_positive_expectation = (
                    classification in BOUNDED_POSITIVE_CLASSIFICATIONS
                )
            elif expected in POSITIVE_EXPECTATIONS:
                matches_positive_expectation = classification == expected
            else:
                matches_positive_expectation = False
            if not matches_positive_expectation:
                issues.append(f"{prefix} does not match its positive expectation")
            elif classification == "vm_candidate":
                vm_candidate_positive_count += 1
        elif role in CONTROL_ROLES and classification == "vm_candidate":
            issues.append(f"{prefix} does not satisfy not_vm_candidate")
        controls.append(canonical)
    if positive_count == 0:
        issues.append("control report has no positive controls")
    if vm_candidate_positive_count == 0:
        issues.append("control report has no vm_candidate positive controls")
    if isinstance(summary, dict):
        expected_counts = {
            "artifacts": len(artifacts),
            "baselines": sum(control["role"] == "baseline" for control in controls),
            "controls": len(controls),
            "failures": 0,
            "negatives": sum(control["role"] == "negative" for control in controls),
            "positives": positive_count,
        }
        for key, expected in expected_counts.items():
            if summary.get(key) != expected:
                issues.append(f"summary {key} does not match controls")
    return issues, sorted(controls, key=control_sort_key)


def command_failure(seed: str, stage: str, command: dict[str, Any]) -> dict[str, Any]:
    return {
        "detail": command.get("detail", {}),
        "seed": seed,
        "stage": stage,
        "type": "command",
    }


def report_failure(seed: str, report: str, detail: str) -> dict[str, Any]:
    return {
        "detail": detail,
        "report": report,
        "seed": seed,
        "type": "report",
    }


def prepare_replacements(args: argparse.Namespace, build_dir: Path) -> list[tuple[Path, str]]:
    return [
        (build_dir, "$BUILD_DIR"),
        (args.source_dir, "$SOURCE_DIR"),
        (args.output_root, "$OUTPUT_ROOT"),
        (args.cmake, "$CMAKE"),
        (args.llvm_dir, "$LLVM_DIR"),
        (args.python, "$PYTHON"),
        (args.llvm_objdump, "$LLVM_OBJDUMP"),
        (args.analyzer, "$ANALYZER"),
        (args.controller, "$CONTROLLER"),
    ]


def configure_command(args: argparse.Namespace, build_dir: Path, seed: str) -> list[str]:
    return [
        str(args.cmake),
        "-S",
        str(args.source_dir),
        "-B",
        str(build_dir),
        f"-DLLVM_DIR={args.llvm_dir}",
        f"-DPython3_EXECUTABLE={args.python}",
        f"-DOBF_OBJDUMP={args.llvm_objdump}",
        f"-DOBF_RE_HARNESS_BINARY_SCRIPT={args.analyzer}",
        f"-DOBF_RE_HARNESS_BINARY_CONTROLS_SCRIPT={args.controller}",
        f"-DOBF_BENCHMARK_SEED={seed}",
    ]


def build_command(cmake: Path, build_dir: Path, target: str) -> list[str]:
    return [str(cmake), "--build", str(build_dir), "--target", target]


def collect_reports(
    seed: str,
    build_dir: Path,
    replacements: Sequence[tuple[Path, str]],
    failures: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    binary_path = build_dir / "re-harness" / BINARY_REPORT_NAME
    control_path = build_dir / "re-harness" / CONTROL_REPORT_NAME
    binary_report, binary_error = load_json_object(binary_path, replacements)
    if binary_error is not None:
        failures.append(report_failure(seed, "binary", binary_error))
        return {
            "binary": {"artifact_count": 0, "status": "missing"},
            "controls": {"control_count": 0, "status": "not_checked"},
            "status": "fail",
        }, []
    binary_issues, artifacts = validate_binary_report(binary_report)
    if binary_issues:
        for issue in binary_issues:
            failures.append(report_failure(seed, "binary", issue))
    binary_status = "valid" if not binary_issues else "malformed"

    control_report, control_error = load_json_object(control_path, replacements)
    if control_error is not None:
        failures.append(report_failure(seed, "controls", control_error))
        return {
            "binary": {
                "artifact_count": len(artifacts),
                "artifacts": artifacts,
                "status": binary_status,
            },
            "controls": {"control_count": 0, "status": "missing"},
            "status": "fail",
        }, []
    control_issues, controls = validate_control_report(control_report, artifacts)
    if control_issues:
        for issue in control_issues:
            failures.append(report_failure(seed, "controls", issue))
    control_status = "valid" if not control_issues else "malformed"
    protected_artifacts = [
        {
            "classification": control["actual_classification"],
            "label": control["label"],
            "sha256": control["sha256"],
            "status": control["status"],
        }
        for control in controls
        if control["role"] == "positive" and control["status"] == "pass"
    ]
    valid = binary_status == "valid" and control_status == "valid"
    return {
        "binary": {
            "artifact_count": len(artifacts),
            "artifacts": artifacts,
            "status": binary_status,
        },
        "controls": {
            "control_count": len(controls),
            "outcomes": controls,
            "status": control_status,
        },
        "protected_artifacts": protected_artifacts,
        "status": "pass" if valid else "fail",
    }, protected_artifacts if valid else []


def run_seed(
    args: argparse.Namespace,
    seed: str,
    failures: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    build_dir = args.output_root / f"seed-{seed}"
    replacements = prepare_replacements(args, build_dir)
    seed_record: dict[str, Any] = {
        "commands": {},
        "reports_status": "not_run",
        "seed": seed,
        "status": "fail",
    }
    try:
        clean_build_directory(build_dir)
    except OSError as error:
        failures.append(
            {
                "detail": normalized_text(f"{type(error).__name__}: {error}", replacements),
                "seed": seed,
                "stage": "clean",
                "type": "setup",
            }
        )
        return seed_record, []

    configure = run_command(configure_command(args, build_dir, seed), replacements)
    seed_record["commands"]["configure"] = configure
    if configure["status"] != "pass":
        failures.append(command_failure(seed, "configure", configure))
        return seed_record, []

    benchmark_build = run_command(
        build_command(args.cmake, build_dir, "obf-benchmarks-e2e"), replacements
    )
    seed_record["commands"]["obf-benchmarks-e2e"] = benchmark_build
    if benchmark_build["status"] != "pass":
        failures.append(command_failure(seed, "obf-benchmarks-e2e", benchmark_build))
        return seed_record, []

    harness_build = run_command(
        build_command(args.cmake, build_dir, "obf-re-harness-binary"), replacements
    )
    seed_record["commands"]["obf-re-harness-binary"] = harness_build
    if harness_build["status"] != "pass":
        failures.append(command_failure(seed, "obf-re-harness-binary", harness_build))

    report_record, protected_artifacts = collect_reports(seed, build_dir, replacements, failures)
    reports_status = report_record.pop("status")
    seed_record.update(report_record)
    seed_record["reports_status"] = reports_status
    if harness_build["status"] == "pass" and reports_status == "pass":
        seed_record["status"] = "pass"
        return seed_record, protected_artifacts
    return seed_record, []


def validate_arguments(args: argparse.Namespace, seeds: Sequence[str]) -> list[str]:
    issues: list[str] = []
    for name in ("cmake", "python", "llvm_objdump", "analyzer", "controller"):
        path = getattr(args, name)
        if not path.is_file():
            issues.append(f"{name.replace('_', '-')} is not a file")
    if not args.source_dir.is_dir():
        issues.append("source-dir is not a directory")
    if not args.llvm_dir.is_dir():
        issues.append("llvm-dir is not a directory")
    output_root = args.output_root.resolve(strict=False)
    report_out = args.report_out.resolve(strict=False)
    for seed in seeds:
        build_dir = (output_root / f"seed-{seed}").resolve(strict=False)
        try:
            report_out.relative_to(build_dir)
        except ValueError:
            continue
        issues.append("report-out must not be inside an isolated build directory")
        break
    return issues


def aggregate_protected_artifacts(
    seed_artifacts: Sequence[tuple[str, Sequence[dict[str, Any]]]]
) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for seed, artifacts in seed_artifacts:
        for artifact in artifacts:
            sha256 = artifact["sha256"]
            grouped.setdefault(sha256, []).append(
                {
                    "classification": artifact["classification"],
                    "label": artifact["label"],
                    "seed": seed,
                    "status": artifact["status"],
                }
            )
    return [
        {
            "outcomes": sorted(
                outcomes,
                key=lambda outcome: (
                    outcome["seed"],
                    outcome["label"],
                    outcome["classification"],
                ),
            ),
            "sha256": sha256,
        }
        for sha256, outcomes in sorted(grouped.items())
    ]

def protected_hashes_vary_by_seed(
    seed_artifacts: Sequence[tuple[str, Sequence[dict[str, Any]]]]
) -> bool:
    if len(seed_artifacts) < 2 or any(not artifacts for _, artifacts in seed_artifacts):
        return False
    signatures = {
        tuple(
            sorted(
                (str(artifact["label"]), str(artifact["sha256"]))
                for artifact in artifacts
            )
        )
        for _, artifacts in seed_artifacts
    }
    return len(signatures) > 1




def failure_sort_key(failure: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(failure.get("seed", "")),
        str(failure.get("type", "")),
        str(failure.get("stage", failure.get("report", ""))),
        json.dumps(failure.get("detail", ""), sort_keys=True, separators=(",", ":")),
    )


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    failures: list[dict[str, Any]] = []
    report: dict[str, Any] = {
        "failures": failures,
        "protected_artifacts": [],
        "report_kind": "binary_vm_recovery_multiseed",
        "schema_version": 1,
        "seeds": [],
        "summary": {},
        "tool": "obf-re-harness-binary-multiseed",
    }
    try:
        seeds = parse_seeds(args.seeds)
    except ValueError as error:
        seeds = ()
        failures.append({"detail": str(error), "type": "arguments"})

    if seeds:
        for issue in validate_arguments(args, seeds):
            failures.append({"detail": issue, "type": "arguments"})
    try:
        args.output_root.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        failures.append(
            {
                "detail": normalized_text(
                    f"{type(error).__name__}: {error}",
                    [(args.output_root, "$OUTPUT_ROOT"), (args.report_out, "$REPORT_OUT")],
                ),
                "type": "setup",
            }
        )

    protected_by_seed: list[tuple[str, Sequence[dict[str, Any]]]] = []
    if not failures:
        for seed in seeds:
            seed_record, protected_artifacts = run_seed(args, seed, failures)
            report["seeds"].append(seed_record)
            protected_by_seed.append((seed, protected_artifacts))

    report["protected_artifacts"] = aggregate_protected_artifacts(protected_by_seed)
    distinct_hashes = len(report["protected_artifacts"])
    hashes_vary_by_seed = protected_hashes_vary_by_seed(protected_by_seed)
    valid_reports = sum(
        1 for seed_record in report["seeds"] if seed_record.get("status") == "pass"
    )
    if seeds and valid_reports != len(seeds):
        failures.append(
            {
                "detail": "not every seed produced valid structural and control reports",
                "type": "aggregate",
            }
        )
    if seeds and distinct_hashes < 2:
        failures.append(
            {
                "detail": "fewer than two distinct protected artifact hashes were observed",
                "type": "aggregate",
            }
        )
    if seeds and not hashes_vary_by_seed:
        failures.append(
            {
                "detail": "protected artifact hashes did not differ across seeds",
                "type": "aggregate",
            }
        )
    report["failures"] = sorted(failures, key=failure_sort_key)
    report["summary"] = {
        "distinct_protected_artifact_hashes": distinct_hashes,
        "failures": len(failures),
        "protected_hashes_vary_by_seed": hashes_vary_by_seed,
        "seeds_requested": len(seeds),
        "seeds_with_valid_reports": valid_reports,
        "status": "pass" if not failures else "fail",
    }
    try:
        write_report(args.report_out, report)
    except OSError as error:
        print(
            normalized_text(
                f"failed to write aggregate report: {type(error).__name__}: {error}",
                [(args.output_root, "$OUTPUT_ROOT"), (args.report_out, "$REPORT_OUT")],
            ),
            file=sys.stderr,
        )
        return 1

    print(
        "multiseed binary recovery: "
        f"{report['summary']['seeds_with_valid_reports']}/{report['summary']['seeds_requested']} "
        f"valid seed reports, {distinct_hashes} distinct protected artifact hash(es)"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
