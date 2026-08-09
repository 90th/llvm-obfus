#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import signal
import shutil
import subprocess
import sys
import time
from pathlib import Path


class matrix_failure(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise matrix_failure(message)


def read_log(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def rust_settings(arguments: list[str], family: str, name: str) -> list[str]:
    values: list[str] = []
    index = 0
    option = "-Z" if family == "Z" else "-C"
    while index < len(arguments):
        argument = arguments[index]
        if argument == option and index + 1 < len(arguments):
            value = arguments[index + 1]
            index += 2
        elif argument.startswith(option) and len(argument) > len(option):
            value = argument[len(option) :].removeprefix("=")
            index += 1
        else:
            index += 1
            continue
        if value == name or value.startswith(f"{name}="):
            values.append(value)
    return values


class wrapper_matrix:
    def __init__(self, arguments: argparse.Namespace) -> None:
        self.wrapper = Path(arguments.wrapper).resolve()
        llvm_match = re.search(
            r'^LLVM_PACKAGE_VERSION = r"(\d+)\.(\d+)',
            self.wrapper.read_text(encoding="utf-8"),
            re.MULTILINE,
        )
        require(llvm_match is not None, "generated Rust wrapper has no LLVM version")
        assert llvm_match is not None
        self.mismatched_llvm = (
            f"{llvm_match.group(1)}.{int(llvm_match.group(2)) + 1}.0"
        )
        self.mismatched_llvm_major = (
            f"{int(llvm_match.group(1)) + 1}.{llvm_match.group(2)}.0"
        )
        self.fake = Path(arguments.fake).resolve()
        self.config = Path(arguments.config).resolve()
        self.generic_config = Path(arguments.generic_config).resolve()
        self.plugin = str(Path(arguments.plugin).resolve())
        self.runtime = str(Path(arguments.runtime).resolve())
        self.work = Path(arguments.workdir).resolve()
        shutil.rmtree(self.work, ignore_errors=True)
        self.work.mkdir(parents=True)
        self.quoted_config = self.work / "quoted-frontend.yaml"
        config_text = self.config.read_text(encoding="utf-8")
        require("frontend: rust" in config_text, "Rust fixture has no frontend key")
        self.quoted_config.write_text(
            config_text.replace(
                "frontend: rust",
                '"fr\\x6fntend": "r\\x75st"',
                1,
            ),
            encoding="utf-8",
        )
        self.multiple_config = self.work / "multiple-documents.yaml"
        self.multiple_config.write_text(
            "profile: standard\n---\n" + config_text,
            encoding="utf-8",
        )
        self.flow_config = self.work / "flow-frontend.yaml"
        self.flow_config.write_text(
            "{frontend: rust, default_level: none, "
            "targets: [{match: rust_target, level: strong}], "
            "security: {strip_release_markers: true}}\n",
            encoding="utf-8",
        )
        self.log = self.work / "fake-rustc.jsonl"
        self.source = self.work / "source.rs"
        self.source.write_text("fn main() {}\n", encoding="utf-8")
        self.rustc = self._make_rustc_launcher()

    def _make_rustc_launcher(self) -> Path:
        launcher = self.work / "rustc"
        launcher.write_text(
            "#!/bin/sh\nexec "
            + shlex.quote(sys.executable)
            + " "
            + shlex.quote(str(self.fake))
            + ' "$@"\n',
            encoding="utf-8",
        )
        launcher.chmod(0o755)
        return launcher

    def invoke(
        self,
        label: str,
        wrapper_args: list[str],
        *,
        environment: dict[str, str] | None = None,
        pass_fds: tuple[int, ...] = (),
        expected_status: int = 0,
    ) -> tuple[subprocess.CompletedProcess[str], list[dict[str, object]]]:
        self.log.unlink(missing_ok=True)
        env = os.environ.copy()
        for key in (
            "OBF_CONFIG",
            "OBF_RUST_CRATE_NAME",
            "OBF_RUST_CRATE_TYPE",
            "OBF_RUST_CRATE_ROOT",
            "OBF_RUST_MANIFEST_DIR",
            "CARGO_MANIFEST_DIR",
            "CARGO_MAKEFLAGS",
            "MAKEFLAGS",
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "OBF_RUSTC_FAKE_RELEASE",
            "OBF_RUSTC_FAKE_LLVM",
            "OBF_RUSTC_FAKE_STATUS",
            "OBF_RUSTC_FAKE_PROBE_STATUS",
            "OBF_RUSTC_FAKE_PROBE_SIGNAL",
            "OBF_RUSTC_FAKE_SIGNAL",
            "OBF_RUSTC_FAKE_PARENT_SIGNAL",
            "OBF_RUSTC_FAKE_SIGNAL_MARKER",
        ):
            env.pop(key, None)
        env["OBF_RUSTC_FAKE_LOG"] = str(self.log)
        env["OBF_RUSTC_FAKE_WRAPPER"] = str(self.wrapper)
        if environment:
            env.update(environment)
        process_options: dict[str, object] = {}
        if pass_fds and os.name == "posix":
            process_options["pass_fds"] = pass_fds
        completed = subprocess.run(
            [str(self.wrapper), *wrapper_args],
            cwd=self.work,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            **process_options,
        )
        rows = read_log(self.log)
        require(
            completed.returncode == expected_status,
            f"{label}: expected status {expected_status}, got {completed.returncode}; "
            f"stdout={completed.stdout!r}; stderr={completed.stderr!r}",
        )
        return completed, rows

    @staticmethod
    def require_wrapper_error(label: str, completed: subprocess.CompletedProcess[str]) -> None:
        require(
            "obf-rustc:" in completed.stderr,
            f"{label}: expected obf-rustc diagnostic, got {completed.stderr!r}",
        )

    def active_direct_arguments(self, *extra: str) -> list[str]:
        has_emit = any(
            argument == "--emit" or argument.startswith("--emit=")
            for argument in extra
        )
        has_output = any(
            argument == "-o"
            or (
                argument.startswith("-o")
                and not argument.startswith("--")
                and len(argument) > 2
            )
            for argument in extra
        )
        arguments = [
            f"--rustc={self.rustc}",
            f"--obf-config={self.config}",
            "--crate-type=bin",
        ]
        if not has_emit:
            arguments.append("--emit=link")
        arguments.extend(extra)
        if not has_output:
            arguments.extend(["-o", str(self.work / "active-direct.out")])
        arguments.append(str(self.source))
        return arguments

    def final_row(self, label: str, rows: list[dict[str, object]]) -> dict[str, object]:
        require(len(rows) == 2, f"{label}: expected preflight and child, got {rows!r}")
        require(rows[0]["args"] == ["-vV"], f"{label}: missing preflight {rows!r}")
        return rows[1]

    def assert_active_injection(
        self,
        label: str,
        row: dict[str, object],
        *,
        link: bool = True,
        config: Path | None = None,
    ) -> None:
        arguments = row["args"]
        require(isinstance(arguments, list), f"{label}: malformed fake log")
        require(
            rust_settings(arguments, "Z", "llvm-plugins")
            == [f"llvm-plugins={self.plugin}"],
            f"{label}: expected exactly one plugin flag, got {arguments!r}",
        )
        require(
            rust_settings(arguments, "C", "codegen-units") == ["codegen-units=1"],
            f"{label}: expected exactly one codegen-units setting, got {arguments!r}",
        )
        expected_runtime = [f"link-arg={self.runtime}"] if link else []
        require(
            rust_settings(arguments, "C", "link-arg") == expected_runtime,
            f"{label}: unexpected runtime link arguments: {arguments!r}",
        )
        expected_config = self.config if config is None else config
        pinned_config = row["obf_config"]
        require(
            isinstance(pinned_config, str)
            and pinned_config != str(expected_config)
            and Path(pinned_config).name.startswith("obf-rustc-config-"),
            f"{label}: active child did not receive a pinned OBF_CONFIG",
        )
        require(
            not Path(pinned_config).exists(),
            f"{label}: pinned config was retained after the child exited",
        )

    def reject_without_touching_output(
        self, label: str, *extra: str, replace_crate_type: bool = False
    ) -> None:
        output = self.work / f"{label}.out"
        output.write_text("sentinel\n", encoding="utf-8")
        if replace_crate_type:
            wrapper_args = [
                f"--rustc={self.rustc}",
                f"--obf-config={self.config}",
                "--emit=llvm-ir,link",
                *extra,
                "-o",
                str(output),
                str(self.source),
            ]
        else:
            wrapper_args = self.active_direct_arguments(*extra, "-o", str(output))
        completed, rows = self.invoke(label, wrapper_args, expected_status=2)
        self.require_wrapper_error(label, completed)
        require(rows == [], f"{label}: rejected invocation reached fake rustc: {rows!r}")
        require(
            output.read_text(encoding="utf-8") == "sentinel\n",
            f"{label}: rejected invocation changed existing output",
        )

    def cargo_environment(self, root: Path) -> dict[str, str]:
        manifest = self.work / "cargo-package"
        return {
            "OBF_CONFIG": str(self.config),
            "OBF_RUST_MANIFEST_DIR": str(manifest),
            "OBF_RUST_CRATE_NAME": "same_name",
            "OBF_RUST_CRATE_TYPE": "bin",
            "OBF_RUST_CRATE_ROOT": str(root),
            "CARGO_MANIFEST_DIR": str(manifest),
            "RUSTC_WORKSPACE_WRAPPER": str(self.wrapper),
        }

    def cargo_arguments(self, source: Path, crate_type: str = "bin") -> list[str]:
        return [
            str(self.rustc),
            "--crate-name",
            "same_name",
            f"--crate-type={crate_type}",
            "--emit=link",
            str(source),
        ]

    def run(self) -> None:
        query, rows = self.invoke(
            "inactive-query", [f"--rustc={self.rustc}", "--version"]
        )
        require("FAKE-QUERY-SENTINEL" in query.stdout, "inactive query lost child output")
        require(rows == [{"args": ["--version"], "obf_config": None}], "inactive query was changed")

        query, rows = self.invoke(
            "wrapper-delimiter",
            [f"--rustc={self.rustc}", "--", "--version"],
        )
        require(
            "FAKE-QUERY-SENTINEL" in query.stdout,
            "wrapper delimiter lost child query output",
        )
        require(
            rows == [{"args": ["--version"], "obf_config": None}],
            "wrapper delimiter was forwarded to rustc",
        )

        _, rows = self.invoke(
            "inactive-verbose-version", [f"--rustc={self.rustc}", "-Vv"]
        )
        require(
            rows == [{"args": ["-Vv"], "obf_config": None}],
            "verbose version query was changed",
        )

        query_response = self.work / "query.rsp"
        query_response.write_text("--emit=llvm-ir\n", encoding="utf-8")
        query, rows = self.invoke(
            "active-query-response-pass-through",
            [
                f"--rustc={self.rustc}",
                f"--obf-config={self.config}",
                "--version",
                f"@{query_response}",
            ],
        )
        require(
            "FAKE-QUERY-SENTINEL" in query.stdout,
            "active query response file lost child output",
        )
        require(
            rows
            == [
                {
                    "args": ["--version", f"@{query_response}"],
                    "obf_config": None,
                }
            ],
            "active query response file was changed",
        )

        _, rows = self.invoke(
            "metadata-pass-through",
            [
                f"--rustc={self.rustc}",
                f"--obf-config={self.config}",
                "--emit=metadata,dep-info",
                str(self.source),
            ],
        )
        require(
            rows
            == [
                {
                    "args": ["--emit=metadata,dep-info", str(self.source)],
                    "obf_config": None,
                }
            ],
            f"metadata-only invocation was changed: {rows!r}",
        )

        _, rows = self.invoke(
            "active-direct",
            self.active_direct_arguments("--crate-type=bin,bin"),
        )
        active_row = self.final_row("active-direct", rows)
        self.assert_active_injection("active-direct", active_row)
        require(
            rust_settings(active_row["args"], "C", "split-debuginfo")
            == ["split-debuginfo=off"],
            f"active direct invocation did not force single-file debug output: {active_row!r}",
        )
        require(
            (self.work / "active-direct.out").read_bytes()
            == b"FAKE-RUSTC-OUTPUT\n",
            "active direct output was not atomically installed",
        )

        if os.name == "posix":
            read_fd, write_fd = os.pipe()
            try:
                _, rows = self.invoke(
                    "cargo-jobserver-fds",
                    self.active_direct_arguments(),
                    environment={
                        "CARGO_MAKEFLAGS": f"--jobserver-fds={read_fd},{write_fd}"
                    },
                    pass_fds=(read_fd, write_fd),
                )
                self.assert_active_injection(
                    "cargo-jobserver-fds",
                    self.final_row("cargo-jobserver-fds", rows),
                )
                require(
                    all(row.get("jobserver_fds_open") is True for row in rows),
                    "Cargo jobserver fds were closed before reaching rustc",
                )
            finally:
                os.close(read_fd)
                os.close(write_fd)

        _, rows = self.invoke(
            "direct-environment-config",
            [
                f"--rustc={self.rustc}",
                "--crate-type=bin",
                "--emit=link",
                "-o",
                str(self.work / "environment-config.out"),
                str(self.source),
            ],
            environment={"OBF_CONFIG": str(self.config)},
        )
        self.assert_active_injection(
            "direct-environment-config",
            self.final_row("direct-environment-config", rows),
        )

        _, rows = self.invoke(
            "codegen-without-link",
            [
                f"--rustc={self.rustc}",
                f"--obf-config={self.config}",
                "--crate-type=bin",
                "--emit=llvm-ir",
                "-o",
                str(self.work / "codegen-without-link.ll"),
                str(self.source),
            ],
        )
        self.assert_active_injection(
            "codegen-without-link",
            self.final_row("codegen-without-link", rows),
            link=False,
        )

        explicit_output = self.work / "explicit-emit.ll"
        _, rows = self.invoke(
            "explicit-emit-output",
            [
                f"--rustc={self.rustc}",
                f"--obf-config={self.config}",
                "--crate-type=bin",
                f"--emit=llvm-ir={explicit_output}",
                str(self.source),
            ],
        )
        self.assert_active_injection(
            "explicit-emit-output",
            self.final_row("explicit-emit-output", rows),
            link=False,
        )
        require(
            explicit_output.read_bytes() == b"FAKE-RUSTC-OUTPUT\n",
            "explicit emit output was not atomically installed",
        )

        _, rows = self.invoke(
            "split-wrapper-options",
            [
                "--rustc",
                str(self.rustc),
                "--obf-config",
                str(self.config),
                "--obf-enable",
                "--crate-type",
                "bin",
                "--emit",
                "link",
                "-o",
                str(self.work / "split-wrapper-options.out"),
                str(self.source),
            ],
        )
        self.assert_active_injection(
            "split-wrapper-options",
            self.final_row("split-wrapper-options", rows),
        )

        _, rows = self.invoke(
            "direct-test",
            self.active_direct_arguments("--test"),
        )
        self.assert_active_injection("direct-test", self.final_row("direct-test", rows))

        _, rows = self.invoke(
            "direct-cdylib",
            [
                f"--rustc={self.rustc}",
                f"--obf-config={self.config}",
                "--crate-type=cdylib",
                "--emit=link",
                "-o",
                str(self.work / "direct-cdylib.so"),
                str(self.source),
            ],
        )
        self.assert_active_injection(
            "direct-cdylib", self.final_row("direct-cdylib", rows)
        )

        repeated_output = self.work / "repeated-emit.ll"
        _, rows = self.invoke(
            "repeated-emit",
            self.active_direct_arguments(
                "--emit=llvm-ir",
                "--emit=llvm-ir",
                "-o",
                str(repeated_output),
            ),
        )
        repeated_row = self.final_row("repeated-emit", rows)
        self.assert_active_injection("repeated-emit", repeated_row, link=False)
        require(
            sum(
                argument == "--emit=llvm-ir"
                for argument in repeated_row["args"]
            )
            == 1,
            f"repeated --emit was not normalized: {repeated_row!r}",
        )

        for label, wrapper_args in (
            ("missing-rustc", ["--rustc"]),
            ("empty-rustc", ["--rustc="]),
            ("missing-config", ["--obf-config"]),
            ("empty-config", ["--obf-config="]),
        ):
            completed, rows = self.invoke(label, wrapper_args, expected_status=2)
            self.require_wrapper_error(label, completed)
            require(rows == [], f"{label}: malformed wrapper options reached child")

        _, rows = self.invoke(
            "exact-duplicates",
            self.active_direct_arguments(
                f"-Zllvm-plugins={self.plugin}",
                "-Z",
                f"llvm-plugins={self.plugin}",
                "-Ccodegen-units=1",
                "-C",
                "codegen-units=1",
                f"-Clink-arg={self.runtime}",
                "-C",
                f"link-arg={self.runtime}",
            ),
        )
        self.assert_active_injection("exact-duplicates", self.final_row("exact-duplicates", rows))


        missing_type_output = self.work / "missing-crate-type.ll"
        missing_type_output.write_text("sentinel\n", encoding="utf-8")
        completed, rows = self.invoke(
            "missing-crate-type",
            [
                f"--rustc={self.rustc}",
                f"--obf-config={self.config}",
                "--emit=llvm-ir",
                "-o",
                str(missing_type_output),
                str(self.source),
            ],
            expected_status=2,
        )
        self.require_wrapper_error("missing-crate-type", completed)
        require(rows == [], "missing crate type reached fake rustc")
        require(
            missing_type_output.read_text(encoding="utf-8") == "sentinel\n",
            "missing crate type changed the direct output",
        )
        for crate_type in ("rlib", "lib", "staticlib", "dylib", "proc-macro", "bin,cdylib"):
            self.reject_without_touching_output(
                f"unsupported-{crate_type}",
                f"--crate-type={crate_type}",
                replace_crate_type=True,
            )
        self.reject_without_touching_output("unsupported-emit", "--emit=link,mir")
        self.reject_without_touching_output(
            "multiple-codegen-outputs", "--emit=llvm-ir,link"
        )
        self.reject_without_touching_output(
            "mixed-codegen-sidecar", "--emit=link,dep-info"
        )
        self.reject_without_touching_output(
            "cross-target", "--target=wasm32-unknown-unknown"
        )
        self.reject_without_touching_output("linker-plugin-lto", "-Clinker-plugin-lto")
        self.reject_without_touching_output("conflicting-cgu", "-Ccodegen-units=2")
        self.reject_without_touching_output(
            "conflicting-plugin", "-Zllvm-plugins=/other/obf_plugin.so"
        )
        self.reject_without_touching_output(
            "llvm-policy-override",
            f"-Cllvm-args=--obf-config={self.generic_config}",
        )
        self.reject_without_touching_output(
            "conflicting-runtime", "-Clink-arg=/other/libobf_runtime.a"
        )
        self.reject_without_touching_output(
            "embedded-conflicting-runtime",
            "-Clink-arg=-Wl,/other/libobf_runtime.a",
        )
        self.reject_without_touching_output(
            "plural-link-args",
            "-Clink-args=-Wl,--as-needed",
        )
        response_side_output = self.work / "response-side-output.ll"
        response_side_output.write_text("side sentinel\n", encoding="utf-8")
        response_file = self.work / "rustc-arguments.rsp"
        response_file.write_text(
            f"--emit=llvm-ir={response_side_output}\n",
            encoding="utf-8",
        )
        self.reject_without_touching_output("response-file", f"@{response_file}")
        require(
            response_side_output.read_text(encoding="utf-8") == "side sentinel\n",
            "response-file rejection changed a hidden output",
        )
        map_output = self.work / "linker.map"
        map_output.write_text("map sentinel\n", encoding="utf-8")
        self.reject_without_touching_output(
            "linker-map-output",
            f"-Clink-arg=-Wl,-Map,{map_output}",
        )
        require(
            map_output.read_text(encoding="utf-8") == "map sentinel\n",
            "linker map rejection changed the sidecar",
        )
        self.reject_without_touching_output("save-temps", "-Csave-temps")

        stable_output = self.work / "stable.out"
        stable_output.write_text("sentinel\n", encoding="utf-8")
        completed, rows = self.invoke(
            "stable-preflight",
            self.active_direct_arguments("-o", str(stable_output)),
            environment={"OBF_RUSTC_FAKE_RELEASE": "1.99.0"},
            expected_status=2,
        )
        self.require_wrapper_error("stable-preflight", completed)
        require(len(rows) == 1 and rows[0]["args"] == ["-vV"], "stable preflight ran child")
        require(stable_output.read_text(encoding="utf-8") == "sentinel\n", "stable check changed output")

        completed, rows = self.invoke(
            "llvm-minor-mismatch",
            self.active_direct_arguments(),
            environment={"OBF_RUSTC_FAKE_LLVM": self.mismatched_llvm},
            expected_status=2,
        )
        self.require_wrapper_error("llvm-minor-mismatch", completed)
        require(
            len(rows) == 1 and rows[0]["args"] == ["-vV"],
            "LLVM minor mismatch ran child",
        )

        completed, rows = self.invoke(
            "llvm-major-mismatch",
            self.active_direct_arguments(),
            environment={"OBF_RUSTC_FAKE_LLVM": self.mismatched_llvm_major},
            expected_status=2,
        )
        self.require_wrapper_error("llvm-major-mismatch", completed)
        require(
            len(rows) == 1 and rows[0]["args"] == ["-vV"],
            "LLVM major mismatch ran child",
        )

        _, rows = self.invoke(
            "preflight-child-status",
            self.active_direct_arguments(),
            environment={"OBF_RUSTC_FAKE_PROBE_STATUS": "41"},
            expected_status=41,
        )
        require(
            len(rows) == 1 and rows[0]["args"] == ["-vV"],
            "preflight child status reached final compiler",
        )

        completed, rows = self.invoke(
            "enable-needs-config",
            [f"--rustc={self.rustc}", "--obf-enable", "--version"],
            expected_status=2,
        )
        self.require_wrapper_error("enable-needs-config", completed)
        require(rows == [], "--obf-enable without config reached child")

        completed, rows = self.invoke(
            "generic-config",
            [
                f"--rustc={self.rustc}",
                f"--obf-config={self.generic_config}",
                "--crate-type=bin",
                "--emit=llvm-ir",
                str(self.source),
            ],
            expected_status=2,
        )
        self.require_wrapper_error("generic-config", completed)
        require(rows == [], "generic config reached fake rustc")

        completed, rows = self.invoke(
            "multiple-config-documents",
            [
                f"--rustc={self.rustc}",
                f"--obf-config={self.multiple_config}",
                "--crate-type=bin",
                "--emit=llvm-ir",
                str(self.source),
            ],
            expected_status=2,
        )
        self.require_wrapper_error("multiple-config-documents", completed)
        require(rows == [], "multiple config documents reached fake rustc")

        _, rows = self.invoke(
            "quoted-frontend-config",
            [
                f"--rustc={self.rustc}",
                f"--obf-config={self.quoted_config}",
                "--crate-type=bin",
                "--emit=llvm-ir",
                "-o",
                str(self.work / "quoted-frontend.ll"),
                str(self.source),
            ],
        )
        self.assert_active_injection(
            "quoted-frontend-config",
            self.final_row("quoted-frontend-config", rows),
            link=False,
            config=self.quoted_config,
        )

        _, rows = self.invoke(
            "flow-frontend-config",
            [
                f"--rustc={self.rustc}",
                f"--obf-config={self.flow_config}",
                "--crate-type=bin",
                "--emit=llvm-ir",
                "-o",
                str(self.work / "flow-frontend.ll"),
                str(self.source),
            ],
        )
        self.assert_active_injection(
            "flow-frontend-config",
            self.final_row("flow-frontend-config", rows),
            link=False,
            config=self.flow_config,
        )

        failed_output = self.work / "active-child-status.ll"
        failed_output.write_text("sentinel\n", encoding="utf-8")
        _, rows = self.invoke(
            "active-child-status",
            self.active_direct_arguments(
                "--emit=llvm-ir", "-o", str(failed_output)
            ),
            environment={"OBF_RUSTC_FAKE_STATUS": "37"},
            expected_status=37,
        )
        self.final_row("active-child-status", rows)
        require(
            failed_output.read_text(encoding="utf-8") == "sentinel\n",
            "failed active child replaced the existing direct output",
        )
        require(
            not list(self.work.glob(".active-child-status.ll.obf-rustc-*")),
            "failed active child leaked a staged output",
        )

        if os.name == "posix":
            term = int(signal.SIGTERM)
            signal_output = self.work / "active-direct.out"
            signal_output.write_text("signal sentinel\n", encoding="utf-8")
            _, rows = self.invoke(
                "preflight-child-signal",
                self.active_direct_arguments(),
                environment={"OBF_RUSTC_FAKE_PROBE_SIGNAL": str(term)},
                expected_status=-term,
            )
            require(
                len(rows) == 1 and rows[0]["args"] == ["-vV"],
                "preflight signal reached final compiler",
            )

            _, rows = self.invoke(
                "active-child-signal",
                self.active_direct_arguments("--emit=llvm-ir"),
                environment={"OBF_RUSTC_FAKE_SIGNAL": str(term)},
                expected_status=-term,
            )
            self.final_row("active-child-signal", rows)
            require(
                signal_output.read_text(encoding="utf-8") == "signal sentinel\n",
                "signaled active child replaced the direct output",
            )
            require(
                not list(self.work.glob(".active-direct.out.obf-rustc-*")),
                "signaled active child leaked a staged output",
            )

            signal_marker = self.work / "forwarded-signal"
            signal_marker.unlink(missing_ok=True)
            descendant_marker = self.work / "forwarded-descendant-signal"
            descendant_marker.unlink(missing_ok=True)
            descendant_marker.with_suffix(
                descendant_marker.suffix + ".ready"
            ).unlink(missing_ok=True)
            _, rows = self.invoke(
                "active-parent-signal",
                self.active_direct_arguments("--emit=llvm-ir"),
                environment={
                    "OBF_RUSTC_FAKE_PARENT_SIGNAL": str(term),
                    "OBF_RUSTC_FAKE_SIGNAL_MARKER": str(signal_marker),
                    "OBF_RUSTC_FAKE_DESCENDANT_MARKER": str(descendant_marker),
                },
                expected_status=-term,
            )
            self.final_row("active-parent-signal", rows)
            require(
                signal_marker.read_text(encoding="utf-8").strip() == str(term),
                "wrapper did not forward its terminal signal to rustc",
            )
            deadline = time.monotonic() + 2
            while not descendant_marker.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            require(
                descendant_marker.read_text(encoding="utf-8").strip() == str(term),
                "wrapper did not forward its terminal signal to the rustc process group",
            )
            require(
                signal_output.read_text(encoding="utf-8") == "signal sentinel\n",
                "parent signal replaced the direct output before commit",
            )
            require(
                not list(self.work.glob(".active-direct.out.obf-rustc-*")),
                "parent signal leaked a staged output",
            )

        manifest = self.work / "cargo-package"
        main_root = manifest / "src" / "main.rs"
        lib_root = manifest / "src" / "lib.rs"
        example_root = manifest / "examples" / "same_name.rs"
        cdylib_root = manifest / "src" / "component.rs"
        suffixless_root = manifest / "src" / "entry"
        for path in (main_root, lib_root, example_root, cdylib_root, suffixless_root):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fn main() {}\n", encoding="utf-8")
        cargo_env = self.cargo_environment(main_root)

        passive_cargo_env = {
            "OBF_CONFIG": str(self.config),
            "CARGO_MANIFEST_DIR": str(manifest),
        }
        _, rows = self.invoke(
            "cargo-metadata-pass-through",
            [str(self.rustc), "--emit=metadata,dep-info", str(main_root)],
            environment=passive_cargo_env,
        )
        require(
            len(rows) == 1
            and rows[0]["args"] == ["--emit=metadata,dep-info", str(main_root)],
            "Cargo metadata-only invocation was changed or required selectors",
        )

        query, rows = self.invoke(
            "cargo-query-pass-through",
            [str(self.rustc), "--version"],
            environment=passive_cargo_env,
        )
        require("FAKE-QUERY-SENTINEL" in query.stdout, "Cargo query lost child output")
        require(rows == [{"args": ["--version"], "obf_config": str(self.config)}], "Cargo query was changed")

        _, rows = self.invoke(
            "cargo-root-mismatch",
            self.cargo_arguments(example_root),
            environment=cargo_env,
        )
        require(len(rows) == 1, f"cargo root mismatch did not pass through: {rows!r}")
        row = rows[0]
        require(row["args"] == self.cargo_arguments(example_root)[1:], "cargo root mismatch changed argv")
        require(not rust_settings(row["args"], "Z", "llvm-plugins"), "root mismatch injected plugin")
        require(not rust_settings(row["args"], "C", "codegen-units"), "root mismatch injected codegen units")
        require(not rust_settings(row["args"], "C", "link-arg"), "root mismatch injected runtime")

        _, rows = self.invoke(
            "cargo-library-mismatch",
            self.cargo_arguments(lib_root, "lib"),
            environment=cargo_env,
        )
        require(len(rows) == 1, "cargo lib mismatch did not pass through")
        require(not rust_settings(rows[0]["args"], "Z", "llvm-plugins"), "lib mismatch injected plugin")

        _, rows = self.invoke(
            "cargo-type-mismatch",
            self.cargo_arguments(main_root, "lib"),
            environment=cargo_env,
        )
        require(len(rows) == 1, "cargo type mismatch did not pass through")
        require(
            not rust_settings(rows[0]["args"], "Z", "llvm-plugins"),
            "type mismatch injected plugin",
        )

        name_mismatch_args = self.cargo_arguments(main_root)
        name_mismatch_args[2] = "different_name"
        _, rows = self.invoke(
            "cargo-name-mismatch",
            name_mismatch_args,
            environment=cargo_env,
        )
        require(len(rows) == 1, "cargo name mismatch did not pass through")
        require(
            not rust_settings(rows[0]["args"], "Z", "llvm-plugins"),
            "name mismatch injected plugin",
        )

        _, rows = self.invoke(
            "cargo-owner",
            self.cargo_arguments(main_root),
            environment=cargo_env,
        )
        self.assert_active_injection("cargo-owner", self.final_row("cargo-owner", rows))

        _, rows = self.invoke(
            "cargo-test-owner",
            [*self.cargo_arguments(main_root), "--test"],
            environment=cargo_env,
        )
        self.assert_active_injection(
            "cargo-test-owner", self.final_row("cargo-test-owner", rows)
        )

        cdylib_env = dict(cargo_env)
        cdylib_env["OBF_RUST_CRATE_TYPE"] = "cdylib"
        cdylib_env["OBF_RUST_CRATE_ROOT"] = str(cdylib_root)
        _, rows = self.invoke(
            "cargo-cdylib-owner",
            self.cargo_arguments(cdylib_root, "cdylib"),
            environment=cdylib_env,
        )
        self.assert_active_injection(
            "cargo-cdylib-owner", self.final_row("cargo-cdylib-owner", rows)
        )

        suffixless_env = dict(cargo_env)
        suffixless_env["OBF_RUST_CRATE_ROOT"] = str(suffixless_root)
        _, rows = self.invoke(
            "cargo-suffixless-owner",
            self.cargo_arguments(suffixless_root),
            environment=suffixless_env,
        )
        self.assert_active_injection(
            "cargo-suffixless-owner",
            self.final_row("cargo-suffixless-owner", rows),
        )

        missing_root_env = dict(cargo_env)
        missing_root_env.pop("OBF_RUST_CRATE_ROOT")
        completed, rows = self.invoke(
            "cargo-incomplete-selector",
            self.cargo_arguments(main_root),
            environment=missing_root_env,
            expected_status=2,
        )
        self.require_wrapper_error("cargo-incomplete-selector", completed)
        require(rows == [], "incomplete selector reached fake rustc")

        nonnormalized_name_env = dict(cargo_env)
        nonnormalized_name_env["OBF_RUST_CRATE_NAME"] = "same-name"
        completed, rows = self.invoke(
            "cargo-nonnormalized-name",
            self.cargo_arguments(main_root),
            environment=nonnormalized_name_env,
            expected_status=2,
        )
        self.require_wrapper_error("cargo-nonnormalized-name", completed)
        require(rows == [], "nonnormalized selector reached fake rustc")

        completed, rows = self.invoke(
            "cargo-ambiguous-selector",
            [*self.cargo_arguments(main_root), str(example_root)],
            environment=cargo_env,
            expected_status=2,
        )
        self.require_wrapper_error("cargo-ambiguous-selector", completed)
        require(rows == [], "ambiguous selector reached fake rustc")

        outer_env = dict(cargo_env)
        outer_env["RUSTC_WRAPPER"] = str(self.wrapper)
        completed, rows = self.invoke(
            "cargo-outer-wrapper",
            self.cargo_arguments(main_root),
            environment=outer_env,
            expected_status=2,
        )
        self.require_wrapper_error("cargo-outer-wrapper", completed)
        require(rows == [], "outer-wrapper misuse reached fake rustc")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wrapper", required=True)
    parser.add_argument("--fake", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--generic-config", required=True)
    parser.add_argument("--plugin", required=True)
    parser.add_argument("--runtime", required=True)
    parser.add_argument("--workdir", required=True)
    return parser.parse_args()


def main() -> int:
    try:
        wrapper_matrix(parse_arguments()).run()
    except matrix_failure as error:
        print(f"obf-rustc fake matrix failed: {error}", file=sys.stderr)
        return 1
    print("obf-rustc fake matrix passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
