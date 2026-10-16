"""Install, relocate, and exercise a standalone C/C++ toolchain prefix."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def require(condition, message):
    if not condition:
        raise AssertionError(message)


class Harness:
    def __init__(self, args):
        self.args = args
        self.root = Path(tempfile.mkdtemp(prefix="obf-install-", dir=args.work)).resolve()
        self.commands = self.root / "commands.jsonl"
        self.env = os.environ.copy()
        for name in tuple(self.env):
            if name.startswith("OBF_"):
                del self.env[name]
        # Never obtain a compiler or DLL from a repository toolchain on PATH.
        roots = [str(path.resolve()).lower() for path in args.forbid_root]
        self.env["PATH"] = os.pathsep.join(
            path for path in self.env.get("PATH", "").split(os.pathsep)
            if path and not any(path.lower().startswith(root) for root in roots))
        self.env.update(TEMP=str(self.root), TMP=str(self.root), TMPDIR=str(self.root),
                        PYTHONPYCACHEPREFIX=str(self.root / "pycache"))
        self.source = self.root / "external project"
        shutil.copytree(args.consumer_template, self.source)
        self.sandbox = []
        if os.name != "nt" and shutil.which("bwrap") and args.forbid_root:
            probe = self.run(["bwrap", "--ro-bind", "/", "/", "--", "/usr/bin/true"],
                             expected=None)
            if probe.returncode == 0:
                self.sandbox = ["bwrap", "--bind", "/", "/", "--dev-bind", "/dev", "/dev"]
                for path in args.forbid_root:
                    self.sandbox += ["--tmpfs", str(path.resolve())]
                self.sandbox += ["--chdir", str(self.root), "--"]
                for root in args.forbid_root:
                    for name in ("CMakeLists.txt", "CMakeCache.txt"):
                        witness = root.resolve() / name
                        if witness.is_file():
                            self.run(["/usr/bin/test", "!", "-e", witness], sandbox=True)
        self.rows = []

    def run(self, command, *, env=None, expected=0, sandbox=False):
        command = [str(part) for part in command]
        if sandbox:
            command = self.sandbox + command
        completed = subprocess.run(command, cwd=self.root, env=env or self.env,
                                   capture_output=True, text=True, errors="replace",
                                   timeout=300)
        with self.commands.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(dict(command=command, exit=completed.returncode,
                                         stdout=completed.stdout, stderr=completed.stderr)) + "\n")
        if expected is not None:
            require(completed.returncode == expected,
                    f"command failed ({completed.returncode}): {command}\n"
                    f"{completed.stdout}\n{completed.stderr}")
        return completed

    def layout(self, prefix):
        bindir = prefix / self.args.bindir
        libdir = prefix / self.args.libdir
        includedir = prefix / self.args.includedir
        suffix = ".exe" if os.name == "nt" else ""
        plugin = libdir / ("obf_clang_plugin.dll" if os.name == "nt" else "obf_plugin.so")
        runtime = libdir / ("obf_runtime.lib" if os.name == "nt" else "libobf_runtime.a")
        files = [bindir / name for name in ("obf-clang", "obf-clang++", "obf-opt")]
        files += [bindir / (name + suffix) for name in
                  ("obf-driver", "obf-native-link", "obf-checksum-bind", "clang", "opt")]
        files += [plugin, runtime, includedir / "obf/string_copy.h",
                  includedir / "obf/support/runtime_atomic.h",
                  includedir / "obf/support/runtime_abi_generated.h"]
        if os.name == "nt":
            files += [libdir / "obf_plugin.dll"]
            files += [bindir / (name + ".cmd") for name in ("obf-clang", "obf-clang++", "obf-opt")]
        else:
            files += [bindir / "clang++"]
        require(all(path.is_file() for path in files), f"incomplete installed layout: {files}")
        require(not list(includedir.rglob("*.in")), "header templates were installed")
        return bindir, plugin, runtime

    def scan(self, prefix):
        patterns = set()
        for root in self.args.forbid_root:
            for text in (str(root.resolve()), str(root.resolve()).replace("\\", "/"),
                         str(root.resolve()).replace("/", "\\")):
                patterns.add(text.encode().lower())
                patterns.add(text.encode("utf-16le").lower())
        longest = max(map(len, patterns), default=1)
        count = 0
        for path in prefix.rglob("*"):
            if path.is_symlink():
                require(not Path(os.readlink(path)).is_absolute(), f"absolute installed symlink: {path}")
                require(path.resolve().is_relative_to(prefix.resolve()), f"escaping installed symlink: {path}")
            if not path.is_file():
                continue
            count += 1
            with path.open("rb") as stream:
                previous = b""
                while chunk := stream.read(1024 * 1024):
                    data = (previous + chunk).lower()
                    require(not any(pattern in data for pattern in patterns),
                            f"source/build path remains in installed artifact: {path}")
                    previous = data[-longest:]
        return count

    def ledger(self, path):
        report = json.loads(path.read_text(encoding="utf-8"))
        require(report["capture"] == "enabled", "compiler ledger was not captured")
        for owner, level in (("package_copy_v1", "strong_vm"), ("package_mix", "vm")):
            selected = [event["policy"] for event in report["requested_policy"]
                        if event["owner"] == owner and event["phase"] == "selected"]
            require(len(selected) == 1 and selected[0]["level"] == level,
                    f"installed compiler changed the requested policy for {owner}")
            for stage, status in (("admission", "admitted"), ("emission", "emitted")):
                require(any(event["owner"] == owner and event["mechanism"] == "vm" and
                            event["scope"] == "whole_function" and event["status"] == status and
                            (stage != "emission" or event["count"] > 0) for event in report[stage]),
                        f"installed compiler omitted {status} VM for {owner}")
        bindings = []
        for stage, status in (("emission", "generated"), ("emission", "bound"),
                              ("finalization", "validated")):
            events = [event for event in report[stage] if event["owner"] == "package_copy_v1" and
                      event["mechanism"] == "string_copy_export" and event["status"] == status]
            binding = re.search(r"(?:^|, )id=(\d+)(?:,|$)", events[0]["reason"]) if len(events) == 1 else None
            require(binding is not None and int(binding.group(1)) == 1 and events[0]["count"] == 1,
                    "installed export lost its source binding")
            bindings.append(events[0]["target"])
        require(len(set(bindings)) == 1, "installed export source identity changed")
        require(any(role["owner"] == "package_copy_v1" and role["role"] == "string_decoder" and
                    "authenticated_string_decode" in role["obligations"] for role in report["roles"]),
                "installed export lacks its authenticated decoder")
        require(any(event["mechanism"] == "security_gates" and event["status"] == "validated"
                    for event in report["finalization"]), "installed compiler omitted final security validation")

    def consume(self, prefix, name, overrides=None):
        bindir, plugin, runtime = self.layout(prefix)
        env = self.env.copy()
        env.update(overrides or {})
        if os.name != "nt":
            env["LD_DEBUG"] = "libs,files"
            env["LD_DEBUG_OUTPUT"] = str(self.root / (name + "-loader"))
        launcher = ".cmd" if os.name == "nt" else ""
        build = self.root / (name + " build")
        raw_compiler = bindir / ("clang.exe" if os.name == "nt" else "clang")
        driver = self.run([raw_compiler, "--version"], env=env, sandbox=True)
        version = re.search(r"(?:clang|LLVM) version ([0-9]+(?:\.[0-9]+)+)", driver.stdout + driver.stderr)
        require(version is not None, "installed compiler did not report its LLVM version")
        for selector in ("-cc1", "-cc1as"):
            integrated = self.run([raw_compiler, selector, "-version"], env=env, sandbox=True)
            selected = re.search(r"(?:clang|LLVM) version ([0-9]+(?:\.[0-9]+)+)",
                                 integrated.stdout + integrated.stderr)
            require(selected is not None and selected.group(1) == version.group(1),
                    f"installed compiler changed {selector} dispatch or LLVM identity")
        self.run([self.args.cmake, "-S", self.source, "-B", build, "-G", "Ninja",
                  f"-DCMAKE_C_COMPILER={bindir / ('obf-clang' + launcher)}",
                  f"-DCMAKE_CXX_COMPILER={bindir / ('obf-clang++' + launcher)}",
                  "-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_C_FLAGS=-v -H",
                  "-DCMAKE_CXX_FLAGS=-v -H"], env=env, sandbox=True)
        self.run([self.args.cmake, "--build", build, "--parallel", "3", "--verbose"],
                 env=env, sandbox=True)
        outputs = []
        for language, text in (("c", "C"), ("cpp", "C++")):
            image = build / ("consumer_" + language + (".exe" if os.name == "nt" else ""))
            result = self.run([image], sandbox=True)
            require(result.stdout.strip() == f"{text}: installed authenticated payload mix=687925",
                    f"incorrect installed {text} consumer output: {result.stdout!r}")
            self.ledger(build / (language + "-coverage.json"))
            outputs.append(result.stdout.strip())
        dry = self.run([bindir / ("obf-clang" + launcher), "-###", self.source / "consumer.c",
                        "-o", self.root / "dry-output"], env=env, sandbox=True)
        expected_plugin = env.get("OBF_PLUGIN", str(plugin))
        expected_runtime = env.get("OBF_RUNTIME", str(runtime))
        # Driver traces may escape native Windows separators in quoted operands.
        trace = (dry.stdout + dry.stderr).replace("\\\\", "/").replace("\\", "/")
        require(expected_plugin.replace("\\", "/") in trace and
                expected_runtime.replace("\\", "/") in trace,
                "compiler trace does not use the selected installed plugin/runtime")
        self.rows.append(dict(name=name, prefix=str(prefix), outputs=outputs,
                              plugin=expected_plugin, runtime=expected_runtime))
        if os.name != "nt":
            initialized = []
            for log in self.root.glob(name + "-loader.*"):
                for line in log.read_text(errors="replace").splitlines():
                    if "calling init:" in line and ("libLLVM" in line or "libclang" in line):
                        require(str(prefix) in line, f"LLVM dependency escaped installed prefix: {line}")
                        initialized.append(line.split("calling init:", 1)[1].strip())
            if list((prefix / self.args.libdir).glob("*LLVM*.so*")):
                require(initialized, "loader trace did not observe the packaged LLVM libraries")
            self.rows[-1]["initialized_llvm_libraries"] = sorted(set(initialized))

    def override_errors(self, prefix):
        bindir, _, _ = self.layout(prefix)
        wrapper = bindir / ("obf-clang.cmd" if os.name == "nt" else "obf-clang")
        cases = []
        for variable in ("OBF_PLUGIN", "OBF_RUNTIME"):
            for value in (str(self.root / "absent override"), ""):
                env = self.env.copy()
                env[variable] = value
                result = self.run([wrapper, self.source / "consumer.c", "-o", self.root / "rejected"],
                                  env=env, expected=None, sandbox=True)
                diagnostic = "missing pass plugin" if variable == "OBF_PLUGIN" else "missing runtime archive"
                require(result.returncode != 0 and diagnostic in result.stderr,
                        f"explicit {variable} silently fell back to its installed default")
                require(not (self.root / "rejected").exists(), "rejected override produced an executable")
                cases.append(dict(variable=variable, value=value, rejected=True))
        return cases

    def execute(self):
        archive = None
        if self.args.build:
            if self.args.package:
                packages = self.root / "packages"
                self.run([self.args.cpack, "--config", self.args.build / "CPackConfig.cmake",
                          "-B", packages, "-C", "Release"])
                archives = [*packages.glob("*.tar.gz"), *packages.glob("*.zip")]
                require(len(archives) == 1, "CPack did not produce one native TGZ or ZIP archive")
                archive = archives[0]
                self.run([self.args.cmake, "-E", "tar", "xf", archive])
                candidates = [path for path in self.root.iterdir() if path.is_dir() and
                              (path / self.args.bindir / "obf-clang").is_file()]
                require(len(candidates) == 1, "archive does not contain one standalone prefix")
                prefix = candidates[0]
            elif os.name == "nt":
                prefix = self.root / "installed prefix"
                self.run([self.args.cmake, "--install", self.args.build, "--prefix", prefix,
                          "--config", "Release"])
            else:
                env = self.env.copy()
                env["DESTDIR"] = str(self.root / "stage")
                logical = Path("/llvm-obfus installed prefix")
                self.run([self.args.cmake, "--install", self.args.build, "--prefix", logical,
                          "--config", "Release"], env=env)
                prefix = Path(env["DESTDIR"]) / logical.relative_to("/")
            if not self.args.package:
                manifest = (self.args.build / "install_manifest.txt").read_text(encoding="utf-8")
                (self.root / "install_manifest.txt").write_text(manifest, encoding="utf-8")
                require("obf-clang" in manifest and "runtime_abi_generated.h" in manifest,
                        "install manifest omits required components")
        else:
            require(self.args.prefix is not None, "provide --build or --prefix")
            prefix = self.root / "copied prefix"
            shutil.copytree(self.args.prefix.resolve(), prefix, symlinks=True)
        file_count = self.scan(prefix)
        self.consume(prefix, "default")
        negatives = self.override_errors(prefix)
        _, plugin, runtime = self.layout(prefix)
        alternate = self.root / "explicit override files"
        alternate.mkdir()
        alt_plugin, alt_runtime = alternate / plugin.name, alternate / runtime.name
        shutil.copy2(plugin, alt_plugin)
        shutil.copy2(runtime, alt_runtime)
        # Defaults remain present. Positive and invalid overrides must both take precedence.
        self.consume(prefix, "overrides", dict(OBF_PLUGIN=str(alt_plugin), OBF_RUNTIME=str(alt_runtime)))
        moved = self.root / "relocated prefix with spaces"
        prefix.rename(moved)
        require(not prefix.exists(), "original prefix still exists after relocation")
        self.scan(moved)
        self.consume(moved, "relocated")
        result = dict(status="passed", prefix=str(moved), installed_files=file_count,
                      filesystem_sandbox=bool(self.sandbox), consumers=self.rows,
                      override_rejections=negatives, commands=str(self.commands),
                      archive=str(archive) if archive else None,
                      forbidden_roots=[str(path) for path in self.args.forbid_root])
        (self.root / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"INSTALL_CONSUMER_PASS result={self.root / 'result.json'}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path)
    parser.add_argument("--prefix", type=Path)
    parser.add_argument("--work", type=Path)
    parser.add_argument("--cmake", default="cmake")
    parser.add_argument("--cpack", default="cpack")
    parser.add_argument("--package", action="store_true", help="build and consume the CPack archive")
    parser.add_argument("--bindir", default="bin")
    parser.add_argument("--libdir", default="lib")
    parser.add_argument("--includedir", default="include")
    parser.add_argument("--forbid-root", type=Path, action="append", default=[])
    parser.add_argument("--consumer-template", type=Path,
                        default=Path(__file__).resolve().parent / "install-consumer")
    args = parser.parse_args()
    if args.work:
        args.work.mkdir(parents=True, exist_ok=True)
    harness = Harness(args)
    print(f"INSTALL_CONSUMER_WORK {harness.root}", flush=True)
    harness.execute()


if __name__ == "__main__":
    main()
