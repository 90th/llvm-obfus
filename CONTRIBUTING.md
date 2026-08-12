# Contributing to llvm-obfus

## Toolchain Requirements
* **CMake**: 3.24+
* **Compiler**: Native C++23 support
* **LLVM**: 21+
* **Testing**: Python 3 and LLVM `lit`

## Coding Standards
* Run `clang-format -i` on your changes before opening a pull request.
* The repository enforces a customized Google C++ style via `.clang-format` (K&R braces, 2-space indentation, 100-column limit).

## Building & Testing
All modifications must preserve LLVM IR semantics and pass module verification. Deterministic seed diversity remains part of the heavier opt-in release sweep.

Validate your changes locally before submitting:

```sh
# Configure the build
cmake -S . -B build -DLLVM_DIR="$(llvm-config --cmakedir)"

# Fast contributor checks
cmake --build build --target obf-clang-wrappers obf-driver obf-unit-tests obf-runtime-atomic-tests -- -j1
ctest --test-dir build --output-on-failure -R "obf-lit|obf-unit-tests|obf-runtime-atomic-tests"

# Opt-in sequential benchmark, audit, recoverability, diversity, and multiseed checks
cmake --build build --target obf-benchmarks -- -j1
cmake --build build --target obf-benchmarks-e2e -- -j1
cmake --build build --target obf-audit-benchmarks -- -j1
cmake --build build --target obf-re-harness -- -j1
cmake --build build --target obf-re-harness-binary -- -j1
cmake --build build --target obf-re-harness-binary-seeds -- -j1
cmake --build build --target obf-seed-diversity -- -j1
```

`obf-benchmarks` builds the four core C and C++ corpus targets and adds the Rust, Zig, and TinyGo corpus targets when compatible toolchains are configured. `obf-benchmarks-e2e` then proves baseline versus obfuscated runtime parity for every built corpus benchmark. `obf-audit-benchmarks` audits every built benchmark pair. The current `obf-re-harness` and `obf-seed-diversity` checks intentionally stay scoped to `license_demo`, `config_demo`, and `vm_workflow_demo`.

`obf-re-harness-binary` is separate from the IR-only `obf-re-harness`. It measures the same three final stripped benchmark pairs and writes `build/re-harness/binary-recovery.json` plus `build/re-harness/binary-recovery-controls.json`. The controller requires `license_demo` and `vm_workflow_demo` to be exactly `vm_candidate`. It permits `config_demo` to be either `interpreter_like` or `vm_candidate`. Each multiseed result still requires an actual `vm_candidate` positive.

The binary target gives the analyzer only explicitly selected final stripped ELF64 little-endian x86-64 `ET_EXEC` or `ET_DYN` artifacts and `llvm-objdump`. The analyzer does not read source, IR, YAML, configuration, seed values, or benchmark labels. The controller keeps labels outside the analyzer boundary and runs the analyzer on opaque SHA-256 copies. Symbols and relocation metadata can appear under `metadata_exposure`, but their spellings never seed candidates or scores.

The binary reports measure automated structural recoverability from static binary evidence. They do not establish security or semantic recovery. The analyzer never executes an artifact. A `vm_candidate` requires a recurrent dispatcher with at least two selected targets and two reentering handlers. A direct dispatcher also requires at least two conditional selection blocks. At least two reentering handlers must update the same dispatcher-linked state. An exclusive non-pointer dynamic or mapped data read must link to that state through connected relationships. A switch, table, name, or entropy feature alone is insufficient. `semantic_recovery` is always `unavailable`. A classification cannot provide confidence beyond the observed static structure.
