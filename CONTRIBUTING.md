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

# Opt-in sequential benchmark, audit, and diversity checks
cmake --build build --target obf-benchmarks -- -j1
cmake --build build --target obf-benchmarks-e2e -- -j1
cmake --build build --target obf-audit-benchmarks -- -j1
cmake --build build --target obf-re-harness -- -j1
cmake --build build --target obf-seed-diversity -- -j1
```

`obf-benchmarks` builds the four core C and C++ corpus targets and adds the Rust, Zig, and TinyGo corpus targets when compatible toolchains are configured. `obf-benchmarks-e2e` then proves baseline versus obfuscated runtime parity for every built corpus benchmark. `obf-audit-benchmarks` audits every built benchmark pair. The current `obf-re-harness` and `obf-seed-diversity` checks intentionally stay scoped to `license_demo`, `config_demo`, and `vm_workflow_demo`. 
