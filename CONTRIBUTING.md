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
All modifications must preserve LLVM IR semantics, pass module verification, and retain deterministic seed diversity. 

Validate your changes locally before submitting:

```sh
# Configure the build
cmake -S . -B build -DLLVM_DIR="$(llvm-config --cmakedir)"

# Build and run the verification suite
cmake --build build --target obf-benchmarks obf-seed-diversity obf-unit-tests
ctest --test-dir build --output-on-failure -R "obf-lit|obf-unit-tests"
```
