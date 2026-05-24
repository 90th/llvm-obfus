# Benchmarks

This directory will hold the benchmark corpus used for:

- baseline versus obfuscated comparisons
- overhead measurements
- decompiler and reverse engineering evaluation inputs

Current corpus:

- `corpus/license_demo.cpp`
- `corpus/config_demo.c`
- `corpus/vm_workflow_demo.c`

Build benchmark pairs with:

```sh
cmake --build build --target obf-benchmarks
```

For reproducible checkpoint work, configure a dedicated build with a fixed seed:

```sh
cmake -S . -B build-ghidra-check \
  -DLLVM_DIR="$(llvm-config --cmakedir)" \
  -DOBF_BENCHMARK_SEED=151616
cmake --build build-ghidra-check --target obf-benchmarks -- -j1
```

Artifacts are written under `build/benchmarks/<name>/`:

- `<name>.baseline.ll`
- `<name>.obfuscated.ll`
- `<name>.baseline`
- `<name>.obfuscated`

The binary artifacts are stripped in place after linking so baseline versus obfuscated RE comparisons are not trivially biased by symbol names.

The effective benchmark seed is printed during CMake configure. When `OBF_BENCHMARK_SEED` is empty, CMake generates a non-zero decimal seed for that build tree.

Measure authenticated string decode overhead with:

```sh
python tools/obf-bench/measure_string_auth_overhead.py --build-dir build
```

The runner writes temporary IR, configs, and binaries under `build/string-auth-bench/` and reports:

- lazy first-decode cost
- lazy steady-state helper cost
- ctor startup wall-time impact
