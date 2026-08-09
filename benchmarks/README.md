# Benchmarks

This directory will hold the benchmark corpus used for:

- baseline versus obfuscated comparisons
- overhead measurements
- decompiler and reverse engineering evaluation inputs

Current CMake corpus targets:

- `license_demo` from `corpus/license_demo.cpp`
- `config_demo` from `corpus/config_demo.c`
- `vm_workflow_demo` from `corpus/vm_workflow_demo.c`
- `wpo_demo` linked from `corpus/wpo_demo_main.c` and `corpus/wpo_demo_core.c`

Compatible optional language corpus targets:

- `rust_demo` from `corpus/rust_demo.rs`
- `zig_demo` from `corpus/zig_demo_component.zig` and `corpus/zig_demo_main.zig`
- `tinygo_demo` from `corpus/tinygo_demo.go`

The four C and C++ targets are always in the build corpus. CMake adds Rust with a nightly or development `rustc`, matching LLVM major/minor, and Cargo. CMake adds Zig with Zig 0.16.x on a native Linux host. CMake adds TinyGo with TinyGo 0.41.x, Go 1.23 through 1.26, LLVM 21 `llc`, and LLD on native Linux.

The `obf-re-harness` and `obf-seed-diversity` targets analyze only `license_demo`, `config_demo`, and `vm_workflow_demo`.

Build benchmark pairs with:

```sh
cmake --build build --target obf-benchmarks -- -j1
```

Run default-mode and benchmark-mode parity checks with:

```sh
cmake --build build --target obf-benchmarks-e2e -- -j1
```

This target runs each built baseline and obfuscated pair once in normal mode and once with `OBF_BENCH_ITERS` set.

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
- `<name>.obfuscated.cleaned.ll` when `OBF_BENCHMARK_CLEAN_IR=ON`

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
