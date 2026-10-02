# Benchmarks

This directory contains the benchmark corpus for:

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

The four core targets require a loadable pass plugin.
CMake adds optional language targets when their toolchain checks pass:

- Rust requires Cargo and a nightly or development `rustc` with matching LLVM major and minor versions.
  Windows also requires a plugin bound to the Rust LLVM host.
- Zig requires Zig 0.16.x on native Linux or Windows.
- TinyGo requires native Linux, TinyGo 0.41.x with embedded LLVM 20, and Go 1.23 through 1.26.
  The project LLVM package, `llc`, and LLD must use version 21.

See [frontend requirements](../docs/frontends.md) for setup and limits.

The `obf-re-harness` and `obf-seed-diversity` targets analyze only `license_demo`, `config_demo`, and `vm_workflow_demo`.

Build benchmark pairs with:

```sh
cmake --build build --parallel 3 --target obf-benchmarks
```

Run default-mode and benchmark-mode parity checks with:

```sh
cmake --build build --parallel 3 --target obf-benchmarks-e2e
```

This target checks normal-mode behavior and benchmark output for each baseline/protected pair.
The license checks also cover invalid inputs, not only baseline/protected parity.

In normal mode, `license_demo` grants only the exact token `delta-7` and returns status `0`.
Other tokens print `ACCESS DENIED` and return status `1`.
The runner checks both binaries against this contract, including the former `fdlta-7` collision.

For reproducible checkpoint work, configure a dedicated build with a fixed seed:

```sh
cmake -S . -B build-ghidra-check \
  -DLLVM_DIR="$(llvm-config --cmakedir)" \
  -DOBF_BENCHMARK_SEED=151616
cmake --build build-ghidra-check --parallel 3 --target obf-benchmarks
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
