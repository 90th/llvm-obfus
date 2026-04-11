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

Artifacts are written under `build/benchmarks/<name>/`:

- `<name>.baseline.ll`
- `<name>.obfuscated.ll`
- `<name>.baseline`
- `<name>.obfuscated`

The binary artifacts are stripped in place after linking so baseline versus obfuscated RE comparisons are not trivially biased by symbol names.
