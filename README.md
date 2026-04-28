# llvm-obfus

out-of-tree LLVM 21+ pass plugin for policy-driven IR obfuscation.

## why?

the project applies obfuscation per function instead of as one blanket pipeline. you can inspect policy decisions with `obf-feature-report`, run individual passes directly, or use `obf-safe-pipeline` to drive the current pass sequence.

## what it has

- `obf_plugin` for LLVM's new pass manager
- registered passes: `obf-feature-report`, `obf-entropy-init`, `obf-cfg-state-cleanup`, `obf-artifact-cleanup`, `obf-block-split`, `obf-split-scaffold`, `obf-string-encode`, `obf-vm`, `obf-constant-encode`, `obf-instruction-substitute`, `obf-opaque-gep`, `obf-function-outline`, `obf-control-flatten`, `obf-opaque-preds`, `obf-bogus-cf`, `obf-safe-pipeline`
- YAML config with `profile`, `seed`, `default_level`, `overrides`, `targets`, `block_split`, `string_encoding`, `constant_encoding`, `mba`, `security`, and `debug_preserve_generated_names`
- benchmark targets: `license_demo_bench`, `config_demo_bench`, `vm_workflow_demo_bench`, `wpo_demo_bench`
- a runtime entropy object generated from `runtime/entropy_anchor.c`

## layout

```text
include/obf/       public headers
lib/analysis/      function feature extraction
lib/frontend/      yaml config loading and annotation collection
lib/plugin/        pass registration and pipeline wiring
lib/policy/        policy selection
lib/report/        reporting
lib/transforms/    IR transforms
lib/vm/            VM lowering and dispatch pieces
runtime/           entropy anchor and runtime support code
tests/lit/         lit suite
benchmarks/        corpus, configs, and benchmark targets
tools/obf-driver/  driver scaffold
```

## building

- requires CMake `3.24+`, a C++23 compiler, LLVM `21+`, Python3, and `lit`
- CMake also expects `opt`, `clang`, `clang++`, `llvm-link`, `llc`, and `llvm-strip` from that LLVM install

```sh
cmake -S . -B build -DLLVM_DIR="$(llvm-config --cmakedir)"
cmake --build build
```

## usage

```sh
opt -load-pass-plugin build/obf_plugin.so \
  --obf-config=config.yaml \
  -passes=obf-feature-report \
  -disable-output input.ll

opt -load-pass-plugin build/obf_plugin.so \
  --obf-config=config.yaml \
  -passes=obf-safe-pipeline \
  -S input.ll -o output.ll

opt -load-pass-plugin build/obf_plugin.so \
  --obf-config=config.yaml \
  --obf-seed=20240601 \
  -passes=obf-vm \
  -S input.ll -o output.ll
```

## config

the loader accepts `profile`, `seed`, `default_level`, `overrides`, `targets`, `block_split`, `string_encoding`, `constant_encoding`, `mba`, `security`, and `debug_preserve_generated_names`.

protection levels are `none`, `light`, `strong`, `vm`, and `strong_vm`.

profiles are optional. if `profile` is omitted, legacy defaults are used. new configs should usually start with `profile: standard` and then add `targets` or `overrides` for the functions that need protection.

profile defaults are applied before explicit YAML sections, and `--obf-seed` still overrides the top-level `seed` after config loading:

```text
base defaults -> profile defaults -> explicit YAML sections -> --obf-seed
```

section-level overrides win as a unit. for example, if `profile: fortress` and an `mba:` section are both present, the explicit `mba:` section is used while other absent sections still come from the fortress profile.

available profiles:

- `fast`: quick iteration, low overhead
- `standard`: recommended default for normal use
- `guarded`: stronger protection for sensitive paths while staying practical
- `fortress`: strict high-value protection defaults
- `lab`: experimental/high-diversity stress defaults

profiles do not automatically promote every function to `strong_vm`. use `targets`, `overrides`, or annotations to choose which functions are protected. `strong_vm` invariants are always fail-closed regardless of profile and cannot be disabled by config.

```yaml
profile: standard
seed: 20240601
default_level: none

overrides:
  - name: classify_byte
    level: vm
  - name: route_score
    level: vm

block_split:
  max_splits_per_function: 1
  min_instructions_per_block: 2

string_encoding:
  min_string_length: 2
  max_strings_per_module: 64
  prefer_lazy_decode: true
  allow_ctor_fallback: true

constant_encoding:
  max_constants_per_function: 4
  min_bit_width: 8

mba:
  depth: 1
```

example high-value config:

```yaml
profile: fortress
targets:
  - match: "verify_*"
    level: strong_vm
  - match: "license_*"
    level: strong_vm
```

example lab config for one function:

```yaml
profile: lab
overrides:
  - name: verify_license
    level: strong_vm
```

## notes

- `tools/obf-driver` currently loads a config and prints a summary; it is not a full compile driver
- the build, tests, and benchmark flows use an extra object generated from `runtime/entropy_anchor.c`
- tests are wired through `ctest`; direct `lit -sv build/tests` works too
- `cmake --build build --target obf-benchmarks` writes benchmark artifacts under `build/benchmarks/`
- `cmake --build build --target obf-benchmarks-mir` also emits MIR for the linked benchmark
