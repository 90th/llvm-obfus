# llvm-obfus

make reverse engineers mass.

an out-of-tree LLVM pass plugin that selectively obfuscates your IR.
you pick the protection level, it does the rest.

> LLVM 21 · C++23 · New Pass Manager · Linux-first

---

## what it does

eight transforms, one policy engine, zero runtime dependencies (yet).

| pass | what happens |
|------|-------------|
| `obf-block-split` | chops basic blocks at seeded points |
| `obf-constant-encode` | XOR-encodes integer constants |
| `obf-string-encode` | encrypts string literals (lazy / ctor / inline-stack) |
| `obf-instruction-substitute` | replaces arithmetic with MBA identities |
| `obf-control-flatten` | switch-dispatch control flow flattening |
| `obf-opaque-preds` | injects always-true predicates into branches |
| `obf-bogus-cf` | adds fake paths guarded by opaque predicates |
| `obf-vm` | lowers functions to a micro-IR interpreter |

or just run `obf-safe-pipeline` and let the policy engine figure it out.

---

## build

```sh
cmake -S . -B build -DLLVM_DIR="$(llvm-config --cmakedir)"
cmake --build build
```

## use

```sh
# the full pipeline
opt -load-pass-plugin build/obf_plugin.so \
    --obf-config=config.yaml \
    -passes=obf-safe-pipeline -S input.ll -o output.ll

# just one pass
opt -load-pass-plugin build/obf_plugin.so \
    --obf-config=config.yaml \
    -passes=obf-vm -S input.ll -o output.ll

# analysis only — see what would happen
opt -load-pass-plugin build/obf_plugin.so \
    --obf-config=config.yaml \
    -passes=obf-feature-report -disable-output input.ll
```

## configure

drop a YAML file. that's it.

```yaml
seed: 1337
default_level: light

overrides:
  - name: hot_loop
    level: none          # leave performance-critical code alone

targets:
  - match: verify_*
    level: strong
  - match: license_check
    level: vm            # full virtualization

string_encoding:
  prefer_lazy_decode: true
  allow_ctor_fallback: true
```

five protection levels:

| level | you get |
|-------|---------|
| `none` | nothing. it's opt-out. |
| `light` | strings + constants + block split |
| `strong` | everything except VM |
| `vm` | virtualized into a bytecode interpreter |
| `strong_vm` | strong + VM |

policy precedence: **override > annotation > target rule > auto-analysis > default**

source annotations work too:

```c
__attribute__((annotate("obf:strong")))
int check_license(const char *key) { ... }
```

`strong_vm` is the loud one: strong classical transforms first, then VM.

## test

```sh
ctest                  # or: lit -sv build/tests
```

15 lit tests covering every pass with FileCheck + `lli` runtime verification.

## benchmarks

```sh
cmake --build build --target obf-benchmarks
```

builds baseline vs. obfuscated stripped binaries under `build/benchmarks/`.
open both in Ghidra. enjoy the difference.

---

## project layout

```
include/obf/         headers — clean C++ interfaces, no LLVM pass goo
lib/transforms/       the eight transforms
lib/vm/               micro-IR lowering + switch-dispatch emitter
lib/plugin/           pass registration and pipeline orchestration
lib/policy/           per-function protection decisions
lib/analysis/         feature extraction (complexity, loops, strings, …)
lib/frontend/         YAML config loader + annotation parser
lib/report/           JSON report generation
tests/lit/            lit tests + YAML configs
benchmarks/           corpus + configs for RE comparison
runtime/              (empty — future home of VM dispatch + string helpers)
```
