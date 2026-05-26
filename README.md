# llvm-obfus

`llvm-obfus` is an out-of-tree LLVM 21+ pass plugin for policy-driven IR obfuscation.

The project applies native LLVM IR transforms to selected functions. The main production entry point is `obf-safe-pipeline`, which composes virtualization, structural rewrites, string and constant protection, late indirect dispatch, and final artifact cleanup.

The design goal is simple: make static recovery materially harder while staying inside normal LLVM semantics. The project does not rely on malformed objects, inline-asm traps, EH spoofing, or target-specific parser breaks.

## Main Features

### Strong Virtualization And MBA Flattening

- Protection levels are `none`, `light`, `strong`, `vm`, and `strong_vm`.
- `vm` and `strong_vm` lower selected functions into VM-backed execution paths.
- `strong_vm` implementation bodies continue through later hardening stages, not just the public wrapper.
- MBA rewriting is used both directly and as part of other transforms such as constant reconstruction.

### Cryptographic Indirect Dispatch

- `indirect_dispatch` is a late pass in the safe pipeline.
- It rewrites supported conditional branches and switch dispatch sites into keyed `blockaddress` plus arithmetic plus `indirectbr` sequences.
- The implementation reconstructs targets from same-function deltas in SSA instead of emitting absolute dispatch tables in globals.
- Unsupported shapes are skipped conservatively: EH personalities, EH pads, `invoke`, `callbr`, existing `indirectbr`, `catchswitch`, `catchreturn`, `cleanupreturn`, `resume`, `musttail`, and non-integral program address spaces.

### Authenticated Runtime Strings

- String encoding is configured under `string_encoding`.
- `authenticated_mode` enables authenticated runtime decode.
- The runtime support lives in `runtime/string_auth_runtime.c` and handles authenticated string and constant-pool recovery.
- Lazy decode, eager decode, constructor fallback, and forwarded-pointer cases are handled in the transform.

### Constant Pooling

- Constant encoding modes are `off`, `mba_inline`, `keyed_pool`, `auto`, and `all`.
- `mba_inline` reconstructs constants directly in IR.
- `keyed_pool` moves constants into authenticated pools recovered at use sites.
- `auto` chooses a strategy per use site.

### Stealth ABI And Artifact Cleanup

- Public runtime ABI names are generated at build time in `build/include/obf/support/runtime_abi_generated.h`.
- The default public prefix is `rt_core_`.
- Final cleanup strips marker attributes, removes annotation metadata, anonymizes local/internal obfuscation artifacts, and strips local SSA names.
- Security gates can fail the build on leaked public `obf` symbols.

## Architecture

### Frontend

- YAML loading and config parsing live in `lib/frontend/`.
- Profiles are `fast`, `standard`, `guarded`, `fortress`, and `lab`.
- Profile defaults are applied first; explicit top-level YAML sections override them; `--obf-seed` overrides the final seed after config loading.

### Analysis And Policy

- Per-function feature extraction lives in `lib/analysis/`.
- Policy selection lives in `lib/policy/`.
- The pipeline is function-selective rather than blanket-on for the whole module.

### Transforms

- Core transforms live in `lib/transforms/`.
- VM lowering lives in `lib/vm/`.
- Pass registration and safe-pipeline orchestration live in `lib/plugin/`.

### Runtime

- `runtime/entropy_anchor.c` provides the entropy anchor support object used by builds and tests.
- `runtime/string_auth_runtime.c` provides authenticated decode support for strings and constant pools.

## Safe Pipeline Order

`obf-safe-pipeline` is the integrated pipeline used by the benchmarks and lit coverage. Its current high-level order is:

1. entropy initialization
2. VM lowering and call rewriting for `vm`
3. VM lowering and call rewriting for `strong_vm`
4. post-VM string encoding
5. constant encoding
6. opaque GEP
7. instruction substitution
8. opaque predicates
9. control flattening
10. function outlining
11. bogus control flow
12. block splitting
13. additional hardening on `strong_vm` implementation functions
14. CFG state cleanup
15. indirect dispatch
16. security gate enforcement
17. artifact cleanup

The late ordering matters. Indirect dispatch runs after the major structural passes so it can rewrite the final dispatch-heavy CFG shapes, including VM implementation functions.

## Configuration

Top-level sections currently supported by the loader:

- `profile`
- `seed`
- `default_level`
- `overrides`
- `targets`
- `block_split`
- `string_encoding`
- `constant_encoding`
- `mba`
- `indirect_dispatch`
- `security`
- `debug_preserve_generated_names`

`overrides` entries match exact function names; `targets` entries support glob-style wildcard patterns (e.g., `"verify_*"`).

### Profile Defaults

| Setting | `fast` | `standard` | `guarded` | `fortress` | `lab` |
|---|---|---|---|---|---|
| `mba.depth` | 1 | 1 | 2 | 3 | 4 |
| `block_split.max_splits_per_function` | 1 | 1 | 2 | 4 | 8 |
| `string_encoding.min_string_length` | 3 | 2 | 2 | 1 | 1 |
| `string_encoding.max_strings_per_module` | 32 | 128 | 256 | 512 | 1024 |
| `string_encoding.prefer_lazy_decode` | true | true | true | false | false |
| `string_encoding.allow_ctor_fallback` | true | true | false | false | false |
| `constant_encoding.max_constants_per_function` | 2 | 4 | 8 | 16 | 32 |
| `security.fail_on_public_obf_symbol` | false | true | true | true | true |

All profiles default to `authenticated_mode: false`, `min_instructions_per_block: 2` (`fortress` and `lab` use `1`), `min_bit_width: 8`, `default_level: none`, and `constant_encoding.mode: mba_inline`. Explicit top-level YAML keys override profile defaults.

### Per-Function Annotations

Protection levels can be set directly in source using LLVM's `annotate` attribute. The annotation value must be `"obf:<level>"` where `<level>` is one of `none`, `light`, `strong`, `vm`, or `strong_vm`.

```c
__attribute__((annotate("obf:strong_vm")))
void sensitive_routine(void) { ... }
```

Annotations take precedence below explicit `overrides` entries but above `targets` rule matching. The automatic security floor applies independently and may raise the level further.

Minimal example:

```yaml
profile: fortress
seed: 20260601
default_level: none

targets:
  - match: "verify_*"
    level: strong_vm
  - match: "license_*"
    level: strong_vm

string_encoding:
  authenticated_mode: true
  prefer_lazy_decode: true
  allow_ctor_fallback: false

constant_encoding:
  mode: auto
  max_constants_per_function: 8
  min_bit_width: 8

mba:
  depth: 3

indirect_dispatch:
  enabled: true
  max_sites_per_function: 4
  max_switch_targets: 8
  target_vm_dispatchers: true
  target_flattened_headers: true

security:
  fail_on_public_obf_symbol: true
  strip_release_markers: true
```

## Build

Requirements:

- CMake 3.24+
- C++23 compiler
- LLVM 21+
- Python 3
- `lit`
- LLVM tools: `opt`, `clang`, `clang++`, `llvm-link`, `llc`, `llvm-strip`

Configure and build:

```sh
cmake -S . -B build -DLLVM_DIR="$(llvm-config --cmakedir)"
cmake --build build
```

Useful cache variables:

- `OBF_BENCHMARK_SEED`
- `OBF_RUNTIME_ABI_PREFIX`
- `OBF_BENCHMARK_CLEAN_IR`

## Usage

Feature report:

```sh
opt -load-pass-plugin build/obf_plugin.so \
  --obf-config=config.yaml \
  -passes=obf-feature-report \
  -disable-output input.ll
```

Full safe pipeline:

```sh
opt -load-pass-plugin build/obf_plugin.so \
  --obf-config=config.yaml \
  -passes=obf-safe-pipeline \
  -S input.ll -o output.ll
```

Isolated indirect dispatch:

```sh
opt -load-pass-plugin build/obf_plugin.so \
  --obf-config=config.yaml \
  -passes=obf-indirect-dispatch \
  -S input.ll -o indirect.ll
```

`obf-driver` currently loads a config and prints a summary. It is not a full compile driver.

## Verification

Requested release sweep:

```sh
cmake --build build --target obf-benchmarks obf-seed-diversity obf-unit-tests
ctest --test-dir build --output-on-failure -R "obf-lit|obf-unit-tests"
```

Other useful targets:

- `obf-benchmarks`
- `obf-benchmarks-mir`
- `obf-audit-benchmarks`
- `obf-re-harness`
- `obf-seed-diversity`

Current benchmark corpus:

- `license_demo`
- `config_demo`
- `vm_workflow_demo`
- `wpo_demo`

## Repository Layout

```text
include/obf/       public headers
lib/analysis/      feature extraction
lib/frontend/      config loading and annotations
lib/plugin/        pass registration and pipeline wiring
lib/policy/        function-level policy selection
lib/report/        reporting
lib/transforms/    IR transforms
lib/vm/            VM lowering and dispatch
runtime/           runtime support objects
tests/lit/         lit coverage
tests/unit/        unit tests
benchmarks/        corpus, configs, and build targets
tools/             helper tools and scripts
```
