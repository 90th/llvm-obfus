# llvm-obfus

`llvm-obfus` is an out-of-tree LLVM 21+ pass plugin for policy-driven IR obfuscation.

The project applies native LLVM IR transforms to selected functions. The main production entry point is `obf-safe-pipeline`, which composes virtualization, structural rewrites, string and constant protection, late indirect dispatch, and final artifact cleanup.

The design goal is simple: make static recovery materially harder while staying inside normal LLVM semantics. The project does not rely on malformed objects, inline-asm traps, EH spoofing, or target-specific parser breaks.

## Main Features

### Strong Virtualization And MBA Flattening

- Protection levels are `none`, `light`, `strong`, `vm`, and `strong_vm`.
- `vm` and `strong_vm` lower selected functions into VM-backed execution paths.
- `strong_vm` implementation bodies continue through later hardening stages, not just the public wrapper.
- MBA rewriting owns arithmetic identity diversification such as `add`, `sub`, and `xor`, both directly and as part of other transforms such as constant reconstruction.
- `instruction_substitution` stays focused on distinct logical rewrites such as boolean identity transformations instead of duplicating MBA arithmetic forms.

### Seeded Indirect Dispatch

- `indirect_dispatch` is a late pass in the safe pipeline.
- It rewrites supported conditional branches and switch dispatch sites into per-site masked `blockaddress` plus arithmetic plus `indirectbr` sequences.
- Each dispatch site derives its masking material from the protected function seed and site index.
- The implementation reconstructs targets from same-function deltas in SSA instead of emitting absolute dispatch tables in globals.
- This pass does not use the authenticated BLAKE2s runtime used by strings and constant pools.
- Unsupported shapes are skipped conservatively: EH personalities, EH pads, `invoke`, `callbr`, existing `indirectbr`, `catchswitch`, `catchreturn`, `cleanupreturn`, `resume`, `musttail`, and non-integral program address spaces.

### Keyed And Integrity-Checked Runtime Strings

- String encoding is configured under `string_encoding`.
- `authenticated_mode` enables the keyed and integrity-checked runtime decode path.
- The runtime support lives in `runtime/string_auth_runtime.c` and handles keyed string and constant-pool recovery.
- Lazy decode, eager decode, constructor fallback, and forwarded-pointer cases are handled in the transform.

### Constant Pooling

- Constant encoding modes are `off`, `mba_inline`, `keyed_pool`, `auto`, and `all`.
- `mba_inline` reconstructs constants directly in IR.
- `keyed_pool` moves constants into keyed, integrity-checked pools recovered at use sites.
- `auto` chooses a strategy per use site.

### Seed And Key Derivation

- The top-level `seed` is the root build input. Function-selective passes such as `indirect_dispatch` derive per-function seeds from the module name, function name, and top-level seed; the keyed string and keyed-pool runtime currently uses the top-level seed directly.
- `authenticated_mode` and `keyed_pool` use a domain-separated BLAKE2s schedule implemented in `include/obf/support/auth_encoding.h`.
- The schedule is `build_key(seed)` -> `function_key(module_id, function_id)` -> per-site or per-pool key -> labeled `enc` and `mac` subkeys.
- Authenticated strings derive distinct keys from descriptor metadata including `module_id`, a derived `function_id`, and `site_id`. Keyed constant pools derive distinct keys from `module_id` and `pool_id`.
- Authentication uses a keyed BLAKE2s tag over descriptor metadata plus ciphertext, and encryption uses a BLAKE2s-derived XOR keystream with a derived nonce. It does not use AES, ChaCha20, HMAC, or SipHash.
- The emitted artifacts store the 32-byte `build_key` in internal globals and reconstruct derived keys at runtime from descriptor metadata. This is an embedded-key, self-contained runtime: no hardware token, remote service, white-box key split, or entropy-anchor binding is involved.
- Integrity verification is fail-closed: descriptor mismatches, tag mismatches, and length mismatches trap in the runtime instead of returning tampered plaintext.
- `runtime/entropy_anchor.c` supports opaque arithmetic and MBA-style transforms; it is separate from the keyed string and constant-pool key schedule.

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
- `runtime/string_auth_runtime.c` provides keyed and integrity-checked decode support for strings and constant pools.

## Safe Pipeline Order

`obf-safe-pipeline` is the integrated pipeline used by the benchmarks and lit coverage. Its current high-level order is:

1. entropy initialization
2. VM lowering and call rewriting for `vm`
3. VM lowering and call rewriting for `strong_vm`
4. post-VM string encoding
5. constant encoding
6. opaque GEP
7. instruction substitution for logical and boolean rewrites
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

All profiles default to `authenticated_mode: false`, `indirect_dispatch.enabled: false`, `min_instructions_per_block: 2` (`fortress` and `lab` use `1`), `min_bit_width: 8`, `default_level: none`, and `constant_encoding.mode: mba_inline`. Explicit top-level YAML keys override profile defaults.

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
- LLVM tools: `opt`, `clang`, `clang++`, `llvm-link`, `llc`, `llvm-strip`, `llvm-nm`, `llvm-objdump`
- Optional: `strings` for benchmark string audits

Configure and build:

```sh
cmake -S . -B build -DLLVM_DIR="$(llvm-config --cmakedir)"
cmake --build build
```

Useful cache variables:

- `OBF_BENCHMARK_SEED`
- `OBF_RUNTIME_ABI_PREFIX`
- `OBF_BENCHMARK_CLEAN_IR`
- `OBF_BENCHMARK_CLEANUP_PASSES`

## Usage

Feature report:

- `obf-feature-report` is read-only and emits `obf.feature_report.v3` JSON with per-function policy decisions and per-transform strategy details.

```sh
opt -load-pass-plugin build/obf_plugin.so \
  --obf-config=config.yaml \
  -passes=obf-feature-report \
  -disable-output input.ll
```

Policy audit:

- `obf-audit` prints a policy-resolution table and can also write `obf.audit.v1` JSON with `--obf-audit-out`.

```sh
opt -load-pass-plugin build/obf_plugin.so \
  --obf-config=config.yaml \
  --obf-audit-out=audit.json \
  -passes=obf-audit \
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

Other standalone passes:

- Read-only/reporting: `obf-feature-report`, `obf-audit`.
- Transform stages: `obf-entropy-init`, `obf-vm`, `obf-block-split`, `obf-string-encode`, `obf-constant-encode`, `obf-opaque-gep`, `obf-instruction-substitute`, `obf-control-flatten`, `obf-function-outline`, `obf-opaque-preds`, `obf-bogus-cf`, `obf-indirect-dispatch`, `obf-cfg-state-cleanup`, and `obf-artifact-cleanup`.

`obf-driver` currently loads a config and prints a summary. It is not a full compile driver.

## Benchmarks

Benchmark targets build paired baseline and obfuscated artifacts under `build/benchmarks/<name>/`. The benchmark build passes `--obf-seed=${OBF_EFFECTIVE_BENCHMARK_SEED}` to `opt`, so `OBF_BENCHMARK_SEED` controls the effective benchmark seed for the whole build tree even when a sample benchmark config contains its own `seed:` entry.

Build benchmark pairs:

```sh
cmake --build build --target obf-benchmarks
```

Per-benchmark artifacts:

- `<name>.baseline.ll`
- `<name>.obfuscated.ll`
- `<name>.obfuscated.cleaned.ll` when `OBF_BENCHMARK_CLEAN_IR=ON`
- `<name>.baseline`
- `<name>.obfuscated`

Benchmark and analysis targets:

- `obf-benchmarks` builds stripped baseline and obfuscated pairs for the full corpus.
- `obf-benchmarks-mir` emits MIR snapshots for linked benchmark targets such as `wpo_demo`.
- `obf-audit-benchmarks` audits stripped obfuscated benchmark binaries for leaked symbols and, when `strings` is available, residual strings.
- `obf-re-harness` scores how much VM structure is recoverable from obfuscated benchmark IR and writes `build/re-harness/vm_recovery.json`.
- `obf-seed-diversity` verifies seed-driven IR diversity and writes `build/diversity/diversity.json`.

Current benchmark corpus:

- `license_demo`
- `config_demo`
- `vm_workflow_demo`
- `wpo_demo`

Measure keyed string decode overhead:

```sh
python tools/obf-bench/measure_string_auth_overhead.py --build-dir build
```

The helper writes temporary inputs under `build/string-auth-bench/` and reports lazy first-decode cost, lazy steady-state helper cost, and constructor startup impact.

## Verification

Requested release sweep:

```sh
cmake --build build --target obf-benchmarks obf-seed-diversity obf-unit-tests
ctest --test-dir build --output-on-failure -R "obf-lit|obf-unit-tests"
```

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
