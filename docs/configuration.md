# Configuration

[Documentation](README.md) · [Usage](usage.md) · [Frontends](frontends.md) · [Protection](protection.md)

Use a YAML file to select functions and set transform limits.
Use one top-level mapping. The parser rejects multiple non-empty YAML documents.

- [Minimal selection](#minimal-selection)
- [Selection and precedence](#selection-and-precedence)
- [Pass eligibility](#pass-eligibility)
- [Profiles and inherited values](#profiles-and-inherited-values)
- [Extended example](#extended-example)
- [Security gates](#security-gates)

## Minimal selection

Save this example as your own configuration file.
Replace `license_verify` with a defined LLVM function name.

```yaml
frontend: generic
seed: 20260817
default_level: none
overrides:
  - name: license_verify
    level: strong
security:
  fail_on_public_obf_symbol: true
  strip_release_markers: true
```

This configuration selects `license_verify` explicitly.
Automatic analysis, policy floors, and caller promotions can still select other functions.
Feature restrictions can disable transforms, and individual passes can skip unsupported sites.
See [selection and precedence](#selection-and-precedence) and [feature restrictions](#feature-restrictions) for the details.

Self-checksum and indirect dispatch stay disabled unless you enable them.
String authentication also stays disabled in this minimal example.

Use [the usage guide](usage.md) to pass the file to a wrapper or plugin.
Use [the frontend guide](frontends.md) for Rust, Zig, or TinyGo configuration requirements.

## Selection and precedence

The engine excludes runtime-internal names before it applies user selection.
Names that start with `__obf_` or `_obf_` remain excluded, even with an explicit target, override, or annotation.
An embedded `_obf_` does not exclude a user function, such as `verify_obf_token`.
The existing exclusions for names that contain `rt_core_`, `ObfEntropy`, `ObfBlake`, or `llvm.` still apply.

### Generic frontend

The policy engine compares selectors with LLVM function names. It does not demangle C++ names.
Use a mangled name, a source annotation, or an `extern "C"` function.
This selector restriction does not apply to checksum binding.

The initial selection order is:

1. The first matching `overrides[].name` entry. This comparison is exact.
2. A recognized source annotation, such as `obf:strong`.
3. The first matching `targets[].match` entry.
4. Automatic feature analysis.
5. `default_level`.

Generic target rules support `*` for any sequence and `?` for one character.
The first matching rule wins, not the most specific rule.
Generic selectors that match no function do not cause a missing-target error.

Automatic analysis selects `light` for functions with string references.
Otherwise, it selects `strong` for qualifying control flow.
That condition requires cyclomatic complexity of at least three, at most 128 instructions, and no address-taken use.

The engine then applies a minimum security floor:

- Qualifying control flow requires `strong`, `vm`, or `strong_vm`.
- Otherwise, string references require a level other than `none`.

Floors can raise an override or annotation that selects `none` or `light`.
`security.allow_unsafe_config` does not disable these floors.
Therefore, `default_level: none` is a fallback, not an exact-selection mode.

The generic pipeline can also promote callers of `strong`, `vm`, or `strong_vm` functions.
It considers `main` and callers whose protected results drive control flow or escape through returns, stores, or calls.
These promotions can include functions with an explicit `none` selection.
A selected `vm` caller keeps its VM level and eligibility when this promotion adds classical protection.
Existing feature restrictions still apply.

### Rust, Zig, and TinyGo frontends

These frontends use explicit selection instead of generic automatic selection.
They ignore source annotations and do not apply generic caller promotions.

Their effective configuration must meet all these requirements:

- Set `default_level: none`.
- Set `security.strip_release_markers: true`.
- Keep `security.allow_unsafe_config: false`.
- Provide at least one target or override.
- Use non-empty exact names without `*` or `?`.
- Use only `light` or `strong` for every entry.
- Do not repeat a name or select it in both lists.
- For TinyGo, set `string_encoding.max_strings_per_module: 0`.

Every selected name must resolve to a defined function in the input module.
A name can select an alias that resolves to a defined function.
Two selectors cannot resolve to the same function.
The resolved function name must also exclude `*` and `?`.

Unmatched functions stay at `none`. Security floors apply only to explicitly selected functions.
Thus, a selected `light` function can rise to `strong` when its control flow meets the floor.

### Feature restrictions

Selection does not guarantee that every eligible pass changes a function.

- Declarations and recognized runtime-internal names receive `none`.
- Address-taken functions cannot use VM lowering. Their `vm` or `strong_vm` policy becomes `strong`.
- Exception edges or inline assembly usually reduce `strong`, `vm`, or `strong_vm` to restricted `light`.
- An exact generic override keeps its selected level despite these risky features, but disables VM lowering.
- Individual transforms also reject unsupported instructions, address spaces, or control-flow shapes.

The feature report labels these results as candidate predictions.
The outcome ledger retains original selection reasons and later caller-promotion reasons.
It records actual admission and emission separately.
See [compiler coverage reports](usage.md#compiler-coverage-reports).

## Pass eligibility

This table shows the initial function-policy flags, before feature restrictions and configuration switches.
“Yes” means eligible, not guaranteed execution or complete protection.
VM lowering can replace the source body, so later passes do not necessarily act on that original body.

| Transform | `none` | `light` | `strong` | `vm` | `strong_vm` |
|---|:---:|:---:|:---:|:---:|:---:|
| VM lowering | No | No | No | Yes | Yes |
| String encoding | No | Yes | Yes | Yes | Yes |
| Zero-comparison reduction | No | Yes | Yes | Yes | Yes |
| Constant encoding | No | Yes | Yes | Yes | No |
| Instruction substitution | No | No | Yes | No | Yes |
| Opaque global offsets (`opaque_gep`) | No | No | Yes | No | Yes |
| Opaque predicates | No | No | Yes | No | No |
| CFG flattening | No | No | Yes | No | Yes |
| Function outlining | No | No | Yes | No | Yes |
| Bogus control flow | No | No | Yes | No | No |
| Block splitting | No | Yes | Yes | Yes | No |
| Indirect dispatch | No | No | Yes | Yes | Yes |
| Self-checksum | No | No* | Yes | Yes | Yes |

\* `self_checksum.enabled: true` also makes non-`none` functions at `light` eligible.
The self-checksum stage still requires a supported transform site and final-file binding.

Additional controls:

- Indirect dispatch and self-checksum default to disabled.
- Zero-comparison reduction defaults to enabled, but still requires function-policy eligibility.
- TinyGo disables string encoding, regardless of the selected level.
- `light` caps block splits at one and encoded constants at two per function.
- `strong_vm` bypasses the ordinary constant-encoding pass. Its VM bytecode and handlers use separate protection.
- `mba.depth` controls [MBA construction](protection.md#mba-and-substitution) across several passes, not a separate level-wide MBA pass.

See [Protection](protection.md) for transform behavior and limits.

## Profiles and inherited values

There is no implicit profile. An omitted `profile` uses the structure defaults, reported as `legacy`.
A profile supplies defaults. It does not select functions or guarantee a protection outcome.

### Explicit preset values

“Unset” means that the preset does not supply an optional MBA override.
It does not mean `false` or zero.

| Setting | `fast` | `standard` | `guarded` | `fortress` | `lab` |
|---|---:|---:|---:|---:|---:|
| `mba.depth` | 1 | 1 | 2 | 3 | 4 |
| `mba.enable_polynomial` | Unset | Unset | Unset | Unset | `true` |
| `mba.enable_multiplication` | Unset | Unset | Unset | Unset | `true` |
| `mba.max_ir_instructions` | Unset | Unset | Unset | Unset | 320 |
| `block_split.max_splits_per_function` | 1 | 1 | 2 | 4 | 8 |
| `block_split.min_instructions_per_block` | 2 | 2 | 2 | 1 | 1 |
| `string_encoding.min_string_length` | 3 | 2 | 2 | 1 | 1 |
| `string_encoding.max_strings_per_module` | 32 | 128 | 256 | 512 | 1024 |
| `string_encoding.prefer_lazy_decode` | `true` | `true` | `true` | `false` | `false` |
| `string_encoding.allow_ctor_fallback` | `true` | `true` | `false` | `false` | `false` |
| `constant_encoding.max_constants_per_function` | 2 | 4 | 8 | 16 | 32 |
| `security.fail_on_public_obf_symbol` | `false` | `true` | `true` | `true` | `true` |

With no optional MBA overrides, depths one through four supply expansion budgets of 64, 128, 192, and 256.
The tracker charges expansion costs, not every emitted IR instruction.
Polynomial and multiplication features default to enabled at depth three or higher.
Thus, `fortress` can enable these features even though its preset entries are unset.
`lab` explicitly sets a larger budget of 320.

### Inherited structure defaults

Profiles retain these values unless your YAML replaces their containing sections:

| Setting | Default |
|---|---|
| `frontend` / `default_level` / `seed` | `generic` / `none` / `0` |
| `string_encoding.authenticated_mode` | `false` |
| `string_encoding.enable_ephemeral_slots` | `true` |
| `constant_encoding.mode` / `min_bit_width` | `mba_inline` / `8` |
| `zero_comparison.enabled` | `true` |
| `zero_comparison.max_sites_per_function` / `max_unroll_bytes` | `16` / `64` |
| Both zero-comparison transform switches | `true` |
| `vm.max_virtual_instructions` / `max_mba_depth` | `512` / Unset |
| `indirect_dispatch.enabled` | `false` |
| `indirect_dispatch.max_sites_per_function` / `max_switch_targets` | `4` / `8` |
| Both indirect-dispatch target switches | `true` |
| `self_checksum.enabled` / `window_size` / `max_sites` / `seed` | `false` / `64` / `4` / `0` |
| `security.strip_release_markers` / `allow_unsafe_config` | `false` / `false` |
| `debug_preserve_generated_names` / `emit_progress_warnings` | `false` / `false` |

Without a profile, string encoding limits the module to 64 strings, with a minimum length of two.
It prefers lazy decoding and allows constructor fallback.
Other unprofiled limits use the `standard` values shown above, except `security.fail_on_public_obf_symbol`, which defaults to `false`.

### Section replacement, not recursive merging

An explicit top-level section replaces that entire profile section.
Omitted members within the section use parser defaults, not the profile's values.

For example, this configuration limits strings to 64, not 512:

```yaml
profile: fortress
string_encoding:
  authenticated_mode: true
```

It also restores the parser's minimum length of two, lazy decoding, and constructor fallback.
Likewise, `mba: {depth: 2}` removes `lab`'s explicit optional overrides.
When you change one member, specify the other profile values you want to retain.

The top-level seed is an unsigned 64-bit integer.
Function seeds also depend on the module name and function name.
A fixed seed alone does not promise identical output for different module paths.

## Extended example

Use this example for the generic frontend only.
Replace the function names and patterns with your own LLVM selectors.
The example keeps self-checksum disabled because ordinary frontend workflows do not all bind the final file.

```yaml
frontend: generic
profile: guarded
seed: 20260817
default_level: none

overrides:
  - name: license_verify
    level: strong_vm
  - name: decrypt_payload
    level: strong

targets:
  - match: "auth_*"
    level: strong
  - match: "crypto_*"
    level: vm

string_encoding:
  min_string_length: 2
  max_strings_per_module: 256
  prefer_lazy_decode: true
  allow_ctor_fallback: false
  authenticated_mode: true
  enable_ephemeral_slots: true

constant_encoding:
  mode: auto
  max_constants_per_function: 8
  min_bit_width: 8

mba:
  depth: 2
  enable_polynomial: false
  enable_multiplication: false
  max_ir_instructions: 128

vm:
  max_virtual_instructions: 512
  max_mba_depth: 2

indirect_dispatch:
  enabled: true
  max_sites_per_function: 8
  max_switch_targets: 16
  target_vm_dispatchers: true
  target_flattened_headers: true

block_split:
  max_splits_per_function: 2
  min_instructions_per_block: 2

zero_comparison:
  enabled: true
  max_sites_per_function: 16
  max_unroll_bytes: 64
  transform_string_comparisons: true
  transform_integer_comparisons: true

self_checksum:
  enabled: false
  window_size: 32
  max_sites: 4
  seed: 20260817

security:
  fail_on_public_obf_symbol: true
  strip_release_markers: true
  allow_unsafe_config: false

debug_preserve_generated_names: false
emit_progress_warnings: false
```

`constant_encoding.mode` accepts `off`, `mba_inline`, `keyed_pool`, `auto`, or `all`.
`vm.max_mba_depth` caps VM arithmetic depth at the smaller of that value and `mba.depth`.
A zero self-checksum seed uses the top-level seed.

## Security gates

Keep `security.allow_unsafe_config: false` for normal builds.

Configuration preflight requires:

- `vm.max_virtual_instructions` must be at least one.
- A configuration that selects `vm` or `strong_vm` cannot preserve generated debug names.
- `strong_vm`, `fortress`, and `lab` require `security.fail_on_public_obf_symbol: true`.
- Non-generic frontends must meet their stricter [selection requirements](#rust-zig-and-tinygo-frontends).

For generic configurations, `allow_unsafe_config: true` bypasses the debug-name and public-symbol preflight requirements.
It does not bypass the instruction-budget check, policy floors, or the pipeline's `strong_vm` invariants.
Non-generic frontends reject it.

The pipeline checks `strong_vm` virtualization, protected-string outcomes, seed resolvers, target caches, and generated function attributes.
The public-symbol gate rejects public obfuscator symbols when you enable it.
Marker stripping is a separate option. Profiles do not enable it automatically.

Enable self-checksum only when your final artifact meets the [binding contract](self-checksum.md).
Rust, Zig bitcode, and TinyGo workflows do not bind records automatically.
A protected site with a required unbound record traps if execution reaches it.
See [SECURITY.md](../SECURITY.md) for security limits.

## Source reference

The [parser and presets](../lib/frontend/config.cpp), [configuration types](../include/obf/frontend/config.h),
[policy engine](../lib/policy/policy_engine.cpp), and [pipeline policy](../lib/plugin/plugin_policy.cpp) define these rules.
The [profile fixtures](../tests/lit/tooling/profile-config.ll), [floor fixtures](../tests/lit/tooling/policy-floor.ll),
and [frontend fixtures](../tests/lit/tooling/frontend-policy-safety.ll) cover their contracts.
