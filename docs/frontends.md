# Frontends

[Documentation](README.md) · [Building](building.md) · [Usage](usage.md) · [Configuration](configuration.md)

Use Clang for the native C/C++ workflow.
Rust, Zig, and TinyGo use narrower integration routes with explicit function selection.

- [Support and compatibility](#support-and-compatibility)
- [Shared selection rules](#shared-selection-rules)
- [Rust](#rust)
- [Zig](#zig)
- [TinyGo](#tinygo)
- [Final-file binding](#final-file-binding)

## Support and compatibility

| Frontend | Integration | Host and toolchain conditions |
|---|---|---|
| Clang / Clang++ | `-fpass-plugin` or `obf-clang` / `obf-clang++` | Linux or configured Windows plugin hosts. See [Building](building.md) and [Usage](usage.md). |
| LLVM bitcode | `obf-bc` or the `opt` plugin | A compatible LLVM producer, reader, target, and runtime. Windows needs its configured plugin host. |
| Rust | `obf-rustc`, directly or through `RUSTC_WORKSPACE_WRAPPER` | Nightly or dev `rustc` with matching LLVM major.minor. Native target only. Windows also needs a bound Rust LLVM host. |
| Zig | A component bitcode pipeline through `obf-bc` | The documented route uses Zig 0.16.x on native Linux or Windows. |
| TinyGo | `obf-tinygo` | Native Linux. TinyGo 0.41.x, Go 1.23–1.26, embedded LLVM 20.x, and project LLVM 21 tools. |

LLVM bitcode compatibility and plugin ABI compatibility are different requirements.
A Rust plugin loads inside `rustc`. Matching a reported LLVM version alone does not establish every ABI requirement.
Zig and TinyGo produce bitcode outside the plugin host.
Their documented routes do not imply general compatibility with every LLVM producer or language runtime.

The real Rust, Zig, and TinyGo frontend fixtures cover native Linux routes.
Windows Rust has separate bound-host fixtures. Zig benchmark discovery also permits native Windows.
These conditions are not guarantees for other platforms or future compiler versions.

## Shared selection rules

For `frontend: rust`, `zig`, or `tinygo`:

1. Set `default_level: none`.
2. Select defined functions with exact `targets[].match` or `overrides[].name` entries.
3. Use only `light` or `strong` for those entries.
4. Set `security.strip_release_markers: true`.
5. Keep `security.allow_unsafe_config: false`.

Do not use wildcards, duplicate selections, or target/override overlaps.
An exact alias can select its defined implementation.
Two aliases cannot select the same implementation twice.
Missing definitions cause an error instead of a silent skip.

These frontends ignore source annotations and leave unmatched functions at `none`.
A security floor can raise a selected `light` function to `strong`.
See [Configuration](configuration.md#selection-and-precedence) for the full policy rules.

Use a stable exported symbol when possible.
Compiler-generated names can change with compiler versions, build options, or source changes.
Keep the selected definition in the module that the pipeline processes.

The commands below require your own source files and YAML files.
They do not refer to shipped `config/rust_protect.yaml`, `config/zig_protect.yaml`, or `config/tinygo_protect.yaml` files.
The shell examples use POSIX syntax. Use equivalent environment assignments and executable paths on Windows.

## Rust

### Prerequisites

- Build the plugin, `obf-driver`, runtime archive, and `obf-rustc` wrapper.
- Use a nightly or dev compiler. Stable `rustc` does not meet the active wrapper's requirement.
- Match the LLVM major.minor reported by `rustc -vV` with the plugin build's LLVM major.minor.
- Use the native target configured as `LLVM_HOST_TRIPLE`. The wrapper rejects a different explicit `--target`.
- For Cargo, install Cargo and select one exact binary or `cdylib` crate.

The wrapper injects `-Zllvm-plugins`, one code generation unit, and runtime link flags when it links.
A conflicting `-Ccodegen-units` value causes an error.
If your Cargo profile specifies code generation units, set the selected profile to one.

On Windows, configure all three Rust host inputs:

- `OBF_WINDOWS_RUST_LLVM_HOST_IMAGE`: the `rustc_driver` DLL that owns the LLVM exports.
- `OBF_WINDOWS_RUST_LLVM_HOST_IMPORT_LIBRARY`: its matching import library.
- `OBF_WINDOWS_RUST_LLVM_HOST_RUSTC`: the matching `rustc.exe`.

The build creates a separate Rust plugin for this host.
The active wrapper checks the bound compiler and recorded host identity.
It also checks the adjacent owner DLL against its configured hash.
An ordinary Windows Clang/`opt` plugin build does not enable active Rust protection.
See [Building](building.md) for host setup.

### Source and configuration

An exported C ABI function gives the YAML a stable name.
For example, add this function to your binary crate and call it from your application:

```rust
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn rust_protected(value: u32) -> u32 {
    value.wrapping_mul(17).wrapping_add(29) ^ 0x5a5a
}
```

Save this configuration as your own Rust YAML file:

```yaml
frontend: rust
default_level: none
targets:
  - match: rust_protected
    level: strong
string_encoding:
  authenticated_mode: true
  prefer_lazy_decode: true
  allow_ctor_fallback: false
security:
  strip_release_markers: true
  fail_on_public_obf_symbol: true
```

Replace `rust_protected` if your selected symbol has a different name.
Keep self-checksum disabled unless you will bind a supported final executable.

### Direct compilation

Set the four required input variables before this command:

```sh
: "${BUILD:?Set the absolute llvm-obfus build directory}"
: "${RUSTC_BIN:?Set the matching nightly or dev rustc executable}"
: "${RUST_CONFIG:?Set the Rust YAML file you created}"
: "${RUST_SOURCE:?Set your Rust binary crate root}"

"$BUILD/obf-rustc" \
  --rustc="$RUSTC_BIN" \
  --obf-config="$RUST_CONFIG" \
  --edition=2024 --crate-name=protected_app --crate-type=bin \
  "$RUST_SOURCE" -o rust_app
```

A configuration activates protection. `--obf-enable` is not necessary when you supply one.
The source must define `main` and the selected symbol.

Direct active compilation requires one code-generating emit kind and one explicit output destination.
Use `-o` or an explicit `--emit=kind=path` output.
The wrapper supports `bin`, `cdylib`, or a direct `--test` invocation.
It does not support active `rlib`, `lib`, or `staticlib` compilation.

Direct mode disables split debug information and rejects sidecar-producing options such as incremental compilation and saved temporaries.
Use Cargo for those workflows.
The wrapper also rejects linker-plugin LTO, `-Cllvm-args`, compiler response files, and conflicting plugin flags.
Direct mode rejects user `-Clink-arg` values. Use `-l`/`-L` or Cargo instead.

### Cargo: exact owner selection

Configure `obf-rustc` as `RUSTC_WORKSPACE_WRAPPER`, not `RUSTC_WRAPPER`.
`OBF_CONFIG` activates protection for the selected code-generating invocation.

All four owner selectors must match:

| Variable | Required value |
|---|---|
| `OBF_RUST_MANIFEST_DIR` | Canonical absolute directory for the selected package's `Cargo.toml`. |
| `OBF_RUST_CRATE_ROOT` | Canonical absolute path to the selected crate's source root. |
| `OBF_RUST_CRATE_NAME` | Exact rustc crate name, with Cargo's underscore normalization. For example, `my-app` becomes `my_app`. |
| `OBF_RUST_CRATE_TYPE` | Exactly `bin` or `cdylib`. |

The manifest directory is the package directory, not necessarily the workspace root.
The crate root separates a binary from a library or example with the same crate name.
Do not derive the selector from the package name alone.

This example selects one existing Cargo binary.
Set `CARGO_BIN_NAME` to its Cargo target name and `CRATE_NAME` to its normalized rustc name.

```sh
: "${BUILD:?Set the absolute llvm-obfus build directory}"
: "${RUSTC_BIN:?Set the matching nightly or dev rustc executable}"
: "${RUST_CONFIG:?Set the Rust YAML file you created}"
: "${PACKAGE_DIR:?Set the selected Cargo package directory}"
: "${CRATE_ROOT:?Set the selected binary source-root path}"
: "${CARGO_BIN_NAME:?Set the exact Cargo binary target name}"
: "${CRATE_NAME:?Set its normalized underscore rustc crate name}"

MANIFEST_DIR="$(realpath "$PACKAGE_DIR")"
ROOT="$(realpath "$CRATE_ROOT")"
CONFIG="$(realpath "$RUST_CONFIG")"

RUSTC="$RUSTC_BIN" \
RUSTC_WORKSPACE_WRAPPER="$BUILD/obf-rustc" \
OBF_CONFIG="$CONFIG" \
OBF_RUST_MANIFEST_DIR="$MANIFEST_DIR" \
OBF_RUST_CRATE_ROOT="$ROOT" \
OBF_RUST_CRATE_NAME="$CRATE_NAME" \
OBF_RUST_CRATE_TYPE=bin \
cargo build --release --jobs 3 \
  --manifest-path "$MANIFEST_DIR/Cargo.toml" --bin "$CARGO_BIN_NAME"
```

Do not also set `RUSTC_WRAPPER` to `obf-rustc`.
For a `cdylib`, select its library source root and crate name, set its crate type, and use Cargo's library target.

The wrapper passes compiler queries, metadata-only actions, and nonmatching owner invocations through without plugin injection.
Therefore, `cargo check` does not establish that a protected binary build works.
Unselected libraries, examples, build scripts, and other workspace crates do not receive protection from this selector.

## Zig

### Component route

The documented workflow uses Zig 0.16.x and a stable exported C ABI component.
It is not a whole-program Zig build wrapper.
`obf-bc` does not check the Zig version. Supply compatible bitcode and a compatible final-link toolchain.

For example, your component can export:

```zig
export fn zig_protected(value: u32) u32 {
    return (value *% 17) +% 29;
}
```

Save a YAML file that selects this export:

```yaml
frontend: zig
default_level: none
targets:
  - match: zig_protected
    level: strong
security:
  strip_release_markers: true
  fail_on_public_obf_symbol: true
```

Zig can represent the export as an alias to an internal definition.
The non-generic selector resolver follows that alias.
Use C-compatible exported argument and result types.
The repository fixture also covers an `extern struct` argument.

This command sequence requires a component source and a separate Zig application source that calls its export.
The application must not compile the component source again.

```sh
: "${BUILD:?Set the absolute llvm-obfus build directory}"
: "${ZIG_BIN:?Set the Zig 0.16.x executable}"
: "${ZIG_CONFIG:?Set the Zig YAML file you created}"
: "${ZIG_COMPONENT:?Set the exported component source path}"
: "${ZIG_MAIN:?Set the separate Zig application source path}"
: "${OBF_RUNTIME:?Set the matching obfuscator runtime archive path}"

"$ZIG_BIN" build-obj "$ZIG_COMPONENT" \
  -fllvm -O ReleaseFast -fno-emit-bin -femit-llvm-bc=component.bc

"$BUILD/obf-bc" --obf-config="$ZIG_CONFIG" \
  component.bc -o component.obf.bc

"$ZIG_BIN" build-exe "$ZIG_MAIN" component.obf.bc \
  "$OBF_RUNTIME" -femit-bin=zig_app
```

The final link consumes the exact protected bitcode and the matching runtime archive.
The real Linux fixture covers this same-host component route.
Do not interpret it as support for arbitrary cross-target Zig programs or incompatible bitcode versions.

## TinyGo

### Prerequisites and restrictions

`obf-tinygo` supports the native Linux retained-link workflow only.
It requires:

- TinyGo 0.41.x with Go 1.23–1.26 and embedded LLVM 20.x.
- A project build with LLVM 21, an LLVM 21 `llc`, and an LLVM 21 LLD linker.
- A matching native Linux runtime archive and LLVM host triple.
- A recognized native architecture: x86-64, AArch64, or the supported ARM host names.

The real frontend fixture uses a numeric-only program with both supported GC modes.
The architecture checks do not establish equal test coverage for every recognized host.

The wrapper accepts only:

- The `build` subcommand and one package or `.go` file.
- An explicit `-scheduler=none`.
- An explicit `-gc=conservative` or `-gc=none`.
- The default build mode and a native executable output path.

It rejects package wildcards, `-target`, `-C`, and non-empty `GOOS`, `GOARCH`, `GOARM`, or `GOMIPS` overrides.
It also rejects cgo sources in the package or its dependencies.
The retained linker command cannot use shared-library, relocatable, or explicit PIE output modes.
Response files, linker groups, and unsupported linker-command shapes also cause an error.
This is not a firmware, WebAssembly, or cross-compilation route.

### Source and configuration

Give the selected numeric function an explicit export and prevent inlining:

```go
//go:export protected_value
//go:noinline
func protectedValue(x uint64) uint64 {
    return (x * 17) ^ (x + 29)
}
```

Include this function in a `package main` program and call it from `main`.
Save this configuration as your own YAML file:

```yaml
frontend: tinygo
default_level: none
targets:
  - match: protected_value
    level: light
string_encoding:
  max_strings_per_module: 0
security:
  strip_release_markers: true
  fail_on_public_obf_symbol: true
```

String encoding must stay disabled. The wrapper requires a block-style selection list and `string_encoding` mapping.

```sh
: "${BUILD:?Set the absolute llvm-obfus build directory}"
: "${TINYGO_CONFIG:?Set the TinyGo YAML file you created}"
: "${GO_SOURCE:?Set your package or main Go source path}"

"$BUILD/obf-tinygo" --obf-config="$TINYGO_CONFIG" \
  build -scheduler=none -gc=conservative -p=3 \
  -o app_go "$GO_SOURCE"
```

The wrapper obtains whole-program bitcode and a retained baseline link command.
It passes the bitcode through `obf-bc`, lowers the protected output with LLVM 21 `llc`, and repeats the retained link.
It replaces `WORK/main.o` and inserts the runtime archive immediately afterward.

Add `--obf-save-bc=app_go.obf.bc` to retain the protected bitcode.
The saved path must differ from the executable path, and its parent directory must exist.
If saving bitcode fails after the final executable commits, the new executable remains installed.
Use `-x` for command traces and `-work` to retain intermediate work directories.

The wrapper uses configured tools by default.
Tool overrides are `OBF_TINYGO_BIN`, `OBF_BC_BIN`, `OBF_LLC_BIN`, `OBF_LLD_BIN`, and `OBF_LLD_DRIVER`.
Version and closure checks still apply to overrides.

## Final-file binding

`obf-rustc`, the Zig bitcode workflow, and `obf-tinygo` do not bind self-checksum records automatically.
Keep `self_checksum.enabled: false` unless you will bind the final executable manually.

Binding supports Linux x86-64 ELF executables and PIE files, plus native Windows x86-64 PE32+ executables.
Rust `cdylib` support does not imply Windows DLL checksum-binding support.
TinyGo's recognized ARM hosts do not imply ARM checksum-binding support.

Use [Self-Checksum](self-checksum.md) for the supported artifacts, bind order, and platform binder commands.
See [SECURITY.md](../SECURITY.md) for security limits.

## Source reference

The [Rust wrapper](../tools/obf-rustc/obf-rustc.py.in), [TinyGo wrapper](../tools/obf-tinygo/obf-tinygo.py.in),
and [toolchain detection](../cmake/ObfToolchain.cmake) define the integration requirements.
The [Rust direct](../tests/lit/tooling/obf-rustc-direct.ll), [Cargo](../tests/lit/tooling/obf-rustc-cargo.ll),
[Zig component](../tests/lit/tooling/obf-bc-zig-component.ll), and [TinyGo](../tests/lit/tooling/obf-tinygo-e2e.ll)
fixtures show the supported end-to-end routes.
