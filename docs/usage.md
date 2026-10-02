# Use llvm-obfus

[Documentation](README.md) · [Build](building.md) · [Configuration](configuration.md) · [Frontend workflows](frontends.md)

## Choose a route

| Input | Recommended route | Final-link responsibility |
|---|---|---|
| C | `obf-clang` | Wrapper links the matching runtime and binds supported self-checksum records |
| C++ | `obf-clang++` | Same wrapper contract, with C++ driver mode |
| LLVM `.bc` | `obf-bc` | You compile, link the runtime, and bind records when required |
| C/C++ Full LTO or ThinLTO | Managed C/C++ wrapper route | Wrapper validates inputs and loads the backend plugin |
| Rust, Zig, TinyGo | [Frontend workflows](frontends.md) | Follow the frontend-specific runtime and binding instructions |

Run the examples from the repository root after a [build](building.md).
Use the LLVM tools from that build's SDK.
The examples use Linux paths unless a section states otherwise.

## C quick start

This complete example creates its own source and configuration files.
The configuration requests `strong_vm` for `protected_value`.

```sh
mkdir -p build/usage-demo
cat > build/usage-demo/sample.c <<'EOF'
__attribute__((noinline))
unsigned protected_value(unsigned value) {
    return value * 7u + 3u;
}

int main(int argc, char **argv) {
    (void)argv;
    const unsigned value = (unsigned)argc;
    return protected_value(value) != value * 7u + 3u;
}
EOF

cat > build/usage-demo/protect.yaml <<'EOF'
frontend: generic
profile: standard
seed: 20260817
default_level: none
targets:
  - match: protected_value
    level: strong_vm
self_checksum:
  enabled: false
EOF

build/obf-clang -O1 -fno-inline \
  --obf-config=build/usage-demo/protect.yaml \
  build/usage-demo/sample.c -o build/usage-demo/sample
build/usage-demo/sample
```

The program returns zero when the protected calculation gives the expected result.
This is a behavior check, not a security measurement.

`default_level: none` does not guarantee that unlisted functions remain unprotected.
Automatic function selection and minimum protection requirements can still protect them.
Related callers can also receive protection.
An explicit `none` request cannot bypass those minimum requirements.
See [Configuration](configuration.md) for selection precedence and [Protection](protection.md) for the protection limits.

### Wrapper configuration and seed

Pass `--obf-config=<file>` directly to the wrapper, or set `OBF_CONFIG` in the environment.
The wrapper passes the selected path to the compiler through `OBF_CONFIG`.
Do not place `--obf-config` inside a compiler configuration file or response file.

Use a nonzero decimal `OBF_SEED` to override the YAML seed for the compiler invocation.

```sh
OBF_SEED=20260818 build/obf-clang -O1 -fno-inline \
  --obf-config=build/usage-demo/protect.yaml \
  build/usage-demo/sample.c -o build/usage-demo/sample-seed
```

The C/C++ wrapper accepts `--obf-config`, not `--obf-seed`.
Use `OBF_SEED` for this route.
A fixed seed does not guarantee identical binaries across different tools, inputs, or build settings.

### Separate compilation and linking

The wrapper loads the frontend plugin for compilation.
It adds `libobf_runtime.a` from the same build for final links.
Compile-only actions do not link the runtime.

```sh
build/obf-clang -O1 -fno-inline \
  --obf-config=build/usage-demo/protect.yaml \
  -c build/usage-demo/sample.c -o build/usage-demo/sample.o
build/obf-clang --obf-config=build/usage-demo/protect.yaml \
  build/usage-demo/sample.o -o build/usage-demo/sample-object
```

Use the same plugin build and its runtime archive throughout the application build.
The archive contains the entropy-anchor and authenticated-decoder support.
See the [Runtime contract](../runtime/README.md) for runtime behavior and ABI details.

## C++ use

Use `obf-clang++` for C++ compilation and final linking.
Configuration selectors match LLVM IR function names, not C++ source spellings.
Use `extern "C"` linkage for a stable unmangled selector, or specify the actual mangled LLVM name.

For example, this definition matches the quick-start selector `protected_value`:

```cpp
extern "C" __attribute__((noinline))
unsigned protected_value(unsigned value) {
    return value * 7u + 3u;
}
```

For your application, create `app.cpp` and `app.yaml` with matching function selectors.
Then use:

```sh
build/obf-clang++ -std=c++23 -O1 -fno-inline \
  --obf-config=app.yaml app.cpp -o app
```

An unmangled YAML selector will not match a normal mangled C++ function.
Source annotations avoid the need to spell that function's mangled name.

## Source annotations

Add an annotation to a C or C++ function definition.
The generic frontend reads Clang's `llvm.global.annotations` entries.

```c
#if defined(__clang__)
#define OBF_PROTECT(level) __attribute__((annotate("obf:" level)))
#else
#define OBF_PROTECT(level)
#endif

OBF_PROTECT("strong_vm")
unsigned protected_value(unsigned value) {
    return value * 7u + 3u;
}
```

Accepted levels are `none`, `light`, `strong`, `vm`, and `strong_vm`.
An explicit YAML override takes precedence over an annotation.
An annotation takes precedence over a YAML target rule.
Minimum-security floors and orchestrator promotions can still raise the selected level.

Loading the plugin alone does not activate its automatic compiler callbacks.
Use a configuration file, or set `OBF_ENABLE=1` for an annotation-only invocation.
For example, after you add the annotation to the quick-start source, use:

```sh
OBF_ENABLE=1 build/obf-clang -O1 -fno-inline \
  build/usage-demo/sample.c -o build/usage-demo/sample-annotated
```

The macro has no effect under a non-Clang compiler.
Do not use that fallback as evidence that another compiler applied protection.

## Direct Clang use

For a non-LTO Linux build, set the configuration, load the plugin, and link the runtime yourself.
The following commands reuse the quick-start files.

```sh
OBF_CONFIG=build/usage-demo/protect.yaml \
clang -O1 -fno-inline -fpass-plugin=build/obf_plugin.so \
  -c build/usage-demo/sample.c -o build/usage-demo/direct.o
clang build/usage-demo/direct.o build/libobf_runtime.a \
  -o build/usage-demo/direct
```

For C++, use the matching `clang++` for compilation and final linking.
For self-checksum records, follow the [manual finalization rules](#self-checksum-finalization) below.

### Windows plugin choice

Use `build\obf-clang.cmd` and `build\obf-clang++.cmd` when possible.
For direct compilation, load `obf_clang_plugin.dll` into the configured exported `clang.exe`.
For direct `opt`, load `obf_plugin.dll` into the configured exported `opt.exe`.

These DLLs are not interchangeable.
Each DLL imports LLVM from its matching host and import library.
The Windows C++ wrapper invokes the canonical `clang.exe` with `--driver-mode=g++`.
It does not load the plugin into a separate `clang++.exe`.
See [Windows build](building.md#windows-build) for host setup.

## Standalone LLVM bitcode

`obf-bc` accepts exactly one `.bc` input, an explicit configuration, and a distinct `.bc` output.
It applies `obf-safe-pipeline`, then runs LLVM verification before it installs the output.
It does not compile or link the application.

This example uses checked-in source and configuration files.
The configuration selects `protected_value` with `light` protection.

```sh
clang -O1 -fno-inline -fno-inline-functions -fno-builtin-strcmp \
  -emit-llvm -c tests/lit/Inputs/obf-bc-e2e.c -o build/module.bc
build/obf-bc --obf-config=tests/lit/Inputs/obf-bc-e2e.yaml \
  --obf-seed=20260817 build/module.bc -o build/module.obf.bc
clang build/module.obf.bc build/libobf_runtime.a -o build/module
build/module
```

The example prints `sum=77`.
Use bitcode that the configured LLVM tools can parse and compile.
For frontend-specific bitcode, also follow the [Frontend workflows](frontends.md) compatibility rules.

The input, configuration, and plugin must be regular files.
The output directory must exist, and an existing output must be a regular file.
The wrapper rejects input/output aliases and unsupported command-line options.
Use `--obf-seed` with a nonzero decimal integer for an explicit seed on this route.

The wrapper stages the transformed output and verifies it before replacement.
Handled interruptions before commit trigger cleanup and, when replacement occurred, an attempt to restore the previous output.
Filesystem errors can prevent cleanup or restoration.
Do not treat this as crash recovery for every process or storage failure.

On Windows, use `build\obf-bc.cmd`.
It loads `obf_plugin.dll` into the exported `opt.exe`.

### Direct opt use

On Linux, you can select the same pipeline directly:

```sh
opt -load-pass-plugin=build/obf_plugin.so \
  --obf-config=tests/lit/Inputs/obf-bc-e2e.yaml \
  --obf-seed=20260817 -passes=obf-safe-pipeline \
  build/module.bc -o build/module.opt.bc
opt -passes=verify -disable-output build/module.opt.bc
```

Direct `opt` use does not provide the bitcode wrapper's staged-output workflow.
It also does not link the runtime or bind final self-checksum records.

On Windows, set `OBF_CONFIG` and `OBF_SEED` instead of passing plugin-owned options to raw `opt.exe`.
The `obf-opt.cmd` launcher maps `--obf-config`, `--obf-seed`, `--obf-audit-out`, and `--obf-enable` to environment variables.
That launcher does not load a plugin or select a pipeline for you.

## Managed Full LTO and ThinLTO

Use the C/C++ wrappers for the managed LTO contract.
It requires an ELF target and a non-Windows host.
The wrapper loads the plugin in both the frontend and the linker backend.
It uses the `ld.lld` reported by configured Clang and requires equal reported Clang and LLD versions.

The following commands reuse the quick-start source and policy:

```sh
build/obf-clang -O2 -flto=thin \
  --obf-config=build/usage-demo/protect.yaml \
  -c build/usage-demo/sample.c -o build/usage-demo/sample.thin.o
build/obf-clang -O2 --obf-config=build/usage-demo/protect.yaml \
  build/usage-demo/sample.thin.o -o build/usage-demo/sample-thin
```

Use `-flto` or `-flto=full` instead of `-flto=thin` for Full LTO.
The wrapper detects bitcode in object and archive inputs.
An object/archive final link does not need to repeat `-flto`.
You can also compile and link source with LTO in one wrapper invocation.

### Retained policy and backend finalization

Pre-link bitcode retains its selected policy, original selectors, explicit exclusions, seeds, and VM roles.
The backend validates existing protection instead of applying VM lowering twice.
It reevaluates retained native exclusions when protected callee definitions become visible.
New orchestrator promotions receive protection without repeating transforms on already-protected bodies.

Protected LTO code can retain an unresolved guard symbol until the linker backend validates its protection.
If the required backend does not run, the final link fails.
This also applies to shared-library links that retain the guard.
Do not define the guard or suppress the link error to bypass validation.

Use the same effective configuration, seed, and protection options at pre-link compilation and final linking.
Rebuild protected bitcode after you change those settings.
The backend rejects incompatible retained configuration or seed identities.

For O0 backend links, the wrapper supplies `obf-lto-finalize,verify` as an explicit finalization pipeline.
This addresses the missing default ThinLTO plugin callbacks at O0 in LLVM 22.
The backend also prepares eligible promotable locals before it lowers new O0 targets.
It does not raise the requested optimization level to obtain those callbacks.

### ThinLTO cache

You can retain a user cache and its pruning policy:

```sh
build/obf-clang -O2 --obf-config=build/usage-demo/protect.yaml \
  -Wl,--thinlto-cache-dir=build/thinlto-cache \
  build/usage-demo/sample.thin.o -o build/usage-demo/sample-cached
```

The wrapper selects a subdirectory keyed by plugin contents, configuration path and contents, and the `OBF_SEED` environment value.
It validates actual linker inputs before backend processing or cache lookup.
This also covers temporary bitcode from combined compile-and-link commands.
A compiler configuration tail must not override the managed cache namespace or backend pipeline.

### Input and policy limits

Managed LTO requires an in-process native LLD backend.
It rejects:

- Non-ELF targets and Windows-hosted final LTO links.
- Unsupported linker selections or linker-routing overrides.
- Conflicting custom pipelines. The supported explicit pipeline is `obf-lto-finalize,verify`.
- Index-only, distributed, remote-compiler, single-module, and emit-IR/assembly LTO routes.
- Fat-LTO native objects and fat-LTO archive members.
- Bitcode objects or archives hidden through linker scripts.
- Linker-script layouts whose complete input set the wrapper cannot prove.
- Implicit native `.deplibs` inputs and nonempty bitcode `llvm.dependent-libraries` metadata, including archive members.
- Required exact protection targets without bitcode definitions.
- Selected protection targets with competing native definitions, including native definitions alongside unused archive bitcode.

Pass bitcode objects and archives directly to the linker.
Remove dependent-library metadata and pass the complete library set explicitly.
Simple native library-wrapper scripts with direct filenames remain supported.
Move script `-l` operands to the linker command line.
Managed script validation rejects `INCLUDE`, `STARTUP`, and `SEARCH_DIR`.

### Direct LTO integration

Frontend `-fpass-plugin` loading alone is not an LTO protection contract.
A direct integration must also load the backend plugin and provide equivalent policy and whole-input validation.
Exact ThinLTO selectors require that whole-input validation.
Do not set the private validation marker without performing those checks on the actual complete input set.

Use the wrapper unless your integration implements the same linker, pipeline, policy, cache, and input checks.
The [LTO integration test](../tests/lit/tooling/obf-clang-lto-linker-plugin.ll) shows lower-level plugin commands.
Those commands are not a replacement for the managed contract.

## Self-checksum finalization

The C/C++ wrappers automatically bind records for supported final executable links.
An active `self_checksum` final wrapper link requires an explicit `-o <path>`.
Objects and static archives can contain `UNBOUND` records.
Bind those records only after the final executable link.

The supported v1 executable workflows are Linux x86-64 ELF/PIE and native Windows x86-64 PE32+ EXE.
Windows DLL binding is not supported.
Other architectures and formats do not provide the supported v1 bound workflow.
An active Windows self-checksum final wrapper link on a non-Windows host is unsupported.
The wrapper rejects it and does not auto-finalize inherited PE records there.

Direct Clang, direct `opt`, `obf-bc`, Rust, Zig, and TinyGo workflows require manual binding when they produce supported records.
For a manual ELF link, disable the GNU build ID before binding.
For example, if `protected.o` contains required self-checksum records, use:

```sh
clang protected.o build/libobf_runtime.a -Wl,--build-id=none -o protected-app
build/obf-checksum-bind protected-app
```

On Windows, use `link -> bind -> sign`.
Run `build\obf-checksum-bind.exe` on the final EXE before embedded Authenticode signing.
The binder rejects a nonzero PE Security directory.
Do not run the binder on an object, static archive, or DLL.

`--probe` inspects record slots without modifying the file.
A successful probe does not prove that binding will succeed.
See [Self-checksum binding](self-checksum.md) for exit codes, binary rules, record layouts, and relocation restrictions.
See [Security](../SECURITY.md#self-checksum-security-contract) for the security contract.
