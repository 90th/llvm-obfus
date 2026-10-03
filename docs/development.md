# Development

[Documentation](README.md) / Development

## Source layout

| Directory | Purpose |
|---|---|
| `include/obf/` | Public and internal C++ headers |
| `lib/frontend/` | YAML parsing and validation |
| `lib/policy/` | Function selection and protection policy |
| `lib/analysis/` | Function metrics and feature analysis |
| `lib/plugin/` | LLVM pass registration and pipeline stages |
| `lib/transforms/` | Native LLVM IR transforms |
| `lib/vm/` | VM candidate analysis, serialization, and interpreter emission |
| `lib/support/` | Shared transform utilities, key schedules, and runtime ABI support |
| `lib/report/` | Policy and transform reports |
| `runtime/` | Entropy, checksum, and authenticated decode runtime |
| `tools/` | Compiler wrappers, checksum binder, audit tools, and recovery analyzers |
| `tests/` | Unit, runtime, and LLVM lit tests |
| `benchmarks/` | Baseline and protected sample programs |
| `cmake/` | Toolchain checks, target definitions, and generated wrappers |

The [protection reference](protection.md#safe-pipeline) describes the safe pipeline.
The [configuration guide](configuration.md) describes function selection and pass permissions.

## Tests

Build the project before you run CTest:

```sh
cmake --build build --parallel 3
ctest --test-dir build --output-on-failure -j 1
```

CTest runs the LLVM lit suite, transform and policy unit tests, runtime atomic tests, decode concurrency tests, and MBA lifetime tests.
It also checks six malformed pending-decode cases through a trap observer.
The configured lit test uses three workers.
Keep outer CTest serial so native runtime tests do not overlap the lit workload.
Windows VM tests can produce large IR modules and use several GiB of committed memory.
Keep free disk space available for managed pagefile growth.
Record the system commit limit and process allocations when an allocation fails.

The trap observer waits up to two seconds for an illegal-instruction or breakpoint exit.
Process creation occurs before that wait and can add time to the helper's total duration.
On Windows, it disables Windows Error Reporting for the child through inherited `SEM_NOGPFAULTERRORBOX`.
It preserves the other error-mode flags and restores its previous mode after the subprocess exits or fails.
The exception still terminates the child. Other exit codes and timeouts still fail the check.
This matches the observer's existing Linux core-collection control.

Windows phase measurements found a 1.53–1.57-second delay between `C000001D` and process exit with normal crash reporting.
The same diagnostic image exited 0.30–0.61 milliseconds after that exception with reporting disabled.
Rejection execution took less than one millisecond. Parent exit observation took less than two milliseconds.
Historical events also show a 1.97-second crash-report interval for this executable, with `C000001D` recorded within 100 milliseconds of creation.
The original timeout lacks child/parent phase timestamps and a recorded PID.
Its exact timing and any contention contribution remain unknown.
See the [Windows error-mode contract](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-seterrormode).

Run a focused lit selection with the `lit` executable from your build configuration:

```sh
lit -j 3 -sv build/tests --filter='vm-extrema'
```

The hidden-token admission probe prunes unreachable definitions before it assembles each scenario.
It follows the replacement entry point and keeps reachable protected bodies intact.
Membership variants exist only for their own case, not across later targets.
These rules limit full-module copies without reducing token cases or trap-before-effects checks.

On Windows, run `obf-clang-dll-lifecycle-pe` and `obf-clang-dll-output-pe` separately with three lit workers for focused native DLL checks.
They check protected constructors and `DllMain` callbacks, decoded strings, return values, effects, exact exports, rebasing, and joined unload cycles.

Individual runtime and unit executables are also available:

```sh
build/obf-unit-tests
build/obf-runtime-atomic-tests
build/obf-runtime-decode-concurrency-tests
build/obf-mba-lifetime-tests
```

On Windows, use the generated executable names with the `.exe` suffix.
Use CTest for platform-specific trap expectations.
See [Contributing](../CONTRIBUTING.md) for code style and submission rules.

## Benchmarks

The core corpus contains `license_demo`, `config_demo`, `vm_workflow_demo`, and `wpo_demo`.
CMake adds Rust, Zig, and TinyGo examples only when their toolchain checks pass.
These targets require a loadable pass plugin.

```sh
cmake --build build --parallel 3 --target obf-benchmarks
cmake --build build --parallel 3 --target obf-benchmarks-e2e
```

The first target builds baseline and protected artifacts.
The second checks results and output against each program's contract.
It also checks invalid license inputs.
Matching program results and output does not prove resistance to reverse engineering.

See the [benchmark corpus](../benchmarks/README.md) for artifact names and fixed-seed builds.

## Audits and recovery analysis

Run these opt-in targets separately:

```sh
cmake --build build --parallel 3 --target obf-audit-benchmarks
cmake --build build --parallel 3 --target obf-re-harness
cmake --build build --parallel 3 --target obf-re-harness-binary
cmake --build build --parallel 3 --target obf-seed-diversity
```

- `obf-audit-benchmarks` checks the built benchmark artifacts for configured exposure rules.
- `obf-re-harness` analyzes emitted IR for three core benchmarks.
- `obf-re-harness-binary` analyzes selected final binary pairs and checks positive and negative controls.
- `obf-seed-diversity` compares selected artifacts across fixed seeds.

The IR, binary, and diversity targets use `license_demo`, `config_demo`, and `vm_workflow_demo`.
They do not cover the complete optional language corpus.

The binary analyzer measures static structural evidence.
It does not execute the inputs or recover their algorithms.
Its current input scope is ELF64 little-endian x86-64 executables and shared-object-format images.
A reported VM candidate does not prove that the analyzer recovered a unique VM or measured security strength.

`obf-re-harness-binary-seeds` performs a separate multiseed build and analysis sweep.
It can take substantial time.
Before you run it on a resource-limited machine, inspect the [multiseed controller](../tools/obf-re-harness/verify_binary_recovery_multiseed.py).

Keep source-assisted analysis separate from binary-only analysis.
Record false positives, analysis limits, artifact hashes, and method versions with each result.
Compiler coverage reports use a separate stage ledger, not recovery scores or native execution claims.
Report contracts compare ABI rejection and regional emission with the actual pipeline.
See [capture commands and schema boundaries](usage.md#compiler-coverage-reports).
The [security contract](../SECURITY.md) defines guarantees independently of these scores.
