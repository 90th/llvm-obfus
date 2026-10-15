# Development

[Documentation](README.md) / Development

## Source layout

| Directory | Purpose |
|---|---|
| `include/obf/` | Public C/C++ API and internal C++ headers |
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

## String-copy export integration

`include/obf/string_copy.h` defines the public C/C++ declarations and status constants.
`include/obf/transforms/string_copy.h` and `lib/transforms/string_copy.cpp` implement declaration preparation, authentication binding, and final validation.
The supported routes are native Linux x86-64 glibc and Windows x64 MSVC PE/COFF.
Full LTO and ThinLTO reject declared exports.
See the [usage guide](usage.md#authenticated-cross-dso-string-copies) for the API and caller preconditions.

Prepare exports before policy selection and before the native ownership snapshot.
The safe-pipeline entry also prepares exports.
`prepare_string_copy_exports` reads source annotations and validates sources, IDs, native targets, and accessor signatures.
It creates omitted accessor declarations when Clang drops unused source prototypes.
It rejects existing accessor bodies instead of replacing arbitrary code.
Named metadata makes repeated preparation idempotent.

Each source retains `obf.string_copy.source` metadata with its private payload helper, accessor, ID, and full source length.
Value metadata keeps identity independent of generated symbol spelling.
The generated accessor selects an ID and checks capacity before it calls the source-specific private payload helper.
The helper has signature `i32(ptr source, ptr destination)` and starts as an undefined declaration.
The accessor passes the original source address to preserve dependencies through pre-VM ownership capture.
Query and ordinary error paths do not call the payload helper.
The accessor does not allocate, truncate, or throw across its C ABI.

The string encoder recognizes declared sources without changing their original protection obligations.
It supports empty text and rejects ephemeral, inline, non-authenticated, or unapplied export plans.
Unsupported sharing, source uses, and configured limits remain build failures.
Bind authentication only after a supported authenticated lazy or constructor plan succeeds.
`bind_string_copy_authentication` binds the existing producer-private descriptor bundle.
Define the payload helper after optimization and VM lowering.
Its straight-line body calls the configured V3 decoder, copies the decoder result with ordinary fixed-length `memcpy`, then returns `OBF_STRING_COPY_OK`.
The bound helper uses trusted descriptor, topology, length, and binding constants.
It does not trust a caller-supplied source address.
Keep the helper internal, nonpreemptible, `nounwind`, and `noinline`.
It adds no buffers, allocations, shared keys, or runtime decoder ABI changes.

Windows accessor declarations use `__declspec(dllexport)`.
VM wrapper replacement preserves this storage class, while internal implementations and source helpers use default DLL storage.
Final validation checks the live accessor export and producer-private V3 bundle globals.
After the actual COFF link, `obf-native-link` compares the PE export directory with private runtime addresses from the linker MAP.
It rejects private names, aliased addresses, ordinal-only exports, and private runtime forwarders.
It follows bounded executable `E9 rel32` thunk chains to detect MSVC incremental aliases without disabling incremental links.
The existing rejected-output path removes the primary image.

All runtime ABI definitions in `libobf_runtime.a` use `OBF_HIDDEN` on ELF, including the entropy anchor and five entropy-pair functions.
The entropy initializer pass changes the anchor value without changing its hidden visibility.
User-module declarations remain unchanged. The runtime lit suite checks resolution through `lli --extra-object`.
After a final ELF link, `obf-native-link` checks defined `.dynsym` symbols against private runtime addresses.
It uses the actual LLD or GNU ld map and available output symbols, including map authority for stripped outputs.
It rejects runtime-prefix names, direct function or data aliases, and executable x86 `E9 rel32` or `EB rel8` thunk routes.
The check follows at most 32 jumps with section, file, displacement, and cycle bounds.
Other instructions and uncertain routes stop traversal. This check is not a general code-equivalence or disassembly proof.
Partial ELF links retain the existing ownership reconciliation path.


Run `validate_string_copy_exports` before security-gate completion.
Reject missing bindings and inconsistent source, accessor, ID, length, or payload paths.
Existing policy floors can promote requested `none` selections. Validate the resulting obligations, not the requested level alone.
Inspect the actual straight-line helper, its V3 decoder call, copy ordering, and trusted constants.
Follow returned function-pointer graphs through shared VM resolvers, including integer-encoded targets.
Self-reported flags do not establish authentication.
Coverage events retain source, accessor, and ID evidence.
Rejection ledgers use `code=` identifiers for source, ABI, strategy, and native-route failures.
Tests check these identifiers, not full diagnostic sentences.
Compiler validation does not prove native execution or producer provenance to another image.

Every successful export must authenticate, including repeated copies from constructor-backed storage.
Queries and ordinary error paths must not report payload success.
Authentication failure must trap before destination writes.
Preserve existing decoder waiting semantics, VM admission, plaintext gates, image-local static ownership, and raw-manifest restrictions.
Do not add a foreign-static exemption or downgrade requested `vm` or `strong_vm` policies.

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

The `vm-expanded` and `vm-opcode-scramble` regressions run the original and virtualized modules.
Coverage reports must confirm whole-function VM admission and emission for every selected target.
Do not pin generated pointer slots or basic-block order.

The hidden-token admission probe prunes unreachable definitions before it assembles each scenario.
It follows the replacement entry point and keeps reachable protected bodies intact.
Membership variants exist only for their own case, not across later targets.
These rules limit full-module copies without reducing token cases or trap-before-effects checks.

On Linux x86-64 glibc, run `obf-clang-cxx-shared-lifecycle-elf` for focused C++ shared-library lifecycle checks.
It covers O0/O2 with `vm` and `strong_vm`, independent raw controls, authenticated decoding, and bound checksums.
It checks exact construction, cleanup, retry, TLS destruction, and final destruction events.
Joined unload, TLS retention, and explicit `RTLD_NODELETE` use separate mapping checks.
Actual unmapping must precede a fresh initialization check.
The harness saves compiler ledgers and native execution evidence in isolated `/tmp` directories.
Other Linux loaders do not run this glibc-specific unload regression.

On native Linux x86-64 glibc, run `obf-clang-cross-dso-string-copy-elf` for the copy-only export contract.
The `tests/lit/Inputs/cross_dso_string_copy.py` harness uses isolated `/var/tmp` directories and bounded native processes.
Use O0/O2, independent `vm`/`strong_vm` consumers, distinct producer build material, and raw semantic controls.
Raw controls handwrite the same C ABI independently. They are not a plaintext fallback in the public header.
The fixture disables inlining, vectorization, and loop unrolling to keep scalar byte-reader admission explicit.
It still compiles both O0 and O2 and requires whole-function VM emission.
Check lazy and constructor-backed `vm` and `strong_vm` producer accessors through their actual resolver paths.
Disable constructor fallback for lazy producer rows.
Check initial private status and completion before any application copy, including empty sources.
Queries and ordinary errors must leave that cold state unchanged.
Check exact bytes, required sizes, NUL, statuses, and unchanged destination sentinels on ordinary rejection.
Cover empty, lazy, and permitted constructor-backed sources.
Require actual producer-private authentication before every successful copy, not constructor-only initialization.
Include a C++ function-local static immutable source alongside file-local and empty sources.
Check `.dynsym` exports with both `ld.lld` and GNU ld. Legitimate accessors must pass without runtime exports.
Pair each managed export rejection with a raw link of the same protected object and runtime archive.
Verify the raw exported name, address, and decoder thunk route before requiring native-link rejection and output removal.
Forced per-source helper and payload exports must fail in the real linker, not the final export check.

After one valid copy, corrupt the primary, secondary, and empty sources.
Change only data: decoded cache, tag, ciphertext, or descriptor length/version.
The next payload copy must trap before shared destination or consumer effects change.
Queries, short-capacity calls, and unknown IDs must retain their ordinary status behavior without certifying authentication.
Do not patch code, expose production test callbacks, or export keys and descriptors.
For ELF mutation, verify the exact producer's readable, non-executable `PT_LOAD` bounds and actual mapping permissions.
Loader-owned BSS tails can use anonymous mappings. A pathname alone does not establish those bounds.

Check handle-scoped accessor ownership and incompatible or missing API versions.
Reject a deliberately mismatched accessor and retained producer before any transfer effects.
Clear callable pointers, drain calls, and verify actual producer unmapping before the consumer reads the caller-owned copy again.
Keep the copy buffer and consumer code live.
Negative builds must retain strict VM failures, required imported-static rejection, and the raw-manifest `protected` ban.
Compiler ledgers establish emission and bindings. Native observations establish only the exercised returns, bytes, effects, traps, and lifetimes.

On native Windows x64, run `obf-clang-cross-dll-string-copy-pe` for the matching DLL contract.
The `tests/lit/Inputs/cross_dll_string_copy.py` harness keeps scratch and evidence under the Windows temporary directory.
Use the same O0/O2 and `vm`/`strong_vm` matrix with independent producer DLLs, consumer DLLs, and raw controls.
Include function-local static arrays and normal CRT constructor-backed sources.
Check exact PE export sets and reject forced private runtime exports through direct, `.def`, and ordinal-only routes.
Use LLD, MSVC nonincremental, and MSVC incremental links with paired raw export controls.
The incremental control must keep a legitimate public accessor thunk while rejecting private decoder aliases and ordinal-only exports.
Data-only corruption must produce the native authentication trap with unchanged caller-owned destination bytes and consumer effects.
The parent process must observe the child trap and shared destination, not infer success from a generic nonzero exit.
Keep application queries and copies outside `DllMain`, `.CRT$XL*` callbacks, and loader-controlled construction or destruction.
After final `FreeLibrary`, require `GetModuleHandleW == NULL` and actual mapping removal before reading surviving copies.


On Windows, run `obf-clang-dll-lifecycle-pe` and `obf-clang-dll-output-pe` separately with three lit workers for focused native DLL checks.
They check protected constructors and `DllMain` callbacks, decoded strings, return values, effects, exact exports, rebasing, and joined unload cycles.

Run `obf-clang-cxx-shared-lifecycle-pe` for native Windows x64 C++ lifetime and unload checks.
It covers O0/O2 with `vm` and `strong_vm`, plus independent raw DLL controls.
Each of six modes runs three cycles: runtime, TLS, FLS, in-flight work, process termination, and failed attachment.
The host checks exact events, returns, effects, thread ownership, retry, member rollback, and LIFO destruction.
Compiler ledgers require whole-function VM emission and protected native EH/SEH fallbacks.
PE checks cover exact exports, bound checksum records, `.pdata`, and referenced unwind data.
Live `RtlLookupFunctionEntry` checks cover the EH/SEH exports.
Ordinary module references retain in-flight work and native TLS workers without pinning.
Explicit FLS drain lets a host thread outlive verified image removal without a DLL callback.
Process termination checks terminating-thread cleanup and skipped dormant-worker TLS destruction separately.
`GetModuleHandleW` and `VirtualQuery` must prove removal before the next fresh load.
The harness saves `result.json`, command logs, and compiler ledgers under the Windows temporary directory.
These checks serialize protected event calls. They do not establish decoder-contention behavior under the loader lock.

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
