# Protection reference

[Documentation](README.md) · [Configuration](configuration.md) · [Usage](usage.md)

The plugin transforms selected LLVM IR functions and data.
Protection levels are `none`, `light`, `strong`, `vm`, and `strong_vm`.
Policy, enabled passes, supported IR shapes, and quotas determine the result.
A level does not guarantee that every instruction receives every transform.

Use this guide for transform behavior and limits:

- [VM execution](#vm-execution)
- [Arithmetic and control flow](#arithmetic-and-control-flow)
- [Strings](#strings)
- [Constants](#constants)
- [Seeds, keys, and runtime checks](#seeds-keys-and-runtime-checks)
- [Self-checksum](#self-checksum)
- [Safe pipeline](#safe-pipeline)

The project combines obfuscation with selected runtime integrity checks.
It does not promise a measured increase in recovery cost or prevent tracing, memory inspection, or arbitrary binary changes.
The [security contracts](../SECURITY.md) define the checked scope and reporting rules.

## VM execution

### VM lowering and build checks

`vm` and `strong_vm` lower supported functions into bytecode-backed execution paths.
The interface wrapper keeps the selected function's linkage, visibility, and DLL export storage class.
The implementation has internal linkage and default visibility, without DLL export or import storage classes.

Candidate analysis rejects unsupported IR, not only exception handlers.
Important limits include:

- Variadic functions and non-integral function pointer address spaces.
- EH pads and unsupported terminators, including `invoke`, `resume`, and Windows EH terminators.
- Inline assembly, operand bundles, and `musttail` calls.
- Volatile or atomic memory operations and dynamic memory-intrinsic lengths.
- Unsupported types, intrinsics, and virtual instruction counts above `vm.max_virtual_instructions`.

Ordinary `vm` can leave an unsupported candidate in native code.
With VM eligibility enabled, `strong_vm` tries whole-function lowering, then supported regional extraction.
For a VM-eligible `strong_vm` function, the final build check fails if no VM binding covers the function.

Feature restrictions can disable VM eligibility before lowering.
An exact generic `strong_vm` override with exception edges or inline assembly keeps its level but disables VM eligibility.
The build check skips functions whose policy disables VM eligibility.
The level label alone does not prove VM execution.
See [feature restrictions](configuration.md#feature-restrictions) for the policy rules.

The VM boundary also checks the function ABI and incoming calls.
It rejects parameters such as `byval`, `sret`, `inalloca`, and other unsupported ABI-changing attributes.
Incoming `invoke`, `callbr`, `musttail`, operand-bundle calls, and ABI mismatches cannot use ordinary call rewriting.
`strong_vm`, `fortress`, and `lab` require a strict VM boundary and reject these cases.

Plugin-generated VM implementations check registered caller tokens before executing bytecode.
An unregistered token traps before protected side effects.
The bytecode entry-state value alone does not pass this check.
The low-level virtualization API retains its explicit disabled-handshake mode.
These embedded token checks are not caller authentication against an attacker who controls the binary.

### Bytecode integrity and physical anchors

The VM checks each instruction when execution reaches it.
It compares all decoded header chunks, including padding, against expected values.
Before handler effects, it also checks the full 64-bit post-header state and every encoded successor target.
Successor checks cover the exact dispatch index and full 64-bit entry state, including edges that execution does not select.
Handlers reuse the checked successor values instead of reading the encoded payloads again.

A failed check traps before the affected call, store, edge assignment, or return.
Volatile bytecode loads preserve runtime tamper observation after optimization.
Return encoding also combines the return key with the registered token.
Rolling decode and sampled probes provide diffusion, not cryptographic authentication.

Each physical anchor stores a seeded, reversible byte permutation with per-byte XOR masks.
The decoder restores canonical ciphertext before the integrity checks.
Copies retain the same payload length and need no runtime decode buffer.
Distinct copies can increase total linked data size because their contents cannot merge.

Physical anchors change data-reference relationships. They do not hide all root references or keep keys secret.
The checks do not authenticate future unexecuted headers, the complete program, or simultaneous changes to code and expected values.
See the [VM bytecode integrity contract](../SECURITY.md#vm-bytecode-integrity-contract) for the canonical scope and limits.

### LLVM semantics and helper ABI

The VM supports scalar `llvm.umin`, `llvm.smin`, `llvm.umax`, and `llvm.smax`.
Each extremum uses two operand freezes, one integer comparison, and one select: four virtual instructions.
Vector extremum intrinsics remain unsupported.
Ordered comparisons at LLVM's maximum integer width fail VM lowering because the operation needs a wider integer type.

Vector select conditions remain lane-wise LLVM selects.
When a scalar select handler introduces a branch, it freezes the condition first.
Do not extend this rule to all VM branches or all poison behavior.
The transforms use specific freeze and operand-reuse rules, not a general promise to remove undefined behavior.

Generated wrappers, implementations, and entry thunks use the selected function's address space and pointer width.
Island, decoy, and split helpers accept state pointers in the module's alloca address space.
Relevant execution attributes include target features, denormal modes, and stack-probe settings.
Helpers keep attributes for their own ABI rather than copying every source attribute.
Body replacement drops invalidated memory, synchronization, progress, and inlining promises.

In-place VM rewriting keeps `no_caller_saved_registers` and `no_callee_saved_registers` on the original function.
Helpers with different signatures do not inherit these ABI attributes.
Ordinary `vm` uses width-specific shared seed resolvers and aligned monotonic atomic target-cache accesses where supported.
The target cache does not publish unrelated runtime state.
Unsupported atomic integer widths use local target decoding. `strong_vm` always uses local decoding and no shared seed resolver.

## Arithmetic and control flow

### MBA and substitution

Mixed Boolean-arithmetic (MBA) helpers diversify `add`, `sub`, `xor`, and supported multiplication forms.
Their shapes include linear identities, odd-multiplier affine encodings, polynomial zero terms, and constant-multiplication decomposition.
Polynomial and multiplication families default to depth 3 or greater, but explicit MBA options can change them.
Unsigned division and remainder rewrites require scalar, nonzero power-of-two constant divisors and an enabled division family.

A depth-derived budget limits recursive expansion. An explicit instruction-budget option can change it.
When recursive expansion exhausts the budget, the engine emits a plain LLVM operation.
The tracker counts expansion costs, not every emitted instruction. It is not an exact total IR or machine-code instruction limit.

`instruction_substitution` rewrites supported scalar integer `and`, `or`, and `xor` sites.
Each site selects one of two identities and can add an MBA opaque zero.
Operand-reuse support stabilizes duplicated operands and restores poison propagation where required.

Later scalar optimization can simplify MBA identities and opaque zeros.
The managed optimized pipelines place obfuscation late, but a separate optimization pipeline can still remove shapes.
Larger depths and surviving opaque zeros can increase code size and hot-path work.
Select functions carefully when compilation cost or runtime latency matters.

### Equality lowering

`zero_comparison` lowers scalar integer equality and inequality, supported integral-pointer equality, and selected integer-result selects.
It uses XOR and zero/nonzero arithmetic. The current pass does not add entropy-masked comparisons.

Libc lowering supports direct, ABI-valid `strcmp`, `strncmp`, `memcmp`, and `bcmp` calls.
Every result use must compare the call result with zero for equality or inequality.
`memcmp`, `bcmp`, and `strncmp` need a constant length within `zero_comparison.max_unroll_bytes`.
`strcmp` needs a known constant-string bound within that limit.
The default limit is 64 bytes.

`memcmp` and `bcmp` use bytewise XOR/OR reduction.
`strcmp` and `strncmp` use short-circuit control flow and stop at the first mismatch or terminating NUL.
Thus, string equality lowering is not uniformly branch-free or constant-time.
It preserves equality semantics, not the original call's ordering result for arbitrary consumers.

### Structural transforms and indirect dispatch

The native stages can flatten eligible CFGs, hide global offsets, add opaque predicates, outline helpers, add bogus blocks, and split blocks.
Each stage has its own eligibility rules and quota.
Flattened string decoders keep the CFG state from their definition when later blocks use that value.
They do not substitute the later block's current dispatcher state.

Late `indirect_dispatch` replaces selected conditional branches and switch sites with masked target arithmetic and `indirectbr`.
It derives site material from the protected function seed, function name, and site index.
Targets use same-function `blockaddress` deltas in SSA, not absolute dispatch tables in globals.

The pass skips EH personalities, EH pads, EH terminators, existing `indirectbr`, `callbr`, and `musttail` shapes.
It also skips non-integral program address spaces and sites outside its configured limits.
These skips do not imply a general VM fallback policy.

## Strings

### Decode strategies and plaintext lifetime

`string_encoding` handles supported constant C-string globals referenced by protected functions.
It does not encrypt every global, runtime string, or arbitrary byte array.
Source-global kind, ownership, pointer use, sharing, and options determine the strategy.

| Strategy | Behavior and limit |
|---|---|
| Micro-slots | Non-authenticated byte-XOR decoding produces transient SSA bytes, not a transform-created contiguous plaintext buffer. |
| Local stack decode | Short, proven uses decode into per-use scratch. Authenticated uses call `rt_core_sd3`. |
| Lazy decode | A helper recovers stable storage when a supported use needs it. |
| Constructor decode | A constructor prepares stable storage for supported fallback cases, including forwarding. |

Micro-slot byte loads need supported constant-index addressing.
Direct micro-slot comparisons support `strcmp`, `strncmp`, and `memcmp`, with at most 64 effective bytes.
Unsupported or larger comparisons use another eligible decode strategy, or remain unsupported.
Micro-slot `strcmp` and `strncmp` preserve short-circuit reads.
Micro-slots are disabled when `authenticated_mode` is active.

The short stack strategy currently requires at most eight stored bytes and at most two proven uses.
Authenticated stack decoding volatile-zeroes scratch and descriptor storage after the comparison returns.
Escaping, shared, or weakly proven uses do not qualify for this strategy.
Other levels can use lazy or constructor storage when policy permits it.

These rules do not guarantee physical-register erasure or removal of compiler-generated copies and spills.
Plaintext can remain observable while live, and stable decode storage has a longer lifetime.

### Original ownership and generated data

When transforms move string uses into generated helpers, those uses retain the source function's seed and protection level.
Encoding, reports, and final validation use that original function's string policy.
Generated helpers retain a separate general transform policy.
LTO retains the original ownership obligation through the final gate.

The `strong_vm` gate rejects surviving protected source plaintext, including unsupported globals and forwarding cases.
A selected or reported strategy alone does not satisfy that gate.
Shared unprotected uses and unsupported escapes can therefore fail the build.
A generated-VM forwarding case can use an authenticated constructor strategy.
This is not a promise that all runtime plaintext uses remain local.

Generated ciphertext, build keys, local encoded strings, and VM bytecode have explicit data provenance.
Discovery uses these roles instead of treating every C-string-shaped byte array as source text.
This prevents another string-encoding pass from re-encoding generated binary data.

## Constants

`constant_encoding.mode` supports `off`, `mba_inline`, `keyed_pool`, `auto`, and `all`.

| Mode | Strategy |
|---|---|
| `off` | Do not encode constants. |
| `mba_inline` | Reconstruct eligible integer constants in IR with MBA helpers. |
| `keyed_pool` | Recover eligible constants through keyed, integrity-checked runtime pools. |
| `auto` | Choose pools for repeated values, widths above 32 bits, or uses outside arithmetic, comparisons, and selects. |
| `all` | Choose pools for repeated values or widths above 32 bits. Use inline reconstruction for other eligible sites. |

`auto` does not select its strategy directly from the target level.
Policy still determines which functions reach constant encoding.
The safe pipeline excludes virtualized bodies and `strong_vm` functions from the ordinary constant-encoding stage.

The pass skips zero, one, minus one, constants below the configured width, and unsupported operands.
Scalar pools require at least two selected keyed uses in a function.
Eligible constant tables need protected-only uses.
`all` therefore does not mean every literal or table receives protection.
Decoded pools use stable runtime storage and share the authenticated waiting rules below.

## Seeds, keys, and runtime checks

The effective top-level `seed` feeds deterministic build material.
Function policy seeds also include the normalized module name and LLVM function name.
Site transforms derive more material from those function seeds and site identities.

Authenticated string and keyed-pool build keys derive from the effective top-level seed.
The original owner seed affects string planning, diversification, and site identity. It does not replace the build-key root.
The schedule uses domain-separated BLAKE2s:

```text
build_key(seed) -> function_key(module_id, function_id)
                -> string_site_key or constant_pool_key
                -> encryption_key and MAC_key
```

String function identities describe the protected users of a string.
Constant pools use function ID zero and separate pool identities.
Encryption XORs a BLAKE2s-derived keystream with the payload.
A keyed BLAKE2s tag covers descriptor metadata and ciphertext.
The scheme does not use AES, ChaCha20, HMAC, or SipHash.

The binary embeds the 32-byte build keys in internal globals.
The runtime reconstructs derived keys from those embedded keys.
The entropy anchor supports opaque arithmetic, not secret key storage or authentication-key binding.
Its five accessor variants read the anchor through different arithmetic and memory paths.
Runtime initialization mixes the current anchor with hardware or timestamp input. This input does not bind authentication keys.
MBA out-parameter thunks use cache pointers in the module's alloca address space.

When descriptor, length, topology, tag, phase, or completed-payload validation fails, authenticated decoders trap instead of returning data.
These checks do not provide whole-binary authentication or protect keys from an attacker who controls code or process memory.
There is no hardware token, remote service, or white-box secrecy guarantee.

### Waiting and availability

For each descriptor, one thread owns decoding. Other threads wait for that thread to finish.
Waiters do not treat an exceeded retry count as evidence of tampering.
After bounded retry batches, they pause with Windows `Sleep(1)` or POSIX `poll(NULL, 0, 1)`.
A delayed decoding thread does not bypass verification or cause a timeout-based tamper rejection.

If decoding never finishes but its pending state remains valid, other threads can wait indefinitely.
The runtime does not guarantee scheduler fairness or recovery after the decoding thread stops.
It also does not guarantee key erasure when a thread is canceled.
See [authenticated decode waiting](../runtime/README.md#authenticated-decode-waiting) for the canonical publication and validation contract.

## Self-checksum

`self_checksum` adds a runtime dependency on 16 to 32 sampled machine-code bytes.
The compiler creates required `UNBOUND` records. The binder writes expected checksums after the final link.
Execution at a required `UNBOUND` site traps.
A bound site injects the XOR of actual and expected checksums into a protected integer calculation.
Narrow sites truncate that difference and can lose a mismatch.

The v1 hash is not cryptographic. It does not authenticate the complete binary or stop simultaneous code and record changes.
The bound path supports Linux x86-64 ELF executables/PIE and native Windows x86-64 PE32+ executables, not DLLs.
Use the [binding guide](self-checksum.md) for workflows and binary rules.
Use the [self-checksum security contract](../SECURITY.md#self-checksum-security-contract) for limits.

## Safe pipeline

`obf-safe-pipeline` runs these stages in order, subject to policy, eligibility, and quotas:

1. Initialize entropy bindings.
2. Lower `vm` targets and rewrite supported calls.
3. Lower `strong_vm` targets and rewrite supported calls.
4. Encode strings in the post-VM module.
5. Flatten eligible native CFGs.
6. Snapshot source bitwise substitution candidates.
7. Lower zero comparisons.
8. Encode constants.
9. Substitute the saved bitwise sites.
10. Encode global-access offsets.
11. Add opaque predicates.
12. Outline helper shards.
13. Add bogus control flow.
14. Add self-checksum sites.
15. Split eligible blocks, excluding VM and flattened functions.
16. Harden `strong_vm` implementations with opaque offsets, flattening, outlining, substitution, and bogus control flow.
17. Remove CFG-state placeholders.
18. Apply late indirect dispatch to eligible native functions and VM implementations.
19. Enforce protection and symbol-isolation gates.
20. Clean artifacts.

The implementation also handles retained LTO obligations before and after these stages.
Use [usage](usage.md) for the managed native, bitcode, and LTO workflows.
Do not assume that a manually reordered list of standalone passes has the same behavior.

### Cleanup

Artifact cleanup strips debug information and local argument, block, and instruction names.
With `security.strip_release_markers`, it also removes release attributes and annotations, and renames local obfuscation symbols.
LTO obligation markers remain until the mandatory backend finalizer consumes them.
Cleanup does not erase every symbol or remove runtime requirements.

The build generates public runtime ABI names with the default prefix `rt_core_`.
Changing this prefix requires a matching plugin and runtime build.
Configured symbol gates reject leaked obfuscator internals. Release cleanup also rejects external `obf` marker names.
`security.allow_unsafe_config` relaxes selected configuration checks, not the unconditional `strong_vm` final gates.
Do not use it as a promise of protected output.
