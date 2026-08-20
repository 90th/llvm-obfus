# Self-Checksum Binding

## Overview

`self_checksum` provides code-as-data verification for selected functions.
The compiler pass selects an eligible target and records a sample range of 16 to 32 bytes.
The pass leaves expected checksum fields zero and marks records `UNBOUND`.
After final linking, `obf-checksum-bind` calculates expected checksums from final linked machine-code bytes and marks records `BOUND`.
At runtime, protected functions compute checksums over loaded machine-code bytes and compare them with bound values.

## Binding Lifecycle

The self-checksum lifecycle proceeds through four stages:

1. **Compilation and Transformation**
   The compiler pass generates 96-byte `OBSC` v1 records in section `.obfsc.<site_id>` (ELF) or `.obfsc$M` (PE/COFF).
   Each record receives the `REQUIRED` flag (`0x00000001`).
   The expected checksum field remains zero.

2. **Final Link**
   The linker combines object files and static archives into a final executable image.
   Section `.obfsc$M` contributions merge into `.obfsc`.
   The linker resolves record-relative relocations to target code.

3. **Post-Link Binding**
   `obf-checksum-bind` parses the final binary, maps target sample ranges to file bytes, and hashes the machine code.
   The binder writes the calculated hash into the record and sets the `BOUND` flag (`0x00000002`).

4. **Runtime Execution**
   The compiler pass emits a volatile load of the record flags.
   Runtime helper `rt_core_sc0` checks that flags equal `REQUIRED | BOUND` (`0x00000003`).
   Runtime helper `rt_core_cc` hashes loaded machine-code bytes.
   The XOR difference between actual and expected checksums propagates into protected program logic.

Compile-only object files and static archives can contain `UNBOUND` records.
Bind required records before execution reaches a protected site in the final executable.

## Record States

Self-checksum records exist in two states:

- **UNBOUND**: `flags = 0x00000001` (`OBF_SC_FLAG_REQUIRED`). Expected checksum is zero.
- **BOUND**: `flags = 0x00000003` (`OBF_SC_FLAG_REQUIRED | OBF_SC_FLAG_BOUND`). Expected checksum contains the 64-bit rolling hash.

When execution reaches a protected site with an `UNBOUND` required record, `rt_core_sc0` traps.
The validated x86-64 Clang build emits an illegal-instruction trap.

## Record Format

Self-checksum records are stored in dedicated sections.
On ELF, the compiler pass emits records into `.obfsc.<site_id>`, and the binder accepts `.obfsc` or `.obfsc.*` sections.
On PE/COFF, the compiler pass emits records into `.obfsc$M`, and the linker merges them into `.obfsc`.

Each record follows the binary layout below:

| Offset | Size | Field | Description |
|---|---|---|---|
| `0x00` | 4 | `magic` | ASCII bytes `"OBSC"` (`0x4353424f`) |
| `0x04` | 2 | `version` | Record format version (`1`) |
| `0x06` | 2 | `record_size` | Record size in bytes (`96`) |
| `0x08` | 4 | `flags` | Bit 0: `REQUIRED` (`0x1`), Bit 1: `BOUND` (`0x2`) |
| `0x0c` | 4 | `algorithm` | Checksum algorithm (`1` = `rt_core_cc_v1`) |
| `0x10` | 4 | `object_format` | Binary format (`1` = ELF, `2` = PE/COFF) |
| `0x14` | 4 | `machine` | Architecture (`1` = x86-64) |
| `0x18` | 8 | `site_id` | 64-bit diagnostic label (non-unique across translation units) |
| `0x20` | 8 | `target_delta` | Record-relative target displacement |
| `0x28` | 4 | `target_kind` | `1` = `RECORD_REL64`, `2` = `RECORD_REL32` |
| `0x2c` | 4 | `sample_offset` | Byte offset from target function start (`0`) |
| `0x30` | 4 | `sample_size` | Number of sampled bytes (`16` to `32`) |
| `0x34` | 4 | `reserved0` | Reserved field (`0`) |
| `0x38` | 8 | `seed` | 64-bit checksum seed |
| `0x40` | 8 | `expected_checksum` | 64-bit bound hash value |
| `0x48` | 24 | `reserved1` | Reserved padding (`0`) |

`site_id` is a diagnostic label and not a global database key.
Duplicate `site_id` values across translation units are valid.

## Runtime Behavior

Protected functions invoke two runtime helpers from `obf_entropy_anchor.o`:

1. `rt_core_sc0(uint32_t flags)`
   The compiler pass loads the 32-bit `flags` field from the record using a volatile load.
   `rt_core_sc0` verifies that `flags` equals `REQUIRED | BOUND` (`0x00000003`).
   If the required BOUND state is missing when this guard runs, `rt_core_sc0` traps.
   The validated x86-64 Clang build emits an illegal-instruction trap.
2. `rt_core_cc(const void* func_ptr, size_t size, uint64_t seed)`
   Computes a 64-bit rolling hash over `size` loaded machine-code bytes starting at `func_ptr` using `seed`.

The generated protected code loads the expected checksum with a volatile load and computes `actual XOR expected`.
For a 64-bit integer site, the pass injects that 64-bit XOR value into the protected operation.
For a narrower integer site, the pass truncates the XOR value to the site width before injection.
In an untampered binary, `actual` equals `expected`, so the injected value is zero.
A full 64-bit checksum mismatch does not guarantee a nonzero injected value after width truncation.

## Binder Probe

The binder provides a non-destructive inspection mode:

```bash
obf-checksum-bind --probe <binary>
```

Probe parses the image and counts fixed-size record slots in recognized record sections.
It does not inspect each record header or prove that normal binding will succeed.
It does not modify the file.

Exit codes for `--probe`:

- `0`: The active platform binder recognizes the image and finds one or more self-checksum record slots.
- `3`: The active platform binder recognizes the image and finds zero self-checksum record slots.
- `1`: Input reading, image parsing, or record-section validation failed.
- `2`: Command-line usage error.

Binding mode applies the full record and mutation-hazard checks.
Normal binding mode returns:

- `0`: Records were bound successfully, or all existing records were already valid and BOUND.
- `1`: Binding failed, including when no `.obfsc` records exist.
- `2`: Command-line usage error.

## Linux ELF Binding

Linux x86-64 ELF binding operates under these rules:

- **Target Scope**: 64-bit little-endian ELF images. The binder accepts `ET_EXEC` and `ET_DYN` final images. The documented v1 workflow supports executables and PIEs.
- **Section Layout**: The compiler pass emits records into `.obfsc.<site_id>`. The ELF binder accepts record sections named `.obfsc` and `.obfsc.*`.
- **Section Flags**: Each `.obfsc` or `.obfsc.*` record section must have `SHF_ALLOC` set.
  It must not have `SHF_WRITE` or `SHF_EXECINSTR`.
- **Target Identity**: Target identity uses `RECORD_REL64` (64-bit signed displacement).
- **Relocation Validation**: The binder checks allocated `SHT_RELA`, `SHT_REL`, and `SHT_RELR` relocation sections.
  It rejects a sampled range that overlaps a supported loader-applied fixup.
  It ignores non-`SHF_ALLOC` static relocation metadata, such as metadata retained by `--emit-relocs`.
- **GNU Build ID**: Binding mode rejects an ELF image that contains `.note.gnu.build-id`.
  Link a manually bound ELF image with `--build-id=none`.

## Windows PE/COFF Binding

Windows x86-64 PE32+ binding operates under these rules:

- **Target Scope**: 64-bit PE32+ (`IMAGE_FILE_MACHINE_AMD64`) executable images (`.exe`).
- **DLL Status**: DLL binding is disabled in v1. The binder rejects images with `IMAGE_FILE_DLL`.
- **Section Layout**: Compiler emits records into `.obfsc$M`. The linker merges them into `.obfsc`.
- **Section Flags**: `.obfsc` must have `IMAGE_SCN_MEM_READ` set.
  `.obfsc` must not have `IMAGE_SCN_MEM_WRITE`, `IMAGE_SCN_MEM_EXECUTE`, or `IMAGE_SCN_MEM_DISCARDABLE`.
  The section virtual size must be an exact multiple of 96 bytes.
- **Target Identity**: Target identity uses `RECORD_REL32` (`IMAGE_REL_AMD64_REL32`).
  The low 32 bits of `target_delta` store the signed displacement from the record to the target function.
  The high 32 bits are zero.
  The binder sign-extends the low 32 bits.
  This representation is invariant under ASLR and `/FIXED` base addresses.
- **Section Mapping**: Sample ranges and records must map to exactly one section.
  The sampled bytes must fall within both `VirtualSize` and `SizeOfRawData`.
  Overlapping sections are rejected.
- **Base Relocation Validation**: The binder parses the PE base relocation directory.
  It rejects a supported base relocation that overlaps sampled code or a record.
  It also rejects unsupported base-relocation types in an AMD64 image.
- **Header CheckSum**: Binaries must have `OptionalHeader.CheckSum` set to `0`. Non-zero checksums are rejected.
- **Security Directory**: `IMAGE_DIRECTORY_ENTRY_SECURITY` must have both address and size set to zero.
  The binder rejects a nonzero PE Security directory, including an embedded Authenticode certificate table.

## Objects and Static Archives

Compiler passes emit `UNBOUND` records into object files (`.o`, `.obj`).
Static archives (`.a`, `.lib`) can contain those object files and their records.
Do not run the binder on intermediate object files or static archives.
The binder must run on the final linked executable image after section layout and relocations are resolved.

## C++ Symbol Selection

Configuration files match targets against LLVM IR function names.
Native C++ compilers emit mangled function names in LLVM IR.
A configuration selector written for an unmangled name (such as `calculate_hash`) will not match a mangled symbol (such as `_Z14calculate_hashv`).
To protect C++ functions:

1. Declare the target with `extern "C"` linkage, or
2. Specify the exact mangled LLVM symbol name in configuration selectors.

## Unsupported Targets

The v1 post-link bound format supports Linux x86-64 ELF and Windows x86-64 PE32+ executables.
Other targets do not support post-link binding in v1:

- 32-bit x86 (Linux, Windows)
- ARM and ARM64 (Linux, Windows, macOS, iOS)
- macOS Mach-O (x86-64, ARM64)
- Windows PE DLL files

When `self_checksum` runs on an unsupported target, the compiler uses the legacy neutral transformation path and emits no bound record.

`obf-clang` and `obf-clang++` reject an active `self_checksum` Windows final link on a non-Windows host.
They do not auto-finalize inherited PE records during that unsupported cross-host workflow.

## Release and Signing Order

On Windows, code signing must follow post-link binding.
Use this sequence:

1. **Link**: `lld-link` or `link.exe` creates the final PE32+ executable.
2. **Bind**: `obf-checksum-bind` writes expected checksums and sets `BOUND` flags.
3. **Sign**: `signtool.exe` applies the Authenticode signature to the bound executable.

For embedded Authenticode signing, run the binder before signing.
Binding mode rejects an image with a nonzero PE Security directory.

## Security Limits

Self-checksumming is designed to detect localized code tampering:

- **Sample Coverage**: The pass records 16 to 32 bytes per protected site. Code outside the sample range is not checked.
- **Single-Byte Tamper Detection**: A single-byte change inside the sampled range changes the v1 checksum.
- **Breakpoint Detection**: A software breakpoint changes the checksum when it replaces a sampled byte with `INT3` / `0xCC`.
- **Width Truncation**: Integer sites below 64 bits use a truncated checksum XOR.
  A full checksum mismatch can therefore produce a zero injected value after truncation.
- **Non-Goals**: Self-checksumming does not provide whole-binary authentication, cryptographic verification, or remote attestation.
  The v1 rolling hash does not provide cryptographic collision resistance.
  Self-checksumming does not prevent debugger attachment.
  An attacker with control over both code bytes and bound metadata can adjust both values simultaneously.
