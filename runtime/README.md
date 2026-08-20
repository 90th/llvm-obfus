# Runtime

The build creates `build/libobf_runtime.a` through the `obf-runtime` CMake target. This archive is the public runtime link artifact for transformed binaries.

`build/libobf_runtime.a` contains:

- `obf_entropy_anchor.o`
- `obf_string_auth_runtime.o`

Users invoking raw `clang` or `clang++` must link `build/libobf_runtime.a` after their transformed input objects.

Users invoking `build/obf-clang` or `build/obf-clang++` get `build/libobf_runtime.a` appended automatically for link actions.

## Self-checksum runtime contract

`self_checksum` uses runtime helpers from `obf_entropy_anchor.o`.
The pass loads the record flags.
`rt_core_sc0` checks that the loaded value equals `REQUIRED | BOUND`.
When execution reaches that protected site, `rt_core_sc0` traps if the required record is UNBOUND.
The pass and runtime do not treat an UNBOUND required record as valid.

`rt_core_cc` calculates the 64-bit checksum over loaded machine-code bytes.
The runtime does not define the expected final code bytes.
`obf-checksum-bind` writes the expected checksum after the final executable link.
The transformed code XORs the runtime checksum with the expected value.
For integer sites below 64 bits, the pass truncates that XOR value to the site width.

An object file or static archive can contain UNBOUND self-checksum records.
Bind required records before you use protected paths in a supported final executable.

Supported `obf-clang` and `obf-clang++` final-link workflows run the platform binder automatically.
Raw compiler and bitcode workflows that produce supported v1 records must run the binder after the final link.

See [`docs/self-checksum.md`](../docs/self-checksum.md) for target support, relocations, signing, and GNU build-ID rules.
See [`SECURITY.md`](../SECURITY.md#self-checksum-security-contract) for the security contract.
