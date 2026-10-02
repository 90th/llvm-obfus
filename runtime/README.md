# Runtime

The build creates `build/libobf_runtime.a` through the `obf-runtime` CMake target. This archive is the public runtime link artifact for transformed binaries.

`build/libobf_runtime.a` contains:

- `obf_entropy_anchor.o`
- `obf_string_auth_runtime.o`

Users invoking raw `clang` or `clang++` must link `build/libobf_runtime.a` after their transformed input objects.

Users invoking `build/obf-clang` or `build/obf-clang++` get `build/libobf_runtime.a` appended automatically for link actions.

## Authenticated decode waiting

Authenticated strings and constant pools share one decode owner per descriptor.
The successful completion compare-exchange elects that owner.
The owner publishes decoded completion before it publishes decoded status.
Waiters use acquire loads and a stable status/completion/status snapshot.
Only decoded status permits payload and completion verification before return.

A delayed owner is not evidence of tampering.
Waiters have no poll-count integrity deadline.
After bounded retry batches, they use Windows `Sleep(1)` or POSIX `poll(NULL, 0, 1)` to reduce contention.
These calls do not authorize data or guarantee scheduler fairness.
The authenticated state remains the completion authority.

Invalid descriptors, tags, stable phases, and completed payloads still trap.
A zero completion in the decoding phase also traps.
The runtime never resets ownership or lets a waiter decode concurrently.

A legal-looking abandoned owner cannot be distinguished from a delayed owner under this ABI.
Such a state can wait indefinitely, but cannot authorize unverified data.
POSIX `poll` can be a cancellation point.
The runtime does not promise cancellation-safe key erasure or abandoned-owner recovery.

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
