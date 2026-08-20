# Security

## Supported version

This project follows a rolling release model. The `main` branch is the supported version.

## Self-checksum security contract

`self_checksum` provides code-as-data verification for selected functions.
It creates a runtime dependency on loaded machine-code bytes.
It is an obfuscation and tamper-detection mechanism, not whole-binary cryptographic authentication.

### Security guarantee

A supported v1 self-checksum site has these properties:

- When execution reaches a BOUND site, runtime code hashes 16 to 32 loaded machine-code bytes.
- The transformed code XORs the runtime checksum with the checksum bound after final linking.
- The transformed code injects a checksum-derived value into a protected integer computation.
- For integer sites below 64 bits, the pass truncates the XOR value to the site width.
- When execution reaches a protected site with a required UNBOUND record, the runtime guard traps.
- A single-byte change in the sample changes the full 64-bit v1 checksum.
- A software breakpoint changes the checksum when it replaces a sampled byte with `0xCC`.

### Security non-goals

`self_checksum` does not provide these protections:

- Whole-binary integrity or signature verification.
- Cryptographic authentication or secret key storage.
- Cryptographic collision resistance for the 64-bit rolling hash.
- Remote attestation.
- Prevention of debugger attachment or process inspection.
- Protection for code outside the selected sample ranges.
- Defense against attackers who modify both machine code and bound record metadata simultaneously.
- Guaranteed program divergence for every checksum mismatch. Narrow integer sites can truncate the XOR to zero.

### Security-relevant defects

Report the following behaviors as security defects:

- Execution reaches a protected site with a required UNBOUND record and does not trap.
- A supported wrapper completes successfully while leaving a protected final image UNBOUND.
- A single-byte sampled-code change, with all other sampled bytes unchanged, produces the clean expected checksum.
- The binder accepts sample ranges that overlap loader-applied relocations or fixups.
- The binder accepts ambiguous, overlapping, or non-file-backed section mappings.
- The PE binder accepts a nonzero PE Security directory instead of rejecting it.
- The compiler or optimizer removes the runtime dependency on the checksum result.

The following scenarios are outside the security contract:

- An attacker modifies both sampled code and stored expected checksums.
- A debugger attaches or sets hardware breakpoints without modifying sampled code bytes.
- Code outside selected sample ranges changes.
- An unsupported architecture does not receive bound v1 records.
- A Windows DLL is not bound by the v1 binder.

### Platform scope

- **Linux x86-64 ELF executable / PIE**: Supported.
- **Windows x86-64 PE32+ EXE on native Windows**: Supported.
- **Windows DLL**: Unsupported in v1.
- **x86 / ARM / ARM64 / macOS**: Unsupported by the bound v1 path.

See [`docs/self-checksum.md`](docs/self-checksum.md) for the detailed technical specification, record format, relocation rules, and binder behavior.

## Report a security problem

Do not report a security problem in a public GitHub issue.

Send a report to ninetieth@riseup.net.

Include these details:

- the affected commit or version
- the LLVM version and target platform
- the build and obfuscation configuration
- steps to reproduce the problem
- the possible security impact

Remove passwords, private keys, and other sensitive data from the report.

## Public issues

Use public GitHub issues for non-sensitive bugs and feature requests.

Keep security details private until the project fixes the problem or agrees to public disclosure.
