# llvm-obfus

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![LLVM](https://img.shields.io/badge/LLVM-21%2B-262D3A?logo=llvm&logoColor=white)](docs/building.md)
[![C++23](https://img.shields.io/badge/C%2B%2B-23-00599C?logo=cplusplus&logoColor=white)](docs/building.md)

`llvm-obfus` is an out-of-tree LLVM pass plugin for function-selective obfuscation and virtualization.
Configure it with YAML or source annotations. The main entry point is `obf-safe-pipeline`.

**[Build](docs/building.md) · [Usage](docs/usage.md) · [Configuration](docs/configuration.md) · [Documentation](docs/README.md) · [Security](SECURITY.md)**

## Features

- VM bytecode with encoded dispatch, registered caller tokens, and instruction/successor integrity checks.
- MBA, instruction substitution, CFG flattening, outlining, and seeded indirect dispatch.
- String and constant encoding, with optional authenticated runtime decoding.
- Code-as-data self-checksum with post-link binding.
- Release marker cleanup and configurable symbol-isolation checks.

Levels control pass eligibility. Input shape and configuration determine which transforms apply.

| Level | Purpose |
|---|---|
| `none` | Requests no transforms, subject to enforced security floors |
| `light` | Permits string encoding, constant encoding, and block splitting |
| `strong` | Permits native arithmetic and control-flow transforms |
| `vm` | Permits VM execution and selected supporting transforms |
| `strong_vm` | Adds VM implementation hardening and enforces admission for VM-eligible functions |

Profiles (`fast`, `standard`, `guarded`, `fortress`, `lab`) set budgets and defaults.
See the [configuration reference](docs/configuration.md) for the full pass matrix and selection rules.

## Supported workflows

Linux and Windows x86-64. LLVM 21 minimum, with matching tools and plugin hosts.

| Input | Workflow |
|---|---|
| C / C++ | `obf-clang` / `obf-clang++`, or direct Clang plugin loading |
| LLVM bitcode | `obf-bc`, followed by compilation and runtime linkage |
| Rust / Cargo | `obf-rustc` with a compatible nightly or development toolchain |
| Zig | LLVM bitcode workflow with a compatible toolchain |
| TinyGo | `obf-tinygo` on Linux |

Windows plugins require compatible hosts that export LLVM symbols.
Clang uses `obf_clang_plugin.dll`. `opt` uses `obf_plugin.dll`.

## Build on Linux

Requires CMake 3.24+, a C++23 compiler, LLVM development files and tools, Python 3.10+, `lit`, and Ninja.

```sh
cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_DIR="$(llvm-config --cmakedir)"
cmake --build build --parallel 3
```

See [Build and toolchains](docs/building.md) for Windows setup and toolchain requirements.

## Quick start

From the repository root after building:

1. Create `example.c`:

```c
#include <stdio.h>

int protected_value(int input) {
    return (input * 7) ^ 0x5a;
}

int main(void) {
    printf("%d\n", protected_value(7));
    return 0;
}
```

2. Create `protect.yaml`:

```yaml
profile: standard
seed: 20260817
default_level: none
overrides:
  - name: protected_value
    level: strong_vm
self_checksum:
  enabled: false
```

3. Compile and run the program:

```sh
build/obf-clang --obf-config=protect.yaml \
  -O1 -fno-inline example.c -o example
./example
```

Expected output:

```text
107
```

The wrapper loads the plugin and links `libobf_runtime.a`.
Self-checksum is disabled in this example, so no binding step is needed.
Policy floors and caller promotions can select functions beyond the explicit target.

Use `obf-clang++` for C++. Select functions by LLVM symbol name or [source annotation](docs/usage.md).
VM expansion can increase build time, memory use, binary size, and runtime cost.

## Security boundaries

Keys are embedded in the binary. Debugging, tracing, and memory inspection can expose live plaintext.

- VM header and successor checks run before handler effects. They are not cryptographic authentication.
- Authenticated runtime decoders check descriptors, ciphertext tags, and completed payloads.
  A valid-looking abandoned decode owner can leave waiters pending indefinitely.
- Self-checksum covers selected code samples, not the whole binary. Required records must be bound after the final link.
- Ordinary `vm` can leave unsupported functions native.
  The `strong_vm` admission gate applies only while VM eligibility remains enabled.

Exception edges or inline assembly can disable VM eligibility, even for an exact `strong_vm` override.
See [feature restrictions](docs/configuration.md#feature-restrictions) and [SECURITY.md](SECURITY.md) for the full limits and private reporting contact.

## Documentation

| Task | Guide |
|---|---|
| Build and select compatible tools | [Build and toolchains](docs/building.md) |
| Use annotations, bitcode, or managed ELF LTO | [Usage](docs/usage.md) |
| Set selectors, profiles, and transform options | [Configuration](docs/configuration.md) |
| Integrate Rust, Zig, or TinyGo | [Other frontends](docs/frontends.md) |
| Understand transforms and pipeline order | [Protection reference](docs/protection.md) |
| Bind self-checksum records | [Self-checksum binding](docs/self-checksum.md) |
| Run tests, benchmarks, and audits | [Development](docs/development.md) |
| View existing decompiler and control-flow images | [Visual examples](docs/visual-examples.md) |

See the [documentation index](docs/README.md) for runtime and contribution references.

## License

[GNU General Public License v3.0](LICENSE).
Developed by [@90th](https://github.com/90th).
