# <h1><img src="images/logo-header.png" width="40" height="40" align="top" alt=""> llvm-obfus</h1>

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![LLVM](https://img.shields.io/badge/LLVM-21%2B-262D3A?logo=llvm&logoColor=white)](docs/building.md)
[![C++23](https://img.shields.io/badge/C%2B%2B-23-00599C?logo=cplusplus&logoColor=white)](docs/building.md)

`llvm-obfus` is an out-of-tree LLVM pass plugin that obfuscates and virtualizes selected functions.
Configure protection with YAML or source annotations. Use `obf-safe-pipeline` to run the combined pipeline.

**[Build](docs/building.md) · [Usage](docs/usage.md) · [Configuration](docs/configuration.md) · [Documentation](docs/README.md) · [Security](SECURITY.md)**

## Features

- Function virtualization with encoded dispatch and runtime integrity checks.
- Mixed Boolean arithmetic (MBA), instruction substitution, control-flow flattening, outlining, and indirect dispatch.
- String and constant encoding, with optional authenticated decoding.
- Checksums of selected code regions, bound after linking.

Choose a protection level for each function. The function and configuration determine which transforms can apply.

| Level | Behavior |
|---|---|
| `none` | Requests no transforms |
| `light` | String and constant encoding, plus block splitting |
| `strong` | Native arithmetic and control-flow obfuscation |
| `vm` | Function virtualization |
| `strong_vm` | Requires virtualization for VM-eligible functions and adds implementation hardening |

Profiles (`fast`, `standard`, `guarded`, `fortress`, `lab`) set transform limits and defaults.
The policy can raise requested levels or select callers automatically.
See the [configuration reference](docs/configuration.md) for selection rules and the full transform matrix.

## Supported workflows

Linux and Windows x86-64, with LLVM 21 or later. Tools and plugin hosts must use compatible LLVM builds.

| Input | Workflow |
|---|---|
| C / C++ | `obf-clang` / `obf-clang++`, or direct Clang plugin loading |
| LLVM bitcode | `obf-bc`, followed by compilation and runtime linkage |
| Rust / Cargo | `obf-rustc` with a compatible nightly or development toolchain |
| Zig | LLVM bitcode workflow with a compatible toolchain |
| TinyGo | `obf-tinygo` on Linux |

## Build on Linux

You need CMake 3.24+, a C++23 compiler, LLVM development files and tools, Python 3.10+, `lit`, and Ninja.

```sh
cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_DIR="$(llvm-config --cmakedir)"
cmake --build build --parallel 3
```

See [Build and toolchains](docs/building.md) for Windows setup, plugin compatibility, and toolchain requirements.

## Quick start

After building, run these commands from the repository root.

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
The policy can also protect functions outside the explicit target list, including callers.

Use `obf-clang++` for C++. Select functions by LLVM symbol name or [source annotation](docs/usage.md).
Virtualization can increase compile time, memory use, binary size, and execution time.

## Security boundaries

Obfuscation does not prevent debugging, tracing, or memory inspection.
Keys remain in the binary, and decoded data can be read at runtime.

- VM bytecode checks run before the affected instruction has side effects. They are not cryptographic authentication.
- Authenticated string and constant decoders verify data before use.
  Other threads can wait indefinitely if decoding does not finish.
- Code checksums cover selected samples, not the whole binary. Required records must be bound after the final link.
- Ordinary `vm` can leave unsupported functions native.
  `strong_vm` requires virtualization only for functions that remain VM-eligible.

Exception edges or inline assembly can disable VM eligibility, even with an exact `strong_vm` selection.
See [feature restrictions](docs/configuration.md#feature-restrictions) and [SECURITY.md](SECURITY.md) for the limits and private vulnerability reporting.

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
| Inspect generated code and control flow | [Visual examples](docs/visual-examples.md) |

See the [documentation index](docs/README.md) for runtime and contribution references.

## License

[GNU General Public License v3.0](LICENSE).
Developed by [@90th](https://github.com/90th).
