# Documentation

Start with the [project README](../README.md) for a build and a complete C example.
Use these guides for larger projects and detailed settings.

## Get started

| Task | Guide |
|---|---|
| Build on Linux or Windows | [Build and toolchains](building.md) |
| Protect C/C++, bitcode, or an LTO build | [Usage](usage.md) |
| Select functions and set protection options | [Configuration](configuration.md) |
| Use Rust, Zig, or TinyGo | [Other frontends](frontends.md) |

## Understand the protection

| Topic | Reference |
|---|---|
| Transforms, VM behavior, and pipeline order | [Protection reference](protection.md) |
| VM integrity, self-checksum limits, and private defect reporting | [Security contract](../SECURITY.md) |
| Final-link checksum binding, records, and binary formats | [Self-checksum binding](self-checksum.md) |
| Runtime linkage and authenticated decode waiting | [Runtime](../runtime/README.md) |
| Existing decompiler and control-flow images | [Visual examples](visual-examples.md) |

## Develop and evaluate

- [Development](development.md): source layout, tests, benchmarks, and recovery-analysis limits.
- [Contributing](../CONTRIBUTING.md): contribution rules and code style.
- [Benchmark corpus](../benchmarks/README.md): input programs and artifact names.

Workflow guides state their required inputs and supported scope.
A protection option does not guarantee that every input function supports that transform.
