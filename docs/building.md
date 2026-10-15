# Build llvm-obfus

[Documentation](README.md) · [Usage](usage.md) · [Frontend workflows](frontends.md)

## Requirements

Build against the LLVM SDK that matches your plugin host, with matching LLVM tools.
A successful CMake version check does not guarantee compatibility with every newer LLVM release.

| Dependency | Requirement |
|---|---|
| CMake | 3.24 or later |
| C and C++ compiler | C++23 for the project and C17 for the runtime |
| LLVM development SDK | LLVM 21 or later, with headers, libraries, CMake files, and loadable-pass-plugin support |
| Python | 3.10 or later for the generated wrappers |
| `lit` | Required during CMake configuration, even if you do not run tests |
| LLVM tools | `clang`, `clang++`, `opt`, `llvm-link`, `llc`, `llvm-strip`, `llvm-nm`, and `llvm-objdump` |
| Archive tool | `llvm-ar`, or the `ar` fallback that CMake accepts |
| Threads | Required by the test targets that CMake configures |
| Ninja | Required only for the Ninja generator used below |

On non-MSVC toolchains, CMake also requires direct aligned 64-bit atomic compare-and-exchange support.
It does not accept a toolchain that needs an external atomic-library fallback for that check.

The test suite also uses LLVM `FileCheck` and command-line utilities such as `cmp`, `not`, and `timeout`.
Some tests need additional LLVM tools, such as `llvm-dis`.
The lit suite also requires `jq` on `PATH` for JSON report checks.
CMake detects `lli` and `strings` when available.
See [Development](development.md) for test commands and platform-specific test requirements.

### Optional workflows

These tools are not required for the C/C++ build.
Their compatibility requirements differ from the general LLVM version check.

| Workflow | Toolchain requirements |
|---|---|
| Managed Full LTO and ThinLTO | ELF target, non-Windows host, and `ld.lld` with the same reported version as configured Clang |
| Rust | Cargo and nightly or development `rustc`, with LLVM major/minor matching the project SDK |
| Zig | Zig 0.16.x for the native Linux and Windows workflow |
| TinyGo | Native Linux, TinyGo 0.41.x using Go 1.23–1.26 and LLVM 20, configured LLVM 21 and `llc`, and LLD 21 |

TinyGo also requires a matching supported host architecture.
Windows Rust requires a separate exported LLVM owner and matching import library.
See [Frontend workflows](frontends.md) for the complete frontend contracts.

## Linux build

Run these commands from the repository root.
Set `LLVM_CONFIG` to the `llvm-config` executable for your selected LLVM SDK.
Keep that SDK's tools first on `PATH`.

```sh
LLVM_CONFIG=llvm-config
LLVM_BIN="$("$LLVM_CONFIG" --bindir)"
export PATH="$LLVM_BIN:$PATH"

cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_DIR="$("$LLVM_CONFIG" --cmakedir)" \
  -DCMAKE_C_COMPILER="$LLVM_BIN/clang" \
  -DCMAKE_CXX_COMPILER="$LLVM_BIN/clang++"
cmake --build build --parallel 3
```

If your distribution supplies a versioned executable, use its name instead of `llvm-config`.
Use a new build directory when you change the compiler or LLVM SDK.

The build directory contains the plugin, wrappers, runtime archive, and supporting tools.
The build-tree wrappers retain the configured tool and artifact paths.
Do not copy a build-tree wrapper alone.
Use the installed prefix below for relocation or standalone consumers.

## Windows build

A standard LLVM installation is not sufficient unless its plugin hosts export the required LLVM API.
The plugin DLL must import LLVM from the executable or DLL that owns the active LLVM objects.
Do not link an independent static LLVM copy into a plugin as a replacement for the host imports.

| Plugin DLL | Required host | Matching import library |
|---|---|---|
| `obf_plugin.dll` | Exported `opt.exe` | `opt.lib` |
| `obf_clang_plugin.dll` | Exported `clang.exe` | `clang.lib` |
| `obf_rustc_plugin.dll`, when configured | The bound `rustc_driver-*.dll` LLVM owner | Its matching `.lib` |

CMake requires canonical `opt.exe` and `clang.exe` names, with their corresponding import-library names.
The LLVM headers must support `LLVM_ENABLE_LLVM_EXPORT_ANNOTATIONS`.
The supplied host-build recipe requires LLVM 22 or later.
It also requires matching `llvm-project` sources, the Clang development package, and the SDK's `lib/clang` resource directory.

### Build exported hosts

If you already have a matching exported host pair and import libraries, continue to the project build.
Otherwise, use the supplied recipe.
Open a Visual Studio x64 developer shell with `clang-cl`, CMake, Ninja, Python, and `lit` available.

Set the following paths to your actual SDK and matching source checkout.

```powershell
$LlvmSdk = "C:/path/to/llvm-sdk"
$LlvmSources = "C:/path/to/llvm-project"
$HostBuild = "$PWD/build-windows-hosts"

cmake -S tools/obf-windows-hosts -B "$HostBuild" -G Ninja `
  -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_C_COMPILER=clang-cl `
  -DCMAKE_CXX_COMPILER=clang-cl `
  "-DLLVM_DIR=$LlvmSdk/lib/cmake/llvm" `
  "-DClang_DIR=$LlvmSdk/lib/cmake/clang" `
  "-DOBF_LLVM_PROJECT_SOURCE_DIR=$LlvmSources"
cmake --build "$HostBuild" --parallel 3
```

The recipe creates `bin/opt.exe`, `bin/clang.exe`, `lib/opt.lib`, and `lib/clang.lib`.
It also builds `FileCheck` and `not` for tests.
Keep the generated Clang resource directory with the host build.

The recipe exports required inline and template APIs through `llvm-api-exports.cpp`.
O0 aggregate preparation uses the host's function-analysis manager and its real proxy key.
If you use an older host build, rebuild both hosts and their import libraries before rebuilding the plugin DLLs.
Do not replace missing analysis APIs with local keys or an independent LLVM runtime.

### Build the project

Use the same SDK and exported host build.

```powershell
cmake -S . -B build -G Ninja `
  -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_C_COMPILER=clang-cl `
  -DCMAKE_CXX_COMPILER=clang-cl `
  "-DLLVM_DIR=$LlvmSdk/lib/cmake/llvm" `
  "-DOBF_WINDOWS_PLUGIN_HOST_ROOT=$HostBuild"
cmake --build build --parallel 3
```

`clang-cl` here builds llvm-obfus itself.
It is not the configured frontend plugin host.
The generated C/C++ wrappers invoke the exported `clang.exe`.
On Windows, `obf-clang++` selects C++ driver mode on that same executable.
Do not substitute a separate `clang-cl.exe` or `clang++.exe` as the plugin owner.

Use the generated `.cmd` launchers from PowerShell or Command Prompt.
Windows Lit tests also require Git for Windows Bash at the location checked by the test configuration.

## Install and package

The standalone C/C++ package supports native Linux x86-64 glibc and Windows x64 MSVC targets.
Build the complete wrapper dependency set before installation:

```sh
cmake --build build --target obf-clang-wrappers --parallel 3
```

### Install on Linux

Set `CMAKE_INSTALL_PREFIX` during configuration, or override it during installation:

```sh
cmake --install build --config Release --prefix "$HOME/opt/llvm-obfus"
```

For distribution staging, use `DESTDIR`:

```sh
DESTDIR="$PWD/stage" cmake --install build --config Release --prefix /opt/llvm-obfus
```

The staged prefix is `stage/opt/llvm-obfus`.
The wrappers do not retain either the staging directory or `/opt/llvm-obfus`.

### Install on Windows

Use the x64 developer shell from the Windows build procedure.
Configure the prefix, then install the Release build:

```powershell
cmake -S . -B build "-DCMAKE_INSTALL_PREFIX=C:/Tools/llvm-obfus"
cmake --build build --target obf-clang-wrappers --parallel 3
cmake --install build --config Release
```

Do not use `DESTDIR` on Windows.
Use the installed `.cmd` launchers from Command Prompt or PowerShell.
They find their Python scripts through `%~dp0` and require `python` on `PATH`.

### Installed layout

| Directory | Contents |
|---|---|
| `bin/` | `obf-clang`, `obf-clang++`, `obf-opt`, and Windows `.cmd` launchers |
| `bin/` | `obf-driver`, `obf-native-link`, `obf-checksum-bind`, and matching Clang/opt hosts |
| `bin/` | Matching optional `ld.lld` on Linux, or `lld-link.exe` and dependent DLLs on Windows |
| `lib/` | `libobf_runtime.a` on Linux, or `obf_runtime.lib` on Windows |
| `lib/` | `obf_plugin.so` on Linux, or host-specific `obf_plugin.dll` and `obf_clang_plugin.dll` on Windows |
| `lib/` | Bundled non-system shared libraries on Linux |
| `lib/clang/<version>/` | Clang resource headers and compiler runtimes |
| `include/obf/` | API, runtime, and C++ headers, including the generated ABI header |
| `libexec/llvm-obfus/<tool>/` | Native Linux LLVM hosts behind loader-aware `bin/` launchers |
| `share/licenses/llvm-obfus/` | Project license |

Configure directory names with `CMAKE_INSTALL_BINDIR`, `CMAKE_INSTALL_LIBDIR`, `CMAKE_INSTALL_INCLUDEDIR`, `CMAKE_INSTALL_LIBEXECDIR`, and `CMAKE_INSTALL_DATADIR`.
Use relative paths inside the prefix, with forward slashes.
Absolute paths and paths that escape the prefix are rejected.
The installed wrappers use the configured destinations, including nested directory names.

The package includes the exact configured Clang/opt hosts and their non-system dependency closure.
Windows keeps the canonical `clang.exe` and `opt.exe` names because the plugin DLLs import those images.
The wrappers set child-process loader paths before compiler, optimizer, and helper calls.
They find headers and libraries relative to the resolved script location, not the current directory or Python installation.
Linux host launchers also set loader paths for direct CMake tool probes outside the obfuscator wrapper.

Python 3.10 or later remains required.
Linux also requires its platform C library, system linker, and C/C++ development environment.
Windows requires its MSVC and Windows SDK development environment.
Packages are platform-specific and do not guarantee compatibility with older operating-system or C-library versions.

The installed C/C++ wrappers automatically select the installed API headers and Clang resource directory.
Keep the runtime archive and plugins from the same build.
An explicitly set `OBF_PLUGIN` or `OBF_RUNTIME` overrides its default, including when the value is empty.
Missing or empty overrides fail rather than silently selecting another plugin or runtime.
On Windows, `OBF_PLUGIN` must select the Clang-host plugin, not the opt-host plugin.

### Use an external project

Compile from any working directory with the installed wrappers:

```sh
"/path/to/prefix/bin/obf-clang" --obf-config=policy.yaml app.c -o app
"/path/to/prefix/bin/obf-clang++" --obf-config=policy.yaml app.cpp -o app-cpp
```

Use `.cmd` suffixes for the corresponding Windows commands.
The [string-copy API](usage.md#authenticated-cross-dso-string-copies) uses the installed `<obf/string_copy.h>` header.
It does not require repository headers or separate runtime-link arguments.

For a CMake consumer, select the wrappers when you create its build directory:

```sh
cmake -S /path/to/consumer -B /path/to/consumer-build -G Ninja \
  "-DCMAKE_C_COMPILER=/path/to/prefix/bin/obf-clang" \
  "-DCMAKE_CXX_COMPILER=/path/to/prefix/bin/obf-clang++"
cmake --build /path/to/consumer-build --parallel 3
```

Move the entire prefix together.
Create a fresh consumer build directory after relocation because CMake caches compiler paths.
No plugin or runtime environment override is required after the move.

### Create an archive

CPack uses the same install rules:

```sh
cpack --config build/CPackConfig.cmake -B packages
```

The default generator is TGZ on Linux and ZIP on Windows.
Archive names identify the matching LLVM version, operating system, and processor.
Extract the archive and use its complete prefix.
The package does not install the optional Rust, TinyGo, or standalone bitcode wrappers.
Those workflows retain their existing build-tree requirements.

Before distribution, preserve the upstream license notices for bundled LLVM and runtime libraries.

## CMake cache variables

Pass cache values as `-DNAME=value` during configuration.
Application YAML and `OBF_SEED` are separate from these build settings.

### SDK and tools

| Variable | Purpose |
|---|---|
| `LLVM_DIR` | Directory containing the selected LLVM CMake package |
| `Python3_EXECUTABLE` | Python interpreter used by the generated wrappers |
| `OBF_LIT` | `lit` executable required during configuration |
| `OBF_CLANG`, `OBF_CLANGXX`, `OBF_OPT` | Compiler and pass-runner paths |
| `OBF_LLVM_LINK`, `OBF_LLC`, `OBF_STRIP`, `OBF_NM`, `OBF_OBJDUMP`, `OBF_LLVM_AR` | Required supporting tool paths |
| `OBF_LLI`, `OBF_STRINGS` | Optional tool paths |
| `OBF_RUSTC`, `OBF_CARGO`, `OBF_ZIG`, `OBF_TINYGO` | Optional frontend tool paths |
| `OBF_LLD` | LLD candidate for optional frontend toolchain detection |

Managed C/C++ LTO does not use `OBF_LLD` to select its linker.
The wrapper asks configured Clang for `ld.lld` and checks the reported Clang and LLD versions.

### Windows host ownership

| Variable | Purpose |
|---|---|
| `OBF_WINDOWS_PLUGIN_HOST_ROOT` | Host-build root with exported hosts in `bin` and import libraries in `lib`, `lib64`, or `bin` |
| `OBF_OPT_IMPORT_LIBRARY` | `opt.lib` paired with `OBF_OPT` |
| `OBF_CLANG_IMPORT_LIBRARY` | `clang.lib` paired with `OBF_CLANG` |
| `OBF_WINDOWS_RUST_LLVM_HOST_IMAGE` | Canonical absolute path to the Rust LLVM owner DLL |
| `OBF_WINDOWS_RUST_LLVM_HOST_IMPORT_LIBRARY` | Canonical absolute path to its matching import library |
| `OBF_WINDOWS_RUST_LLVM_HOST_RUSTC` | Canonical absolute path to the bound `rustc.exe` |

Instead of a host root, you can set all four Clang/opt host paths explicitly.
Use `OBF_OPT`, `OBF_OPT_IMPORT_LIBRARY`, `OBF_CLANG`, and `OBF_CLANG_IMPORT_LIBRARY` together.

Set all three Windows Rust owner variables together, or leave all three unset.
CMake verifies the Rust owner files and compiler identity before it enables the Rust plugin.
These variables do not make a standard Rust installation export the required LLVM API.

### Runtime and benchmark settings

| Variable | Default | Purpose |
|---|---|---|
| `OBF_RUNTIME_ABI_PREFIX` | `rt_core_` | Build-global runtime symbol prefix |
| `OBF_BENCHMARK_SEED` | Empty | Fixed benchmark/runtime-generation seed, or a generated seed when empty |
| `OBF_BENCHMARK_CLEAN_IR` | `OFF` | Enable cleaned benchmark IR for analysis builds |
| `OBF_BENCHMARK_CLEANUP_PASSES` | `dse` | Cleanup pipeline for that analysis mode |

The runtime prefix must be a valid C identifier prefix ending with `_`.
It must not contain `obf`, regardless of letter case.
Link each protected application with the runtime archive from the same plugin build.
See the [Runtime contract](../runtime/README.md).

A fixed benchmark seed must be a nonzero decimal integer without leading zeroes.
The generated seed remains in the CMake cache when `OBF_BENCHMARK_SEED` is empty.
This setting does not select the application seed used by a wrapper invocation.

## Build outputs

| Output | Use |
|---|---|
| `obf_plugin.so` on Linux | Clang and `opt` plugin |
| Windows plugin DLLs listed above | Host-specific plugins |
| `libobf_runtime.a` | Runtime archive, including on Windows |
| `obf-clang`, `obf-clang++` | C/C++ compiler wrappers |
| `obf-opt` | Configured `opt` launcher, with Windows option-to-environment mapping |
| `obf-bc` | Standalone bitcode transformation wrapper |
| `obf-driver` | Configuration reports and managed-LTO input validation |
| `obf-checksum-bind` | Native Linux or Windows self-checksum binder |
| `obf-rustc`, `obf-tinygo` | Optional frontend wrappers |

A generated wrapper can exist even when its optional frontend toolchain is unavailable.
Check the [Frontend workflows](frontends.md) requirements before you use it.
Continue with [Usage](usage.md) for compiler, bitcode, and LTO commands.
