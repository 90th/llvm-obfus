# Ghidra Checkpoints

## Purpose

Ghidra checkpoints are binary-level regression checks for benchmark outputs.
They are used to verify that obfuscation changes do not silently break:

- string and symbol hygiene
- VM topology and helper boundaries
- data-reference concentration
- decompiler resistance expectations

They do not replace lit, audit, or seed-diversity. They complement those checks by looking at the stripped binaries a reverse engineer actually sees.

## Fixed-Seed Benchmark Builds

Use a dedicated build directory for checkpoint work.

```sh
cmake -S . -B build-ghidra-check \
  -DLLVM_DIR="$(llvm-config --cmakedir)" \
  -DOBF_BENCHMARK_SEED=151616
cmake --build build-ghidra-check --target obf-benchmarks -- -j1
cmake --build build-ghidra-check --target obf-audit-benchmarks -- -j1
```

`OBF_BENCHMARK_SEED` pins the benchmark obfuscation seed for that build tree.
If it is left empty, CMake generates a non-zero decimal seed during configure and prints it in the configure output.

## Recommended Pre-Import Commands

Run these before importing anything into Ghidra:

```sh
cmake --build build-ghidra-check --target obf-benchmarks -- -j1
cmake --build build-ghidra-check --target obf-audit-benchmarks -- -j1
file build-ghidra-check/benchmarks/*/*.baseline \
  build-ghidra-check/benchmarks/*/*.obfuscated
sha256sum build-ghidra-check/benchmarks/*/*.baseline \
  build-ghidra-check/benchmarks/*/*.obfuscated
```

If you are checking a normal `build/` tree instead, use the same commands with `build/` instead of `build-ghidra-check/`.

## Expected Benchmark Binary Paths

Expected stripped binaries:

- `build-ghidra-check/benchmarks/license_demo/license_demo.baseline`
- `build-ghidra-check/benchmarks/license_demo/license_demo.obfuscated`
- `build-ghidra-check/benchmarks/config_demo/config_demo.baseline`
- `build-ghidra-check/benchmarks/config_demo/config_demo.obfuscated`
- `build-ghidra-check/benchmarks/vm_workflow_demo/vm_workflow_demo.baseline`
- `build-ghidra-check/benchmarks/vm_workflow_demo/vm_workflow_demo.obfuscated`
- `build-ghidra-check/benchmarks/wpo_demo/wpo_demo.baseline`
- `build-ghidra-check/benchmarks/wpo_demo/wpo_demo.obfuscated`

## Avoiding Stale Imports

Do not trust an old imported program just because the filename matches.

Before import:

- record the build directory
- record the effective benchmark seed from the CMake configure output
- record `sha256sum` for every imported binary

Recommended practice:

- use a fresh build directory for each checkpoint campaign
- use fresh Ghidra program names that encode benchmark, kind, seed, and a short hash
- if an import already exists under the same logical name, delete and reimport instead of reusing it

## Probe Order

Use the cheapest probes first.

1. string and name checks
2. function metrics
3. CFG and control-flow metrics
4. xrefs and callgraph
5. data item xref concentration
6. decompile only small roots, compact routers, and small support helpers

This keeps the checkpoint reproducible and reduces the chance of destabilizing the Ghidra MCP bridge.

## Giant Helper Warning

Do not repeatedly decompile giant VM helper bodies.

Large VM-like helper bodies can hit Ghidra's instruction cap and destabilize the MCP bridge. Prefer:

- `search_strings`
- `search_functions`
- `list_functions_enhanced`
- `analyze_control_flow`
- `get_function_call_graph`
- `get_function_callers`
- `get_function_callees`
- `list_data_items_by_xrefs`
- `get_xrefs_to`
- `get_assembly_context`

Only decompile:

- small roots
- compact first-level routers
- small support helpers

Avoid repeated decompile attempts on anything that is obviously giant or already known to be unstable.

## Checkpoint Template

Use this compact template for each benchmark set.

### String and Name Regression

- source-level names survived: yes/no
- generated `__obf_*` names survived: yes/no
- protected strings survived: yes/no

### Topology Regression

- VM roots identified
- first-level routers identified
- largest transformed bodies identified
- roots stayed small: yes/no
- first-level routers stayed compact: yes/no
- large work stayed out of roots and first-level routers: yes/no

### Function Metrics

For each important VM-like function:

- address
- name
- role
- size
- basic block count
- instruction count
- complexity if available
- direct callers and callees if cheap to collect

### Data-Reference Concentration

- top referenced data items
- xref counts
- comparison against prior checkpoint anchors
- obvious worsening: yes/no

### Readability Scores

Use a 0-5 scale:

- 0 = unreadable or not worth decompiling
- 5 = close to source-equivalent recovery

Score:

- roots
- first-level routers
- representative helper bodies
- small support helpers

### Verdict

- impact: low / moderate / high
- topology preserved: yes/no
- string and symbol hygiene preserved: yes/no
- data-reference concentration acceptable: yes/no
- next recommended implementation step
