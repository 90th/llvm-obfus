# PR26 Fixed-Seed Ghidra Checkpoint Before PR27

## Metadata

| Field | Value |
|---|---|
| Seed | `OBF_BENCHMARK_SEED=151616` |
| Checkpoint date | 2026-05-03 |
| Ghidra image base | `0x00400000` (all binaries) |
| Compiler | gcc (ELF64 x86) |

### Loaded Programs

| Binary | Size | Functions | Hash (sha256 prefix) |
|---|---|---|---|
| `license_demo.obfuscated.pr26.seed151616.020cf53f` | 4.2 MB | 107 (95 Ghidra-recognized) | `020cf53f` |
| `config_demo.obfuscated.pr26.seed151616.0a1b47fa` | 580 KB | 61 (54 recognized) | `0a1b47fa` |
| `vm_workflow_demo.obfuscated.pr26.seed151616.2f7974bf` | 772 KB | 75 (68 recognized) | `2f7974bf` |
| `wpo_demo.obfuscated.pr26.seed151616.da9d6c5e` | — | — | `da9d6c5e` (**not loaded**) |

`wpo_demo` was absent from the Ghidra project at time of checkpoint. Findings below cover the three loaded binaries only.

---

## Executive Verdict

**PR26 binary posture is acceptable before PR27.**

All source-level function names and protected strings are gone. `__obf_*` / `obf.vm.*` markers are stripped. The VM entry-thunk polymorphism added in PR26 is structurally visible: each protected call site goes through a small polymorphic MBA-encoded trampoline before reaching the VM implementation body. The wrapper→implementation chain is **not directly callable** — it is dispatched through embedded data-table function pointers, and the final call to the VM implementation passes an MBA-obfuscated argument.

The main weakness visible at binary level (and the natural PR27 target) is **data-reference concentration**: each VM implementation reads from a small number of globally identifiable pointer objects with very high xref counts. The dominant anchor in `license_demo` has 257 reads from a single function; in `config_demo` 167 reads from scattered VM handler code; in `vm_workflow_demo` 6 pointer globals each with 32–53 reads. These anchors are immediately visible in any data-xref survey and act as bytecode recovery pivots.

---

## Per-Benchmark Findings

---

### license_demo.obfuscated.pr26.seed151616.020cf53f

#### A. String and Symbol Hygiene

| Category | Result |
|---|---|
| Source function names (`verify_license`, `mix_token`) | **absent** |
| Protected strings (`ACCESS GRANTED`, `ACCESS DENIED`, `delta-7`) | **absent** |
| `__obf_*` / `obf.vm.*` / `vm.entry.thunk.shape` markers | **absent** |
| C++ runtime symbols (`operator<<`, `now`, `strlen`, `getenv`, `__isoc23_strtoull`) | **present** (expected — unprotected harness) |
| Dynamic linker strings (`/lib64/ld-linux-x86-64.so.2`, `libstdc++.so.6`, GLIBC version tags) | **present** (unavoidable ELF metadata) |

String hygiene: **clean**. No leakage from protected functions.

#### B. VM Topology

| Function | Address | Size | Instructions | CC | Loops | Calls | Role |
|---|---|---|---|---|---|---|---|
| `entry` | `0x00400400` | 38 B | 13 | 2 | 0 | 1 | ELF entry; passes `FUN_004004f0` to `__libc_start_main` |
| `FUN_004004f0` | `0x004004f0` | 15 KB | 3,830 | 27 | 4 | 28 | `main` / outer VM orchestrator; embeds dispatch-table ptrs |
| `FUN_00803ca0` | `0x00803ca0` | 304 B | 76 | 3 | 0 | 2 | Polymorphic entry thunk; MBA-encodes `param_3` via entropy anchor |
| `FUN_00663980` | `0x00663980` | **1.7 MB** | **379,632** | 35 | 67 | 1 | **Primary VM implementation** (mix_token / verify_license) |
| `FUN_00407ba0` | `0x00407ba0` | 432 KB | 99,791 | 10 | 10 | 1 | **Secondary VM implementation** (second protected function) |
| `FUN_004004f0`-callee subfunctions | `0x00403fe0`, `0x004045c0`, `0x004ae0`… | 1–1.5 KB each | 200–450 | 7–9 | 0 | 2–4 | VM sub-handlers / initialization helpers |
| `FUN_008052b0`…`FUN_008052c0` (cluster) | `0x008051f0`–`0x008052c0` | 8 B each | 4 each | 2 | 0 | 1 | Polymorphic entry-thunk stubs (tiny wrappers around anchor reader) |
| `FUN_008053c0` | `0x008053c0` | 74 B | 19 | 1 | 0 | 0 | **Entropy anchor reader** (reads `DAT_0080b0d0`, stores via ptr) |
| `FUN_00405ff0` | `0x00405ff0` | 1,334 B | 328 | 7 | 1 | 2 | VM router / dispatch helper (6 data xrefs from tables) |

**Notable observations:**
- `FUN_004004f0` has **no direct callers**; it is passed as function pointer via `entry` → `__libc_start_main`. Its body embeds function pointer references to `FUN_00803ca0` in multiple dispatch-table DATA entries.
- `FUN_00663980` has a single basic block reaching 88 KB; decompilation will fail with "Flow exceeded maximum allowable instructions".
- 14 tiny 8-byte stubs (`FUN_008051f0`–`FUN_008052c0`) form a cluster at `0x8051f0`–`0x8052c0`, each calling the entropy anchor reader — visible as a dense thunk array.

#### C. Wrapper / Entry Thunk / Implementation Mapping

```
entry (38B)
  └─> __libc_start_main → FUN_004004f0 [main, 15KB, PARAM xref]
       ├─ dispatch table DATA refs → FUN_00803ca0 [entry thunk, 304B]
       │    ├─ FUN_008052b0 [8B stub] → FUN_008053c0 [entropy anchor reader, 74B]
       │    └─ MBA-encoded param → FUN_00663980 [VM impl #1, 1.7MB]
       └─ additional DATA refs → other VM functions (FUN_00407ba0 etc.)
```

| Question | Answer |
|---|---|
| wrapper → entry thunk identifiable? | **yes** — from DATA xrefs embedded in `FUN_004004f0` |
| entry thunk → VM impl identifiable? | **yes** — decompile of `FUN_00803ca0` reveals the call clearly |
| chain classification | **polymorphic_thunked** |
| thunk shapes polymorphic? | **yes** — each uses different MBA constants and rotation amounts |
| thunk shapes visible after stripping? | **yes** — shapes vary in size (8–304 B) and instruction structure |
| direct wrapper → VM impl edge? | **no** — MBA-encoded indirect only |
| signature matching recovers chain? | **partial** — chain identifiable with callgraph + data xrefs; MBA params opaque |

#### D. Data-Reference Concentration

| Data Item | Address | Type | Xrefs | Source function(s) | Interpretation |
|---|---|---|---|---|---|
| `PTR_DAT_00808910` | `0x00808910` | pointer (8B) | **257** | `FUN_00663980` only | **Dominant bytecode anchor** — VM core #1 reads this exclusively |
| `DAT_0080b0d0` | `0x0080b0d0` | u64 (8B) | **107** | widespread | `__obf_entropy_anchor` — read by every MBA computation |
| `PTR_DAT_008073c0` | `0x008073c0` | pointer (8B) | **65** | `FUN_00407ba0` | Bytecode anchor for VM core #2 |
| `PTR_DAT_00807b20` | `0x00807b20` | pointer (8B) | **64** | (separate VM handler) | Another VM function anchor |
| `PTR_DAT_00808280` | `0x00808280` | pointer (8B) | **56** | (separate VM handler) | Another VM function anchor |
| `PTR_DAT_00808630` | `0x00808630` | pointer (8B) | **52** | (separate VM handler) | Another VM function anchor |
| `PTR_DAT_00807770` | `0x00807770` | pointer (8B) | **47** | (separate VM handler) | Another VM function anchor |
| `PTR_DAT_00807ed0` | `0x00807ed0` | pointer (8B) | **46** | (separate VM handler) | Another VM function anchor |
| `DAT_0080b0b0` / `DAT_0080b0b8` / `DAT_0080b0c0` / `DAT_0080b0c8` | `0x0080b0b0`–`0xb0c8` | u64/u32 | 4–5 each | helpers | VM state cluster near entropy anchor |

**Classification:**
- Bytecode/data recovery confidence: **concentrated** (one dominant anchor per VM impl, tied 1:1 to function)
- Data-reference concentration: **high** (257 reads from one function to one pointer is easily spotted)
- The `PTR_DAT_00808910` anchor acts as a dead giveaway: any analyst running "sort data items by xref count" immediately finds the bytecode base pointer.

#### E. Decompiler Resistance

| Layer | Readability (0–5) | Notes |
|---|---|---|
| `entry` | 5 | Trivial; explicitly shows `FUN_004004f0` passed to `__libc_start_main` |
| `FUN_004004f0` (main) | 1 | Very long switch/loop body; structure visible but not source-equivalent |
| `FUN_00803ca0` (entry thunk) | 2 | Decompiles; MBA expressions identifiable as entropy-XOR mixing; call to VM impl visible |
| Tiny 8B thunks (cluster) | 3 | Decompile shows a single call; clustered shape is obvious |
| `FUN_008053c0` (entropy reader) | 4 | Clean; reads global, stores via ptr, returns xmm pair |
| `FUN_00663980` (VM impl #1) | 0 | **Decompilation expected to fail** — 1.7MB, 379K insns; flow limit exceeded |
| `FUN_00407ba0` (VM impl #2) | 0 | **Decompilation expected to fail** — 432KB, 100K insns |

- Protected algorithm semantics: **not recoverable** through decompilation alone
- Wrapper → VM chain: **structurally recoverable** via callgraph + data-xref survey

#### Verdict

Solid protection posture for license_demo. VM bodies are decompiler-proof. The entry-thunk polymorphism (PR26) breaks simple callee-signature matching. **Main risk:** the `PTR_DAT_00808910` anchor with 257 concentrated xrefs is a single high-value pivot for bytecode recovery. The 14-thunk cluster at `0x8051f0`–`0x8052c0` is a visible array structure despite size variation.

---

### config_demo.obfuscated.pr26.seed151616.0a1b47fa

#### A. String and Symbol Hygiene

| Category | Result |
|---|---|
| Source names (`parse_mode`, `fold_value`) | **absent** |
| Protected strings | **absent** |
| `__obf_*` / `obf.vm.*` markers | **absent** |
| Runtime imports (`printf`, `strcmp`, `strtoull`, `getenv`, `timespec_get`) | **present** (expected) |

String hygiene: **clean**.

#### B. VM Topology

| Function | Address | Size | Instructions | CC | Loops | Calls | Role |
|---|---|---|---|---|---|---|---|
| `entry` | `0x004003c0` | ~40 B | ~13 | 2 | 0 | 1 | ELF entry |
| `FUN_004004b0` | `0x004004b0` | 7,380 B | 1,775 | 23 | 4 | 17 | `main` / outer VM orchestrator |
| `FUN_004694d0` | `0x004694d0` | 34 B | 8 | 2 | 0 | 1 | Entry-thunk wrapper layer 1 |
| `FUN_00469500` | `0x00469500` | 163 B | 43 | 2 | 0 | 1 | MBA entry thunk (layer 2); mixes params with anchor |
| `FUN_004695b0` | `0x004695b0` | ~8 B | 4 | 2 | 0 | 1 | Tiny thunk → entropy reader |
| `FUN_0048bab0` | `0x0048bab0` | 74 B | 19 | 1 | 0 | 0 | **Entropy anchor reader** (reads `DAT_0048e0a8`) |
| `FUN_00402ac0` | `0x00402ac0` | ~180 KB (blocks sparse) | ~725 recognized + large unrecognized handler body | 4 | 2 | 1 | **VM implementation body** (Ghidra partially recognizes; spans to `0x44d613`) |
| `FUN_00402190` | `0x00402190` | 842 B | 233 | 7 | 0 | 4 | VM sub-handler / helper island |
| `FUN_00402800` | `0x00402800` | 655 B | 188 | 2 | 0 | 2 | VM helper (single basic block) |
| `FUN_0048b4e0` | `0x0048b4e0` | 12 B | 5 | 2 | 0 | 1 | Tiny entry-thunk variant |
| 6-thunk cluster | `0x004694b0`–`0x00469620` | 8–34 B each | 4–8 | 2 | 0 | 1 | Polymorphic thunk group (all call `FUN_0048bab0`) |

**Notable:** `FUN_00402ac0` has recognized basic blocks at `0x402ac0` and `0x44d507`/`0x44d613` with a ~180 KB gap between. Ghidra reports `size_bytes: 2865` (sum of recognized blocks only). The real handler body spanning `0x403500–0x44d507` is in the gap and contains the bulk of the VM opcodes — Ghidra cannot bound the function completely. This means the 167-xref bytecode anchor reads at `0x40a73a`, `0x40b3d9`, `0x40c09a`, `0x431d54`, etc., are in unbound handler code that Ghidra does not attribute to any named function.

#### C. Wrapper / Entry Thunk / Implementation Mapping

```
entry
  └─> __libc_start_main → FUN_004004b0 [main, 7.3KB]
       ├─ direct call → FUN_004694d0 [34B, layer-1 thunk]
       │    └─ FUN_00469500 [163B, MBA thunk; mixes (param_1 | 0x4694b0) with anchor]
       │         └─ FUN_004695b0 [8B stub] → FUN_0048bab0 [entropy anchor reader, 74B]
       ├─ direct call → FUN_00469610 [calls FUN_0048bab0 directly]
       └─ dispatch → VM handler body (FUN_00402ac0 / unbound handler code 0x403500–0x44d507)
```

| Question | Answer |
|---|---|
| wrapper → entry thunk identifiable? | **yes** — `FUN_004004b0` directly calls `FUN_004694d0` |
| entry thunk → VM impl identifiable? | **partial** — thunk calls MBA router; VM body partially unrecognized by Ghidra |
| chain classification | **polymorphic_thunked** |
| thunk shapes polymorphic? | **yes** — `FUN_00469500` embeds constant `0x4694b0` (obfuscated VM base address) in MBA expression |
| address leaked in MBA expression? | **yes** — `0x4694b0` is embedded as a literal in `FUN_00469500` decompile output |
| direct wrapper → VM impl edge? | **no** |

**Warning:** The constant `0x4694b0` in `FUN_00469500` decompile output is the address of `FUN_004694b0` (another thunk). While not the actual VM implementation address, it is a pivot: an analyst can recover a VM-related address from the decompile output without knowing the MBA semantics.

#### D. Data-Reference Concentration

| Data Item | Address | Type | Xrefs | Concentration | Interpretation |
|---|---|---|---|---|---|
| `PTR_DAT_0048c860` | `0x0048c860` | pointer (8B) | **167** | high | **Dominant bytecode anchor** — reads spread across `0x40a`–`0x435` range (handler body) |
| `DAT_0048e0a8` | `0x0048e0a8` | u64 (8B) | **23** | medium | `__obf_entropy_anchor` |
| `PTR_DAT_0048c8f8` | `0x0048c8f8` | pointer (8B) | **12** | medium | Secondary VM data anchor |
| `DAT_0048e0b8` | `0x0048e0b8` | u1 (1B) | 9 | low | VM state byte |

**Classification:**
- Bytecode/data recovery confidence: **concentrated** (one dominant anchor, 167 xrefs)
- Data-reference concentration: **medium** (167 xrefs spread across unbound handler body, somewhat harder to attribute than license_demo's single-function case)
- The 167-xref anchor is still the primary data recovery pivot; finding it takes one data-xref-sort operation.

#### E. Decompiler Resistance

| Layer | Readability (0–5) | Notes |
|---|---|---|
| `entry` | 5 | Trivial |
| `FUN_004004b0` (main) | 1 | Long switch body; orchestration visible but not semantic |
| `FUN_004694d0` (layer-1 thunk) | 4 | Single call; essentially transparent |
| `FUN_00469500` (MBA thunk) | 2 | MBA expression output with VM address literal; chain partially visible |
| `FUN_0048bab0` (entropy reader) | 4 | Clean; reads global, stores via ptr |
| `FUN_00402ac0` / VM handler body | 0–1 | Ghidra partially bounds the function; handler regions in gap are unlabeled |

- Protected algorithm semantics (`parse_mode`, `fold_value`): **not recoverable** through decompilation
- VM address leakage via MBA constant: **present** (`0x4694b0` in `FUN_00469500`)

#### Verdict

Good protection posture. VM body is decompiler-resistant. One concern: `FUN_00469500`'s MBA expression embeds a VM-related address literal as a plaintext constant — a minor information leak. Bytecode anchor concentration is the main PR27 target.

---

### vm_workflow_demo.obfuscated.pr26.seed151616.2f7974bf

#### A. String and Symbol Hygiene

| Category | Result |
|---|---|
| Source names (`classify_byte`, `route_score`) | **absent** |
| Protected strings | **absent** |
| `__obf_*` / `obf.vm.*` markers | **absent** |
| Runtime imports (`printf`, `strlen`, `strtoull`, `getenv`, `timespec_get`) | **present** (expected) |

String hygiene: **clean**.

#### B. VM Topology

| Function | Address | Size | Instructions | CC | Loops | Calls | Role |
|---|---|---|---|---|---|---|---|
| `entry` | `0x004003c0` | ~40 B | ~13 | 2 | 0 | 1 | ELF entry |
| `FUN_004004b0` | `0x004004b0` | 2,389 B | 559 | 19 | 4 | 14 | `main` / outer dispatcher |
| `FUN_00401d50` | `0x00401d50` | 1,244 B | 322 | 10 | 2 | 3 | **Polymorphic multi-target router**; MBA-computes dispatch tag; routes to two VM impls or DoS-traps |
| `FUN_004029f0` | `0x004029f0` | **176 KB** | **40,399** | 5 | 7 | 1 | **VM impl #1** (`classify_byte`?) — reads `PTR_DAT_004baf38` |
| `FUN_0042db90` | `0x0042db90` | **118 KB** | **27,147** | 5 | 7 | 1 | **VM impl #2** (`route_score`?) — separate anchor |
| `FUN_004b8f70` | `0x004b8f70` | 74 B | 19 | 1 | 0 | 0 | **Entropy anchor reader** (reads `DAT_004be0a0`, 17 xrefs) |
| 5-thunk cluster | `0x004b8f20`–`0x004b8f60` | 8 B each | 4 each | 2 | 0 | 1 | Polymorphic thunk stubs → `FUN_004b8f70` |
| `FUN_00401d40` | `0x00401d40` | small | — | — | — | — | Additional caller of entropy reader |
| `FUN_0044a850`, `FUN_0044a860` | `0x0044a850`+ | small | — | — | — | — | Additional callers of entropy reader |
| `FUN_004018a0` | `0x004018a0` | 38 B | 8 | 2 | 0 | 1 | **Time helper** — `timespec_get` wrapper (not a thunk) |
| `FUN_00400e10`, `FUN_004011d0` | various | 954–1742 B | 255–417 | 7–9 | 0–2 | 3–4 | VM sub-handlers / helper islands |

**Notable — `FUN_00401d50` polymorphic router decompile summary:**
- Calls `FUN_004b8f40()` (8B entropy thunk)
- MBA-computes a 32-bit discriminator using 15+ operations over 64-bit entropy xmm pair and rotation constants (`0xc8c9b92b21ee2fe0`, `0x36b64270d80d8ae8`, etc.)
- Compares discriminator against **6 tag constants**: `0x11ab128d`, `0x4942a672`, `0x57f4eace`, `0x5b757754`, `0x78ba5110`, `0x7eeab1bd`
- Routes to `FUN_004029f0` or `FUN_0042db90` based on tag match
- If no match → **DSE trap loop** (`while local_6c != 1000000`) + returns `0xffffffff`

#### C. Wrapper / Entry Thunk / Implementation Mapping

```
entry
  └─> __libc_start_main → FUN_004004b0 [main, 2.4KB]
       └─ direct call → FUN_00401d50 [1.2KB, polymorphic multi-router]
            ├─ FUN_004b8f40 [8B stub] → FUN_004b8f70 [entropy anchor reader, 74B]
            ├─ MBA-tag == 0x4942a672/0x5b757754/0x78ba5110 → FUN_004029f0 [VM impl #1, 176KB]
            ├─ MBA-tag == 0x11ab128d/0x7eeab1bd → FUN_0042db90 [VM impl #2, 118KB]
            └─ tag mismatch → DSE trap (1M-iter loop) → return -1
```

| Question | Answer |
|---|---|
| wrapper → entry thunk identifiable? | **yes** — `FUN_004004b0` directly calls `FUN_00401d50` |
| entry thunk → VM impl identifiable? | **yes** — decompile of `FUN_00401d50` shows both target addresses |
| chain classification | **polymorphic_thunked** (multi-target) |
| thunk shapes polymorphic? | **yes** — 5 cluster thunks plus `FUN_00401d50` all distinct |
| tag constants obfuscated? | **yes** — MBA pre-computation; IR harness confirms `raw_opcode_compares: 0` |
| direct wrapper → VM impl edge? | **no** — always via MBA router |
| DoS resistance | **yes** — 1M-iter trap loop fires on tag mismatch |

**Callgraph recoverable:** The chain `FUN_004004b0 → FUN_00401d50 → {FUN_004029f0, FUN_0042db90}` is visible at the callgraph level. An analyst knows exactly which two VM functions are targets. The MBA-computed dispatch tag does not hide the targets — only the routing condition.

#### D. Data-Reference Concentration

| Data Item | Address | Type | Xrefs | Source function | Interpretation |
|---|---|---|---|---|---|
| `PTR_DAT_004baf38` | `0x004baf38` | pointer (8B) | **53** | `FUN_004029f0` | Bytecode anchor for VM impl #1 |
| `PTR_DAT_004bbe88` | `0x004bbe88` | pointer (8B) | **49** | (VM impl body) | Secondary anchor / handler table |
| `PTR_DAT_004bb248` | `0x004bb248` | pointer (8B) | **47** | (VM impl body) | Handler table shard |
| `PTR_DAT_004bb558` | `0x004bb558` | pointer (8B) | **43** | (VM impl body) | Handler table shard |
| `PTR_DAT_004bb868` | `0x004bb868` | pointer (8B) | **43** | (VM impl body) | Handler table shard |
| `PTR_DAT_004bbb78` | `0x004bbb78` | pointer (8B) | **32** | (VM impl body) | Handler table shard |
| `DAT_004be0a0` | `0x004be0a0` | u64 (8B) | **27** | widespread | `__obf_entropy_anchor` |
| `DAT_004be0b0` | `0x004be0b0` | u1 (1B) | 9 | (VM impl body) | VM state byte |

**Classification:**
- Bytecode/data recovery confidence: **moderate** (6 pointer anchors with 32–53 xrefs each; more distributed than license_demo)
- Data-reference concentration: **medium** (6 anchors clustered at `0x4baf38`–`0x4bbb78`, all within 12KB; easily enumerable as a group)
- Notable: the 6 pointer anchors are in a tight address cluster (`0x4baf38`, `0x4bb248`, `0x4bb558`, `0x4bb868`, `0x4bbb78`, `0x4bbe88` — spacing ~0x310). This regular spacing suggests a generated table structure — another recovery pivot.

#### E. Decompiler Resistance

| Layer | Readability (0–5) | Notes |
|---|---|---|
| `entry` | 5 | Trivial |
| `FUN_004004b0` (main) | 2 | Moderate switch/loop; structure visible |
| `FUN_00401d50` (MBA router) | 2 | Decompiles; all 6 tag constants and both call targets visible; DoS trap visible |
| Tiny 8B thunks | 3 | Each single call |
| `FUN_004b8f70` (entropy reader) | 4 | Clean; reads global, stores via ptr |
| `FUN_004018a0` (time helper) | 5 | Directly readable as `timespec_get` wrapper |
| `FUN_004029f0` (VM impl #1) | 0 | **Decompilation expected to fail** — 176KB, 40K insns |
| `FUN_0042db90` (VM impl #2) | 0 | **Decompilation expected to fail** — 118KB, 27K insns |

- Protected algorithm semantics: **not recoverable** through decompilation
- Both VM implementation addresses: **directly visible** in `FUN_00401d50` decompile output

#### Verdict

Good protection for the VM bodies themselves. The multi-router (`FUN_00401d50`) decompiles cleanly and exposes both VM target addresses and all 6 dispatch tag constants. An analyst who decompiles just the router recovers the full structure without touching the VM bodies. The DoS trap is correctly placed. **Main concern:** callgraph topology of vm_workflow_demo is the most recoverable of the three — the router makes it a single decompile to learn everything about the routing.

---

## Cross-Benchmark Observations

### Entropy Anchor Reader Shape

All three binaries contain an entropy anchor reader with **identical structure**:
- 74 bytes, 19 instructions, 1 basic block, 0 calls, returns 128-bit xmm pair
- Reads the 64-bit `__obf_entropy_anchor` global into both halves of the return pair
- Writes the anchor through a pointer slot
- Recognized as `FUN_008053c0` / `FUN_0048bab0` / `FUN_004b8f70`

This is a cross-binary fingerprint. Any Ghidra FLIRT/Function ID rule matching this shape will immediately locate the entropy anchor in any future binary.

### Polymorphic Thunk Cluster Pattern

All three binaries contain a dense array of small (8–34 B) stub functions that call the entropy anchor reader. Each stub is the entry point used by a specific call site. The clusters are:
- license_demo: `0x8051f0`–`0x8052c0` (~14 stubs, 8 B each)
- config_demo: `0x4694b0`–`0x469620` (8+ stubs, 8–34 B)
- vm_workflow_demo: `0x4b8f20`–`0x4b8f60` (5 stubs, 8 B each)

These clusters look like function pointer tables at first glance (consecutive addresses, tiny sizes) and are immediately visible in `list_functions` output sorted by address. PR26 added size variation, but the cluster pattern remains.

### MBA Router Presence

All three binaries have at least one medium-sized (163–1244 B) MBA-encoded router between the entry thunks and the VM implementations. These routers are decompilable and expose call targets. The router is the most information-dense single function for an analyst: decompiling one small function reveals the full dispatch structure.

### Bytecode Anchor Clustering

In all three binaries, the data pointer anchors (the highest-xref pointer objects) are clustered in a small address range:
- license_demo: `0x807770`–`0x808910` (6 anchors in ~16 KB)
- config_demo: `0x48c860`–`0x48c8f8` (2 anchors, tight)
- vm_workflow_demo: `0x4baf38`–`0x4bbe88` (6 anchors in ~12 KB, ~0x310 spacing)

The regular spacing in vm_workflow_demo (`~0x310` = 784 bytes) is especially distinctive — it implies a generated per-bytecode-shard pointer table.

### Symbol / String Leakage Trends

Leakage trend: **none from protected code**. All three binaries are clean. The only surviving named symbols are:
- C++ stdlib stubs (`operator<<`, `now`, `strlen`, etc.) — unavoidable
- libc PLT entries (`printf`, `strcmp`, `strtoull`, `getenv`, `timespec_get`) — unavoidable
- `entry` — ELF standard

### Thunk Polymorphism Visibility

PR26 thunk polymorphism is structurally visible via callgraph analysis: each thunk calls the anchor reader and computes different MBA expressions using different rotation constants. The *shapes* differ, but the *target* (entropy reader) is the same. An analyst can still pivot from any thunk to the entropy reader and from there to the VM implementation.

---

## PR27 Baseline Summary

| Benchmark | bytecode/data confidence | top data xref concentration | wrapper chain confidence | VM impl readability | PR27 priority |
|---|---|---|---|---|---|
| license_demo | concentrated (1 dominant: 257 xrefs) | HIGH — single pointer, single function | polymorphic_thunked; structurally recoverable | 0 (fail) | HIGH — anchor splitting |
| config_demo | concentrated (1 dominant: 167 xrefs, unbound body) | MEDIUM — reads spread in unbound code | polymorphic_thunked; partially recoverable | 0 (fail) | HIGH — anchor splitting + address-literal in MBA |
| vm_workflow_demo | moderate (6 anchors, 32–53 xrefs each) | MEDIUM — 6 clustered anchors, regular spacing | polymorphic_thunked; router exposes both targets | 0 (fail) | MEDIUM — anchor scatter + router opacity |

---

## Recommended PR27 Focus

Based on Ghidra evidence:

### 1. Bytecode Shard Globals — HIGH PRIORITY (all three)

**Evidence:** `PTR_DAT_00808910` (257 xrefs, license_demo), `PTR_DAT_0048c860` (167 xrefs, config_demo), cluster of 6 anchors in vm_workflow_demo.

**Action:** Split each VM's bytecode base pointer into at least 2–3 globals, offset and XOR-masked at access time. Add 2–4 decoy pointer globals nearby with similar xref counts (non-functional reads from handler code). Eliminate the single dominant xref object that immediately reveals the bytecode base.

### 2. Decoy Bytecode Blobs — HIGH PRIORITY

**Evidence:** All anchors point into real handler code. No decoy data blobs exist alongside real ones.

**Action:** Introduce 2–3 globals with similar size and access patterns to the real bytecode anchor, accessed by bogus handler code. These should produce plausible-looking reads in the data xref table.

### 3. Retkey/Seed/Cache Scattering — MEDIUM PRIORITY

**Evidence:** `DAT_0080b0d0` (license_demo, 107 xrefs), `DAT_0048e0a8` (config_demo, 23 xrefs), `DAT_004be0a0` (vm_workflow_demo, 27 xrefs) are each identified immediately as the entropy anchor due to high read counts concentrated near the thunk cluster.

**Action:** Add 2–3 decoy u64 globals near each entropy anchor with comparable access frequency. Use the same store-via-pointer pattern to make decoys shape-match the real anchor reader.

### 4. Pointer Materialization Around Bytecode Bases — MEDIUM PRIORITY (vm_workflow_demo)

**Evidence:** The 6 pointer anchors in vm_workflow_demo have spacing `~0x310` — a generated table fingerprint.

**Action:** Scatter anchor addresses non-uniformly; insert non-power-of-2 gaps between anchor globals. Consider computing one or more base pointers dynamically (e.g., via an opaque GEP) rather than reading from a flat global.

### 5. MBA Literal Leakage — LOW-MEDIUM PRIORITY (config_demo)

**Evidence:** `FUN_00469500` decompile contains `0x4694b0` as a plaintext constant — the address of a VM-related entry thunk.

**Action:** Ensure that any address embedded in an MBA expression is masked or split so it cannot be read directly from decompiler output. Use `opaque_gep` or multi-level XOR mask to conceal the address.

### 6. Router Opacity — MEDIUM PRIORITY (vm_workflow_demo)

**Evidence:** `FUN_00401d50` decompiles to readable output that exposes both VM target addresses and all 6 tag constants.

**Action:** Consider wrapping the tag comparison in an opaque predicate or adding a decoy comparison path. The current router is informative enough that one decompile reveals the full dispatch structure. Adding one bogus branch target (that traps at runtime) would force an analyst to trace more.

### 7. Entry-Thunk Cluster Shape — LOW PRIORITY

**Evidence:** Thunk clusters at fixed address ranges with tiny (8 B) uniform sizes are visible as arrays in function listings.

**Action:** Vary thunk sizes more aggressively (16–128 B range) and intersperse with non-thunk helper functions to break the cluster appearance.
