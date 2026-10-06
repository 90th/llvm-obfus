; REQUIRES: system-linux-x86-64, has-lld-llvm-match, has-self-checksum-binder
;
; The raw provider, protected shared library, and raw native consumer are built
; independently with normal ELF/C++ startup and the configured wrapper runtime.
; O0/O2 x vm/strong_vm x reports on/off check exact typed exception payloads,
; ordered exact-once host cleanup, nonthrow effects, and repeated transitions.
; Local catch/cleanup bodies remain exact-rule policy exclusions. A separate
; same-TU incoming invoke is preserved by vm and rejected by strong_vm.
; Compiler reports corroborate emission, not execution. Retained result.json
; records per-row executables/libraries for independent VM-entry debugger traces.
; RUN: %python %S/../Inputs/cpp_elf_unwind.py --wrapper %obf_clangxx --clang %raw_clang --work %t
;

define void @dummy() {
entry:
  ret void
}
