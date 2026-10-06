; REQUIRES: system-linux-x86-64, has-lld-llvm-match
;
; Boundary milestone: cells/tables, actual archive extraction, unused members,
; prevailing weak/strong definitions, hash-bound raw manifests, invalid required
; provenance, bounded forwarding, actual local leaves, partial links, ordinary
; VM, numeric arrays/structs, runtime buffers, and GNU output-option sentinels.
; Each rejection has an actual native link/execution control. Each invocation
; retains isolated evidence and runs its compiler/linker jobs serially.
; RUN: %python %S/../Inputs/native_string_ownership.py --wrapper %obf_clang --wrapperxx %obf_clangxx --clang %raw_clang --ar %llvm_ar --runtime %obf_runtime --format elf --phase boundaries --work %t

define void @dummy() {
entry:
  ret void
}
