; REQUIRES: system-windows-x86-64
;
; Native COFF boundary milestone. Real MSVC link/lld-link maps establish archive
; extraction. Raw manifests bind exact object/member bytes. Rejected links must
; remove their new primary image. Exact return/effect values cover successful
; links, ordinary VM, numeric arrays/structs, and mutable argument buffers.
; Bounded forwarding and absent local leaves reject. Actual maps prove that
; /OPT:NOREF keeps and /OPT:REF discards the frontend-reachable static reader.
; Resolve the final local owner identity from the object's ownership section.
; MSVC uses Static symbols. LLD uses symbol/section contribution authority.
; RUN: %python %S/../Inputs/native_string_ownership.py --wrapper %obf_clang --wrapperxx %obf_clangxx --clang %raw_clang --ar %llvm_ar --runtime %obf_runtime --format coff --phase boundaries --work %t

define void @dummy() {
entry:
  ret void
}
