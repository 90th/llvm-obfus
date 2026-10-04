; REQUIRES: system-linux-x86-64, has-lld-llvm-match
; RUN: %python %S/../Inputs/lto_protection_matrix.py --matrix forwarded --wrapper %obf_clang --clang %raw_clang --ar %llvm_ar --nm %llvm_nm --objdump %llvm_objdump --runtime %obf_runtime --work %t
;
; Paired-TU strong_vm string forwarding is FullLTO-owned or rejected before a
; ThinLTO link. Native output, plaintext absence and the hidden-token VM entry
; are checked together. Ordinary VM and local forwarding are success controls.

define void @dummy() {
entry:
  ret void
}
