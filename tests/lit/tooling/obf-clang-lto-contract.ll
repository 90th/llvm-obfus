; REQUIRES: system-linux-x86-64, has-lld-llvm-match
; RUN: %python %S/../Inputs/lto_protection_matrix.py --matrix contract --wrapper %obf_clang --clang %raw_clang --ar %llvm_ar --nm %llvm_nm --objdump %llvm_objdump --runtime %obf_runtime --work %t

define void @dummy() {
entry:
  ret void
}
