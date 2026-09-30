; REQUIRES: system-linux, has-lld-llvm-match
; RUN: %python %S/../Inputs/lto_retained_orchestrator_promotion.py --wrapper %obf_clang --opt %opt --plugin %obf_plugin --dis llvm-dis --work %t

define void @dummy() {
entry:
  ret void
}
