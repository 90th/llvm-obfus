; REQUIRES: system-linux-x86-64, has-lld-llvm-match
;
; Managed partial links preserve actual weak/strong winners and scoped readers.
; The matrix uses indexed native return/effect oracles, both provider orders,
; late winners, repeated partials, actual archive extraction, local collisions,
; ordinary VM/no-protection controls, and raw-history/manifest boundaries.
; It covers C/C++, O0/O2, and reports on/off without rerunning the broad phase.
; Native execution checks values and effects, not VM execution at every site.
; RUN: %python %S/../Inputs/native_string_ownership.py --wrapper %obf_clang --wrapperxx %obf_clangxx --clang %raw_clang --ar %llvm_ar --runtime %obf_runtime --format elf --phase partial --work %t

define void @dummy() {
entry:
  ret void
}
