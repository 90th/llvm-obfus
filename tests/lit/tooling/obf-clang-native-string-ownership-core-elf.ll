; REQUIRES: system-linux-x86-64, has-lld-llvm-match
;
; Core milestone: supported local direct strings, managed external plaintext,
; combined temporary objects, and separate native final links. The runner uses
; C/C++, O0/O2, reports on/off, GNU ld and ld.lld. Native values and effects are
; the execution oracle. Reports and diagnostic text do not decide acceptance.
; RUN: %python %S/../Inputs/native_string_ownership.py --wrapper %obf_clang --wrapperxx %obf_clangxx --clang %raw_clang --ar %llvm_ar --runtime %obf_runtime --format elf --phase core --work %t

define void @dummy() {
entry:
  ret void
}
