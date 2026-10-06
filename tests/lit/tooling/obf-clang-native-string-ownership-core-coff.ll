; REQUIRES: system-windows-x86-64
;
; Native COFF core milestone. Use the configured Windows Clang host, normal CRT
; startup, obf-clang/obf-clang++, MSVC link and lld-link. Do not substitute a
; cross-target link for native execution. The matrix covers C/C++, O0/O2, and
; reports on/off, including combined jobs with temporary frontend objects.
; RUN: %python %S/../Inputs/native_string_ownership.py --wrapper %obf_clang --wrapperxx %obf_clangxx --clang %raw_clang --ar %llvm_ar --runtime %obf_runtime --format coff --phase core --work %t

define void @dummy() {
entry:
  ret void
}
