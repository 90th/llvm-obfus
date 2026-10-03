; RUN: %python %S/../Inputs/obf-clang-dll-response.py --check-tokenizer %clang_wrapper_script | %FileCheck %s
;
; Literal quotes cannot appear in native Windows filenames. Check their escape
; parity separately from the native nested-response link and loader regression.
; CHECK: DLL_RESPONSE_QUOTING_OK

define void @dummy() {
entry:
  ret void
}
