; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-vm-owner-provenance.yaml -passes=obf-string-encode -disable-output %s 2>&1 | %FileCheck %s

@.secret = private constant [7 x i8] c"barely\00"
@__obf_vm_ptrconst_invented = private constant ptr @.secret

define i8 @verify_owned_strings() {
entry:
  %pointer = load ptr, ptr @__obf_vm_ptrconst_invented
  %integer = ptrtoint ptr %pointer to i64
  %forwarded = inttoptr i64 %integer to ptr
  %byte = load i8, ptr %forwarded
  ret i8 %byte
}

; CHECK: LLVM ERROR: strong_vm invariant violation: string .secret would remain plaintext; reason=strong_vm_no_global_plaintext: forwarded pointer table use; owner=verify_owned_strings
