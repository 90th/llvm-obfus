; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-vm-owner-provenance.yaml -passes=obf-string-encode -disable-output %s 2>&1 | %FileCheck %s

@.secret = private constant [7 x i8] c"barely\00"
@public_forwarding_cell = global ptr @.secret

define i8 @verify_owned_strings() {
entry:
  %pointer = load ptr, ptr @public_forwarding_cell
  %byte = load i8, ptr %pointer
  ret i8 %byte
}

; CHECK: LLVM ERROR: strong_vm invariant violation: string .secret would remain plaintext; reason=has non-function use; owner=verify_owned_strings
