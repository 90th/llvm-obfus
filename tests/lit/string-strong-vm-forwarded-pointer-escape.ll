; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/string-strong-vm-forwarded-pointer-escape.yaml -passes=obf-string-encode -disable-output %s 2>&1 | %FileCheck %s

@.secret = private unnamed_addr constant [8 x i8] c"delta-7\00"
@.secret.ptr = private unnamed_addr constant ptr @.secret

define ptr @return_forwarded_pointer() {
entry:
  %p = load ptr, ptr @.secret.ptr, align 8
  ret ptr %p
}

; CHECK: LLVM ERROR: strong_vm invariant violation: string .secret would remain plaintext; reason=strong_vm_no_global_plaintext: forwarded pointer table use; owner=return_forwarded_pointer
