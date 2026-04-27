; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/string-strong-vm-plaintext-violation.yaml -passes=obf-string-encode -S %s -o %t 2>&1 | %FileCheck %s

@.skip = private unnamed_addr constant [22 x i8] c"strong-vm-skip-string\00"

define ptr @strong_skip_string() {
entry:
  ret ptr @.skip
}

; CHECK: LLVM ERROR: strong_vm invariant violation: string .skip would remain plaintext; reason=strong_vm_no_global_plaintext: no local string strategy; owner=strong_skip_string
