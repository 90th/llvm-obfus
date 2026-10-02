; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-vm-owner-provenance.yaml -passes=obf-string-encode -disable-output %s 2>&1 | %FileCheck %s

@.public.secret = constant [7 x i8] c"barely\00"

define i8 @verify_owned_strings() {
entry:
  %byte = load i8, ptr @.public.secret
  ret i8 %byte
}

; CHECK: LLVM ERROR: strong_vm invariant violation: string .public.secret would remain plaintext; reason=unsupported string global kind; owner=verify_owned_strings
