; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-vm-owner-provenance.yaml -passes=obf-string-encode -disable-output %s 2>&1 | %FileCheck %s

@.secret = private constant [7 x i8] c"barely\00"

define i8 @verify_owned_strings() #0 {
entry:
  %byte = load i8, ptr @.secret
  ret i8 %byte
}

attributes #0 = { "obf.string.owner.seed"="6062" }

; CHECK: LLVM ERROR: incomplete string protection ownership in 'verify_owned_strings'
