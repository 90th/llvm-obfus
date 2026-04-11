; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/string-encode-lazy-phi.yaml -passes=obf-string-encode -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/string-encode-lazy-phi.yaml -passes=obf-string-encode -S %s -o %t
; RUN: %lli %t

@.secret = private unnamed_addr constant [7 x i8] c"secret\00"
@.plain = private unnamed_addr constant [6 x i8] c"plain\00"

define i32 @first_char(ptr %p) {
entry:
  %first = load i8, ptr %p
  %is_s = icmp eq i8 %first, 115
  %code = select i1 %is_s, i32 0, i32 1
  ret i32 %code
}

define i32 @main() {
entry:
  br i1 true, label %use_secret, label %use_plain

use_secret:
  br label %merge

use_plain:
  br label %merge

merge:
  %chosen = phi ptr [ @.secret, %use_secret ], [ @.plain, %use_plain ]
  %result = call i32 @first_char(ptr %chosen)
  ret i32 %result
}

; CHECK: @.secret = private unnamed_addr global [7 x i8]
; CHECK-NOT: @llvm.global_ctors = appending global
; CHECK: use_secret:
; CHECK: call ptr @__obf_family_
; CHECK: phi ptr
; CHECK: define internal ptr @__obf_family_
