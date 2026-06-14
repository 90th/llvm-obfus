; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-ctor.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-ctor.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: %lli %t

@.secret = private unnamed_addr constant [7 x i8] c"secret\00"
@.plain = private unnamed_addr constant [6 x i8] c"plain\00"

define ptr @leak_secret() {
entry:
  ret ptr @.secret
}

define i32 @main() {
entry:
  %secret.ptr = getelementptr inbounds [7 x i8], ptr @.secret, i64 0, i64 0
  %first = load i8, ptr %secret.ptr
  %is_s = icmp eq i8 %first, 115
  %code = select i1 %is_s, i32 0, i32 1
  ret i32 %code
}

define ptr @get_plain() {
entry:
  ret ptr @.plain
}

; CHECK: @.secret = private unnamed_addr global [7 x i8]
; CHECK-NOT: c"secret\00"
; CHECK: @.plain = private unnamed_addr global [6 x i8]
; CHECK-NOT: c"plain\00"
; CHECK-NOT: @llvm.global_ctors = appending global
; CHECK: define internal ptr @__obf_family_
