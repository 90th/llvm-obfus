; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-compare.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-compare.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: %lli %t

@.secret = private unnamed_addr constant [8 x i8] c"delta-7\00"

declare i32 @bcmp(ptr, ptr, i64)

define i32 @main() {
entry:
  %cmp = call i32 @bcmp(ptr @.secret, ptr @.secret, i64 7)
  %ok = icmp eq i32 %cmp, 0
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK: @.secret = private unnamed_addr global [8 x i8]
; CHECK-NOT: c"delta-7\00"
; CHECK-NOT: @llvm.global_ctors = appending global
; CHECK-NOT: @__obf_get_cfg_state
; CHECK-NOT: @__obf_get_expected_cfg_state
; CHECK-NOT: @__obf_get__secret
; CHECK: %obf.inline.str = alloca [8 x i8]
; CHECK: call i32 @bcmp(ptr %
