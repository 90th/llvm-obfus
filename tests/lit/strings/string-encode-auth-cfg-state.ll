; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-cfg-state.yaml -passes='obf-string-encode,obf-control-flatten,obf-cfg-state-cleanup' -S %s -o - | %FileCheck %s --check-prefix=CHECK
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-cfg-state.yaml -passes='obf-string-encode,obf-control-flatten,obf-cfg-state-cleanup' -S %s -o %t
; RUN: %lli %t

@.secret = private unnamed_addr constant [7 x i8] c"secret\00"

define i32 @first_char(ptr %p) {
entry:
  %first = load i8, ptr %p
  %is_s = icmp eq i8 %first, 115
  %code = select i1 %is_s, i32 0, i32 1
  ret i32 %code
}

define i32 @main() {
entry:
  br i1 true, label %left, label %right

left:
  %left_result = call i32 @first_char(ptr @.secret)
  ret i32 %left_result

right:
  %right_result = call i32 @first_char(ptr @.secret)
  ret i32 %right_result
}

; CHECK-NOT: @__obf_get_cfg_state
; CHECK-NOT: @__obf_get_expected_cfg_state
; CHECK-LABEL: define i32 @main()
; CHECK: %obf.state = phi i32
; CHECK-DAG: call ptr @[[STRHELPER:__obf_[A-Za-z0-9_]+]](ptr {{.*}}, i32 %obf.state, i32 {{-?[0-9]+}}, i64 7, i64 {{-?[0-9]+}})
; CHECK-DAG: call ptr @[[STRHELPER]](ptr {{.*}}, i32 %obf.state, i32 {{-?[0-9]+}}, i64 7, i64 {{-?[0-9]+}})
; CHECK: define internal ptr @[[STRHELPER]](ptr %desc, i32 %cfg_state, i32 %expected_state, i64 %trusted_length, i64 %trusted_binding) {
; CHECK: %obf.str.cfg.match = icmp eq i32 %cfg_state, %expected_state
; CHECK: br i1 %obf.str.cfg.match, label %decode, label %state_mismatch
; CHECK-NOT: load ptr, ptr
; CHECK-NOT: phi ptr
; CHECK: state_mismatch:
; CHECK: call void @llvm.trap()
; CHECK: unreachable
; CHECK: decode:
; CHECK: call ptr @rt_core_sd2(ptr %desc, i64 %trusted_length, i64 %trusted_binding)
; CHECK: ret ptr
