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
; CHECK-DAG: call ptr @[[STRHELPER:__obf_[A-Za-z0-9_]+]](ptr {{.*}}, i32 %obf.state, i32 {{-?[0-9]+}}, i64 7)
; CHECK-DAG: call ptr @[[STRHELPER]](ptr {{.*}}, i32 %obf.state, i32 {{-?[0-9]+}}, i64 7)
; CHECK: define internal ptr @[[STRHELPER]](ptr %desc, i32 %cfg_state, i32 %expected_state, i64 %trusted_length) {
; CHECK: %obf.str.cfg.match = icmp eq i32 %cfg_state, %expected_state
; CHECK: br i1 %obf.str.cfg.match, label %state_check, label %state_mismatch
; CHECK: state_check:
; CHECK: %obf.str.state.addr = getelementptr inbounds{{.*}} i32 0, i32 3
; CHECK: %obf.str.state.ptr = load ptr, ptr %obf.str.state.addr
; CHECK: %obf.str.state = load i32, ptr %obf.str.state.ptr
; CHECK: %obf.str.is_decoded = icmp eq i32 %obf.str.state, 1
; CHECK: br i1 %obf.str.is_decoded, label %fast_path, label %slow_path
; CHECK: state_mismatch:
; CHECK: call void @llvm.trap()
; CHECK: unreachable
; CHECK: fast_path:
; CHECK: %obf.str.destination.addr = getelementptr inbounds{{.*}} i32 0, i32 0
; CHECK: %obf.str.destination = load ptr, ptr %obf.str.destination.addr
; CHECK: br label %merge
; CHECK: slow_path:
; CHECK: call ptr @rt_core_sd1(ptr %desc, i64 %trusted_length)
; CHECK: br label %merge
; CHECK: merge:
; CHECK: %obf.str.result = phi ptr [ %obf.str.destination, %fast_path ], [ {{%[A-Za-z0-9_.]+}}, %slow_path ]
; CHECK: ret ptr %obf.str.result
