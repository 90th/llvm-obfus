; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-lazy.yaml -passes='default<O2>' -S %s -o %t
; RUN: %FileCheck %s --input-file=%t
; RUN: %opt -passes=verify -disable-output %t
; RUN: %lli %t

@.secret = private unnamed_addr constant [7 x i8] c"secret\00"
@runtime_flag = global i1 true

define i32 @first_char(ptr %p) {
entry:
  %first = load volatile i8, ptr %p, align 1
  %is_s = icmp eq i8 %first, 115
  %code = select i1 %is_s, i32 0, i32 1
  ret i32 %code
}

define i32 @main() {
entry:
  %flag = load volatile i1, ptr @runtime_flag, align 1
  br i1 %flag, label %authenticated, label %fallback

authenticated:
  %result = call i32 @first_char(ptr @.secret)
  ret i32 %result

fallback:
  %fallback_result = call i32 @first_char(ptr @.secret)
  ret i32 %fallback_result
}

; CHECK: define internal ptr @[[AUTH_HELPER:[A-Za-z0-9_.$-]+]](ptr [[DESC:%[-A-Za-z$._0-9]+]], i32 [[CFG:%[-A-Za-z$._0-9]+]], i32 [[EXPECTED:%[-A-Za-z$._0-9]+]], i64 [[LENGTH:%[-A-Za-z$._0-9]+]], i64 [[BINDING:%[-A-Za-z$._0-9]+]], ptr [[TOPOLOGY:%[-A-Za-z$._0-9]+]]) {
; CHECK: [[MATCH:%[-A-Za-z$._0-9]+]] = icmp eq i32 [[CFG]], [[EXPECTED]]
; CHECK: br i1 [[MATCH]], label %[[MATCH_LABEL:[-A-Za-z$._0-9]+]], label %[[MISMATCH_LABEL:[-A-Za-z$._0-9]+]]
; CHECK: [[MISMATCH_LABEL]]:
; CHECK: call void @llvm.trap()
; CHECK: unreachable
; CHECK: [[MATCH_LABEL]]:
; CHECK-NOT: phi ptr
; CHECK: call ptr @rt_core_sd3(ptr [[DESC]], i64 [[LENGTH]], i64 [[BINDING]], ptr [[TOPOLOGY]])
