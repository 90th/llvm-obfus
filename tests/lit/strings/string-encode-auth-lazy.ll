; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-lazy.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o - | %FileCheck %s --check-prefix=IR
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-lazy.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
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
  %result = call i32 @first_char(ptr @.secret)
  ret i32 %result
}

; IR: @.secret = private unnamed_addr global [7 x i8] zeroinitializer
; IR-NOT: c"secret\00"
; IR-NOT: @llvm.global_ctors = appending global
; IR: @__obf_string_ct__secret = internal constant [7 x i8]
; IR: @__obf_string_desc__secret = internal constant
; IR: call ptr @__obf_family_auth_v1(ptr @__obf_string_desc__secret, i32 0, i32 0, i64 7)
; IR-LABEL: define internal ptr @__obf_family_auth_v1(ptr %desc, i32 %cfg_state, i32 %expected_state, i64 %trusted_length) {
; IR: %obf.str.cfg.match = icmp eq i32 %cfg_state, %expected_state
; IR: br i1 %obf.str.cfg.match, label %state_check, label %state_mismatch
; IR: state_check:
; IR: %obf.str.state.addr = getelementptr inbounds{{.*}} i32 0, i32 3
; IR: %obf.str.state.ptr = load ptr, ptr %obf.str.state.addr
; IR: %obf.str.state = load i32, ptr %obf.str.state.ptr
; IR: %obf.str.is_decoded = icmp eq i32 %obf.str.state, 1
; IR: br i1 %obf.str.is_decoded, label %fast_path, label %slow_path
; IR: state_mismatch:
; IR: call void @llvm.trap()
; IR: unreachable
; IR: fast_path:
; IR: %obf.str.destination.addr = getelementptr inbounds{{.*}} i32 0, i32 0
; IR: %obf.str.destination = load ptr, ptr %obf.str.destination.addr
; IR: br label %merge
; IR: slow_path:
; IR: call ptr @rt_core_sd1(ptr %desc, i64 %trusted_length)
; IR: br label %merge
; IR: merge:
; IR: %obf.str.result = phi ptr [ %obf.str.destination, %fast_path ],
; IR: ret ptr %obf.str.result
