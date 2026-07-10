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
; IR: @__obf_string_destination_ref__secret = internal constant { i64, ptr }
; IR: @__obf_string_ciphertext_ref__secret = internal constant { i64, ptr }
; IR: @__obf_string_build_key_ref__secret = internal constant { i64, ptr }
; IR: @__obf_string_state_ref__secret = internal global { i64, i64, i64 }
; IR: @__obf_string_desc__secret = internal constant { i32, i32, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, [16 x i8], [16 x i8], ptr, ptr, ptr, ptr } { i32 3, i32 1, i64 7
; IR-SAME: i64 7, i64 7, i64 32
; IR: @__obf_string_topology__secret = internal constant { ptr, ptr, ptr, i64, ptr, ptr, i64, ptr, ptr, i64, ptr }
; IR: call ptr @__obf_family_auth_v3(ptr @__obf_string_desc__secret, i32 0, i32 0, i64 7, i64
; IR-LABEL: define internal ptr @__obf_family_auth_v3(ptr %desc, i32 %cfg_state, i32 %expected_state, i64 %trusted_length, i64 %trusted_binding, ptr %trusted_topology) {
; IR: %obf.str.cfg.match = icmp eq i32 %cfg_state, %expected_state
; IR: br i1 %obf.str.cfg.match, label %decode, label %state_mismatch
; IR-NOT: load ptr, ptr
; IR-NOT: phi ptr
; IR: state_mismatch:
; IR: call void @llvm.trap()
; IR: unreachable
; IR: decode:
; IR: call ptr @rt_core_sd3(ptr %desc, i64 %trusted_length, i64 %trusted_binding, ptr %trusted_topology)
; IR: ret ptr
