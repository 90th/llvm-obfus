; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-ephemeral.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-ephemeral.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: %opt -passes=verify -disable-output %t
; RUN: %lli %t

@.secret = private unnamed_addr constant [8 x i8] c"delta-7\00"
@.escape = private unnamed_addr constant [8 x i8] c"escape!\00"

declare i32 @bcmp(ptr, ptr, i64)

define i32 @first_char(ptr %p) {
entry:
  %first = load i8, ptr %p
  %is_e = icmp eq i8 %first, 101 ; 'e'
  %code = select i1 %is_e, i32 0, i32 1
  ret i32 %code
}

define i32 @main() {
entry:
  %cmp = call i32 @bcmp(ptr @.secret, ptr @.secret, i64 7)
  %ok1 = icmp eq i32 %cmp, 0

  %esc_res = call i32 @first_char(ptr @.escape)
  %ok2 = icmp eq i32 %esc_res, 0

  %both_ok = and i1 %ok1, %ok2
  %ret = select i1 %both_ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK-DAG: @__obf_string_ct__secret = internal constant [8 x i8]
; CHECK-DAG: @__obf_string_build_key__secret = internal constant [32 x i8]
; CHECK-DAG: @__obf_string_ct__escape = internal constant [8 x i8]
; CHECK-DAG: @__obf_string_build_key__escape = internal constant [32 x i8]
; CHECK-DAG: @.escape = private unnamed_addr global [8 x i8] zeroinitializer
; CHECK-DAG: @__obf_string_desc__escape =
; CHECK-NOT: @__obf_string_dest__secret

; CHECK-LABEL: define i32 @main()
; CHECK-DAG: %obf.auth.dref = alloca { i64, ptr }
; CHECK: call ptr @rt_core_sd3(
; CHECK: call ptr @__obf_family_auth_v3(ptr @__obf_string_desc__escape
