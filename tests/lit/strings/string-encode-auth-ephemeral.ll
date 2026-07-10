; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-ephemeral.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-ephemeral.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: %opt -passes=verify -disable-output %t
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

; CHECK-DAG: @__obf_string_ct__secret = internal constant [8 x i8]
; CHECK-DAG: @__obf_string_build_key__secret = internal constant [32 x i8]
; CHECK-NOT: @.secret =
; CHECK-NOT: @__obf_string_dest__secret
; CHECK-NOT: c"delta-7\00"

; CHECK-LABEL: define i32 @main()
; CHECK-DAG: %obf.auth.scratch = alloca [8 x i8]
; CHECK-DAG: %obf.auth.dref = alloca { i64, ptr }
; CHECK-DAG: %obf.auth.cref = alloca { i64, ptr }
; CHECK-DAG: %obf.auth.bref = alloca { i64, ptr }
; CHECK-DAG: %obf.auth.sref = alloca { i64, i64, i64 }
; CHECK-DAG: %obf.auth.desc = alloca
; CHECK-DAG: %obf.auth.topo = alloca

; CHECK: %[[PTR1:.*]] = call ptr @rt_core_sd3(ptr %obf.auth.desc, i64 8, i64 {{.*}}, ptr %obf.auth.topo)
; CHECK: %[[PTR2:.*]] = call ptr @rt_core_sd3(ptr %obf.auth.desc{{.*}}, i64 8, i64 {{.*}}, ptr %obf.auth.topo{{.*}})
; CHECK: %cmp = call i32 @bcmp(ptr %[[PTR1]], ptr %[[PTR2]], i64 7)

; Verify volatile cleanup happens after compare
; CHECK: store volatile i8 0, ptr
; CHECK: store volatile i8 0, ptr
