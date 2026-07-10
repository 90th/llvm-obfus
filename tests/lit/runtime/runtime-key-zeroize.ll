; RUN: %raw_clang -std=c17 -O2 -fPIC -I%obf_build_include -I%S/../../../include -S -emit-llvm %S/../../../runtime/string_auth_runtime.c -o %t.ll
; RUN: %FileCheck %s --input-file=%t.ll

; The wipe helper must survive optimization as a volatile-store loop.
; CHECK-LABEL: define internal void @ObfSecureZeroize(
; CHECK: store volatile i8 0

; Both public authenticated entrypoints must retain cleanup calls after -O2.
; CHECK-LABEL: define hidden ptr @rt_core_sd3(
; CHECK: call void @ObfSecureZeroize
; CHECK: i64 noundef 32
; CHECK: call void @ObfSecureZeroize
; CHECK: i64 noundef 16
; CHECK-LABEL: define hidden ptr @rt_core_cpd3(
; CHECK: call void @ObfSecureZeroize
; CHECK: i64 noundef 32
; CHECK: call void @ObfSecureZeroize
; CHECK: i64 noundef 16

; Temporary BLAKE2 message words are wiped as full 64-byte arrays.
; CHECK-DAG: call void @ObfSecureZeroize(ptr{{.*}}, i64 noundef 64)

; -----------------------------------------------------------------------------
; Caller-side ephemeral scratch wipe under -O2
; -----------------------------------------------------------------------------
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-lazy.yaml -passes='obf-string-encode,default<O2>' -S %s -o %t.opt.ll
; RUN: %FileCheck --check-prefix=CHECK-CALLER %s --input-file=%t.opt.ll

@.secret = private unnamed_addr constant [8 x i8] c"delta-7\00"

declare i32 @bcmp(ptr, ptr, i64)

define i32 @main() {
entry:
  %cmp = call i32 @bcmp(ptr @.secret, ptr @.secret, i64 7)
  %ok = icmp eq i32 %cmp, 0
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK-CALLER-LABEL: define {{.*}} @main(
; CHECK-CALLER: call ptr @rt_core_sd3(
; CHECK-CALLER: store volatile i8 0, ptr
