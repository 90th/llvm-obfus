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
