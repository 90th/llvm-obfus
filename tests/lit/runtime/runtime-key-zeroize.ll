; RUN: %raw_clang -std=c17 -O2 %fpic -I%obf_build_include -I%S/../../../include -S -emit-llvm %S/../../../runtime/string_auth_runtime.c -o %t.ll
; RUN: %FileCheck %s --check-prefix=CHECK-ZEROIZE --input-file=%t.ll
; RUN: %FileCheck %s --check-prefix=CHECK-ENTRIES --input-file=%t.ll

; The wipe helper must survive optimization as a volatile-store loop.
; CHECK-ZEROIZE-LABEL: define internal {{(fastcc )?}}void @ObfSecureZeroize(
; CHECK-ZEROIZE: store {{(atomic )?}}volatile i8 0

; Both public authenticated entrypoints must retain cleanup calls after -O2.
; CHECK-ENTRIES-LABEL: define hidden ptr @rt_core_sd3(
; CHECK-ENTRIES: call {{(fastcc )?}}void @ObfSecureZeroize
; CHECK-ENTRIES: i64 noundef 32
; CHECK-ENTRIES: call {{(fastcc )?}}void @ObfSecureZeroize
; CHECK-ENTRIES: i64 noundef 16
; CHECK-ENTRIES-LABEL: define hidden ptr @rt_core_cpd3(
; CHECK-ENTRIES: call {{(fastcc )?}}void @ObfSecureZeroize
; CHECK-ENTRIES: i64 noundef 32
; CHECK-ENTRIES: call {{(fastcc )?}}void @ObfSecureZeroize
; CHECK-ENTRIES: i64 noundef 16

; Temporary BLAKE2 message words are wiped as full 64-byte arrays.
; CHECK-ENTRIES-DAG: call {{(fastcc )?}}void @ObfSecureZeroize(ptr{{.*}}, i64 noundef 64)

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
