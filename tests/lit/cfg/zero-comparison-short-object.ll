; REQUIRES: system-linux
; RUN: %raw_clang -O1 -S -emit-llvm %S/../Inputs/zero-comparison-short-object.c -o %t.input.ll
; RUN: %raw_clang %t.input.ll -o %t.before
; RUN: %t.before
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/zero-comparison.yaml -passes='obf-zero-comparison,verify' -S %t.input.ll -o %t.ll
; RUN: %FileCheck %s < %t.ll
; RUN: %raw_clang -O0 %t.ll -o %t.after
; RUN: %t.after
; RUN: %opt -passes='default<O2>,verify' -S %t.ll -o %t.opt.ll
; RUN: %raw_clang -O2 %t.opt.ll -o %t.optimized
; RUN: %t.optimized

; CHECK-LABEL: define {{.*}} @compare_string(
; CHECK-NOT: call i32 @strcmp
; CHECK: ret i32
; CHECK-LABEL: define {{.*}} @compare_bounded(
; CHECK-NOT: call i32 @strncmp
; CHECK: ret i32
