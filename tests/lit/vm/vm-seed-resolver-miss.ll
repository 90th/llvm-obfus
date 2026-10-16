; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-seed-resolver-miss.yaml -passes=obf-vm -S %s -o %t.valid.ll
; RUN: %FileCheck %s < %t.valid.ll
; RUN: %lli %t.valid.ll
; RUN: %python %S/../Inputs/vm_seed_resolver_miss.py prepare %t.valid.ll %t.invalid.ll
; RUN: %python %S/../Inputs/vm_seed_resolver_miss.py check %t.invalid.ll -- %lli
; RUN: %opt -passes='default<O2>' -S %t.invalid.ll -o %t.optimized.ll
; RUN: %python %S/../Inputs/vm_seed_resolver_miss.py check %t.optimized.ll -- %lli
;
; An unknown shared-resolver key is a defined trapping failure, not undefined
; behavior that lets LTO assume the key is the only switch case and poison its
; caller operand. Exercise the genuine producer, a legitimate target call, and
; an invalid key before and after interprocedural optimization.
;
; CHECK-LABEL: define private i64 @__obf_vm_seed_resolve(
; CHECK: switch i64
; CHECK: miss:
; CHECK-NEXT: call void @llvm.trap()
; CHECK-NEXT: unreachable

target triple = "x86_64-unknown-linux-gnu"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"

define dso_local i32 @resolver_target(i32 %input) noinline {
entry:
  %scaled = mul i32 %input, 3
  %result = add i32 %scaled, 5
  ret i32 %result
}

define i32 @main() {
entry:
  %result = call i32 @resolver_target(i32 7)
  %bad = icmp ne i32 %result, 26
  %exit = zext i1 %bad to i32
  ret i32 %exit
}
