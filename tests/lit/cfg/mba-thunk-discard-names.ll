; RUN: %opt -passes='default<O0>' %s -o %t.input.bc
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/mba-thunk-discard-names.yaml -passes=obf-constant-encode -discard-value-names -S %t.input.bc -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/mba-thunk-discard-names.yaml -passes=obf-constant-encode -discard-value-names -S %t.input.bc -o - | %opt -passes=verify -disable-output
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/mba-thunk-discard-names.yaml -passes=obf-constant-encode -S %s -o - | %opt -passes=verify -disable-output
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/mba-thunk-discard-names-vm.yaml -passes=obf-safe-pipeline -discard-value-names -S %t.input.bc -o - | %FileCheck %s --check-prefix=CHECK-VM
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/mba-thunk-discard-names-vm.yaml -passes=obf-safe-pipeline -discard-value-names -S %t.input.bc -o - | %opt -passes=verify -disable-output
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/mba-thunk-discard-names-vm.yaml -passes=obf-safe-pipeline -S %s -o - | %opt -passes=verify -disable-output

; Ensure that:
; 1. When compiling with -discard-value-names, the entropy cache alloca is reliably tagged
;    and identified via metadata so that only one cache alloca and one thunk call are emitted per function.
; 2. Under the exact deterministic strong_vm reproducer (target: fib, seed: 20260818) with -discard-value-names,
;    the VM safe-pipeline (which exercises Step 14 opaque GEP across VM interpreter handlers)
;    maintains complete thunk-interface typing consistency and passes full LLVM verification.

define i32 @test_entropy_cache_and_thunk_consistency(i32 %x) {
entry:
  %a = add i32 %x, 17
  %b = xor i32 %a, 85
  %c = sub i32 %b, 1234
  %d = add i32 %c, 9999
  %e = xor i32 %d, 4321
  %f = add i32 %e, 7777
  ret i32 %f
}

define i32 @fib(i32 %n) {
entry:
  %cmp = icmp sle i32 %n, 1
  br i1 %cmp, label %base, label %recurse

base:
  ret i32 1

recurse:
  %sub1 = sub i32 %n, 1
  %call1 = call i32 @fib(i32 %sub1)
  %sub2 = sub i32 %n, 2
  %call2 = call i32 @fib(i32 %sub2)
  %res = add i32 %call1, %call2
  ret i32 %res
}

define i32 @main() {
entry:
  %res = call i32 @test_entropy_cache_and_thunk_consistency(i32 10)
  %cmp = icmp eq i32 %res, 20683
  %ret = select i1 %cmp, i32 0, i32 1
  ret i32 %ret
}

; CHECK-LABEL: define i32 @test_entropy_cache_and_thunk_consistency(i32
; CHECK: alloca { i64, i64 }, align 8, !obf.entropy.cache !0
; CHECK-NOT: alloca { i64, i64 }, align 8
; CHECK-COUNT-1: call {{(void|\{ i64, i64 \})}} @__obf_entropy_thunk_
; CHECK: ret i32

; CHECK-VM-LABEL: define i32 @fib(i32
; CHECK-VM: call
; CHECK-VM: ret i32
