; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-target-cache-16bit.yaml -passes='obf-vm,verify' -S %s -o - | %FileCheck %s

target datalayout = "e-m:e-p:16:16:16-i32:32:32-a:0:32-n32-S64"

define i32 @narrow_cache(i32 %x) {
entry:
  %twice = shl i32 %x, 1
  %mix = xor i32 %twice, 21
  ret i32 %mix
}

define i32 @caller() {
entry:
  %result = call i32 @narrow_cache(i32 5)
  ret i32 %result
}

; CHECK-DAG: @[[TARGET:__obf_vm_t_[A-Za-z0-9_]+]] = private global i16 {{-?[0-9]+}}, align 2
; CHECK-LABEL: define i32 @narrow_cache(i32 %x)
; CHECK: %narrow_cache.obf.wrapper.check = load atomic i16, ptr @[[TARGET]] monotonic, align 2
; CHECK: store atomic i16 %narrow_cache.obf.wrapper.resolved{{(\.poison[0-9]*)?}}, ptr @[[TARGET]] monotonic, align 2
; CHECK-LABEL: define i32 @caller()
; CHECK: %narrow_cache.obf.check = load atomic i16, ptr @[[TARGET]] monotonic, align 2
; CHECK: store atomic i16 %narrow_cache.obf.resolved{{(\.poison[0-9]*)?}}, ptr @[[TARGET]] monotonic, align 2
; CHECK: %narrow_cache.obf.indirect = inttoptr i16 {{.*}} to ptr
