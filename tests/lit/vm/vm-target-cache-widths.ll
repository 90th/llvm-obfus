; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-target-cache-widths.yaml -passes='obf-vm,verify' -S %s -o - | %FileCheck %s --implicit-check-not='load atomic i24' --implicit-check-not='store atomic i24' --implicit-check-not='@__obf_vm_t_{{[A-Za-z0-9_]+}} = private global i24'

target datalayout = "e-p:64:64-p1:24:32-i64:32"

define i32 @cache_width_64(i32 %x) {
  %r = add i32 %x, 1
  ret i32 %r
}

define i32 @cache_width_24(i32 %x) addrspace(1) {
  %r = add i32 %x, 2
  ret i32 %r
}

define i32 @cache_width_caller(i32 %x) {
  %r = call addrspace(1) i32 @cache_width_24(i32 %x)
  ret i32 %r
}

; CHECK: @[[CACHE:__obf_vm_t_[A-Za-z0-9_]+]] = private global i64 {{-?[0-9]+}}, align 8
; CHECK-LABEL: define i32 @cache_width_64(
; CHECK: load atomic i64, ptr @[[CACHE]] monotonic, align 8
; CHECK: store atomic i64 {{.*}}, ptr @[[CACHE]] monotonic, align 8
; CHECK-LABEL: define i32 @cache_width_24(
; CHECK: inttoptr i24 {{.*}} to ptr addrspace(1)
; CHECK: call addrspace(1) i32 %
; CHECK-LABEL: define i32 @cache_width_caller(
; CHECK: inttoptr i24 {{.*}} to ptr addrspace(1)
; CHECK: call addrspace(1) i32 %
