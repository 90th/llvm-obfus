; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/safe-pipeline-direct-opt-non-promoted.yaml -passes=obf-safe-pipeline -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/safe-pipeline-direct-opt-non-promoted.yaml -passes=obf-prepare-o0 -S %s -o - | %FileCheck %s --check-prefix=PREPARE
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/safe-pipeline-direct-opt-non-promoted.yaml -passes=obf-safe-pipeline -S %s -o %t
; RUN: %opt -passes=verify -disable-output %t
; RUN: %lli %t

; Direct `obf-safe-pipeline` coverage on non-promoted IR: the selected function
; starts with an alloca/store/load sequence, and the untouched function proves the
; config match only transforms the chosen target.

define i32 @selected_nonpromoted(i32 %x) {
entry:
  %slot = alloca i32, align 4
  store i32 %x, ptr %slot, align 4
  %loaded = load i32, ptr %slot, align 4
  %sum = add nsw i32 %loaded, 129
  ret i32 %sum
}

define i32 @untouched_nonpromoted(i32 %x) {
entry:
  %slot = alloca i32, align 4
  store i32 %x, ptr %slot, align 4
  %loaded = load i32, ptr %slot, align 4
  %sum = add nsw i32 %loaded, 7
  ret i32 %sum
}

define i32 @main() {
entry:
  %a = call i32 @selected_nonpromoted(i32 5)
  %b = call i32 @untouched_nonpromoted(i32 8)
  %sum = add i32 %a, %b
  %ok = icmp eq i32 %sum, 149
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK-DAG: @rt_core_ea = external externally_initialized global i64, align 8
; CHECK-LABEL: define i32 @selected_nonpromoted(i32
; CHECK: alloca i32, align 4
; CHECK: alloca { i64, i64 }, align 8
; CHECK: call {{.*}} @{{_[0-9a-f]+}}
; CHECK: store i32 %0, ptr %{{[^,]+}}, align 4
; CHECK: load i32, ptr %{{[^,]+}}, align 4
; CHECK: freeze i32
; CHECK-NOT: add nsw i32 %{{[^,]+}}, 129
; CHECK: ret i32 %{{[^ ]+}}
;
; CHECK-LABEL: define i32 @untouched_nonpromoted(i32
; CHECK: alloca i32, align 4
; CHECK: store i32 %0, ptr %{{[^,]+}}, align 4
; CHECK: load i32, ptr %{{[^,]+}}, align 4
; CHECK: add nsw i32 %{{[^,]+}}, 7
; CHECK: ret i32 %{{[^ ]+}}
;
; CHECK-LABEL: define i32 @main()
; CHECK: call i32 @selected_nonpromoted(i32 5)
; CHECK: call i32 @untouched_nonpromoted(i32 8)
; CHECK: icmp eq i32 %{{[^,]+}}, 149

;
; PREPARE-LABEL: define i32 @selected_nonpromoted(i32
; PREPARE-NOT: alloca i32
; PREPARE: ret i32
; PREPARE-LABEL: define i32 @untouched_nonpromoted(i32
; PREPARE: alloca i32, align 4