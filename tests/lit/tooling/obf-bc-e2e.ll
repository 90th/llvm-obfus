; RUN: %raw_clang -O1 -fno-inline -fno-inline-functions -fno-builtin-strcmp -emit-llvm -c %S/../Inputs/obf-bc-e2e.c -o %t.input.bc
; RUN: %raw_clang -S -emit-llvm %t.input.bc -o %t.baseline.ll
; RUN: %FileCheck %s --check-prefix=BASELINE < %t.baseline.ll
; RUN: %obf_bc --obf-config=%S/../Inputs/obf-bc-e2e.yaml --obf-seed 424242 %t.input.bc -o%t.protected.bc
; RUN: %raw_clang -S -emit-llvm %t.protected.bc -o %t.protected.ll
; RUN: %FileCheck %s --check-prefix=SELECTED --implicit-check-not='obf-bc\00' < %t.protected.ll
; RUN: %FileCheck %s --check-prefix=UNMATCHED < %t.protected.ll
; RUN: %FileCheck %s --check-prefix=RUNTIME < %t.protected.ll
; RUN: timeout 120 %raw_clang %t.input.bc -o %t.baseline.exe
; RUN: timeout 120 %raw_clang %t.protected.bc %obf_runtime -o %t.protected.exe
; RUN: %t.baseline.exe > %t.baseline.stdout
; RUN: %FileCheck %s --check-prefix=RESULT < %t.baseline.stdout
; RUN: %t.protected.exe > %t.protected.stdout
; RUN: cmp %t.baseline.stdout %t.protected.stdout
;
; The wrapper consumes project Clang-generated bitcode, not hand-authored IR. The
; selected function must receive a generated decoder call and authenticated runtime
; reference, while the unmatched function remains the original call-free add/return.
;
; BASELINE: c"obf-bc\00"
; BASELINE-LABEL: define{{.*}} @protected_value(
; BASELINE: call{{.*}} @strcmp(
; BASELINE-LABEL: define{{.*}} @unmatched_value(
; BASELINE: add nsw i32
; BASELINE: ret i32
;
; SELECTED-LABEL: define{{.*}} @protected_value(
; SELECTED: call ptr @rt_core_sd3(
; SELECTED: call i32 @strcmp(
;
; UNMATCHED-LABEL: define{{.*}} @unmatched_value(
; UNMATCHED-NOT: call
; UNMATCHED: add nsw i32
; UNMATCHED-NOT: call
; UNMATCHED: ret i32
;
; RUNTIME: @rt_core_ea = external externally_initialized global i64
;
; RESULT: sum=77

define void @dummy() {
entry:
  ret void
}
