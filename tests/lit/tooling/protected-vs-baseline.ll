; RUN: timeout 120 %raw_clang -O1 -fno-inline -fno-inline-functions -emit-llvm -S %S/../Inputs/protected-vs-baseline.c -o %t.baseline.ll
; RUN: %FileCheck %s --check-prefix=BASELINE < %t.baseline.ll
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/protected-vs-baseline.yaml -passes=obf-safe-pipeline -S %t.baseline.ll -o %t.protected.ll
; RUN: %FileCheck %s --check-prefix=PROTECTED --implicit-check-not='baseline-visible-secret' < %t.protected.ll
; RUN: %opt -passes=verify -disable-output %t.protected.ll
; RUN: timeout 120 %raw_clang %t.baseline.ll -o %t.baseline.exe
; RUN: timeout 120 %raw_clang %t.protected.ll %obf_runtime -o %t.protected.exe
; RUN: %t.baseline.exe > %t.baseline.stdout
; RUN: %FileCheck %s --check-prefix=RESULT < %t.baseline.stdout
; RUN: %t.protected.exe > %t.protected.stdout
; RUN: cmp %t.baseline.stdout %t.protected.stdout
;
; Emit a baseline IR snapshot from the C fixture, protect that exact IR through the
; real safe pipeline, then prove the protected executable preserves the baseline
; stdout byte-for-byte while the protected IR hides the fixed secret.
;
; BASELINE: @kProtectedSecret = {{.*}} c"baseline-visible-secret\00"
; BASELINE-LABEL: define{{.*}} @main(
; BASELINE: call{{.*}} @protected_value(i32
; BASELINE-LABEL: define{{.*}} @protected_value(i32
;
; PROTECTED: @rt_core_ea = external externally_initialized global i64
; PROTECTED: call{{.*}} @rt_core_sd3(
; RESULT: digest=29842 len=23

define void @dummy() {
entry:
  ret void
}
