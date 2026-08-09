; REQUIRES: has-zig-016, system-linux
;
; RUN: timeout 120 %raw_zig build-obj %S/../Inputs/obf-bc-zig-protected.zig -fllvm -O ReleaseFast --cache-dir %t.cache --global-cache-dir %t.global-cache -femit-llvm-bc=%t.component.bc -fno-emit-bin
; RUN: %opt -S %t.component.bc -o %t.component.baseline.ll
; RUN: %FileCheck %s --check-prefix=BASELINE --implicit-check-not=@rt_core_ea < %t.component.baseline.ll
; RUN: %obf_bc --obf-config=%S/../Inputs/obf-bc-zig.yaml %t.component.bc -o %t.component.protected.bc
; RUN: %opt -S %t.component.protected.bc -o %t.component.protected.ll
; RUN: %FileCheck %s --check-prefix=PROTECTED < %t.component.protected.ll
; RUN: timeout 120 %raw_zig build-exe %S/../Inputs/obf-bc-zig-main.zig %t.component.bc --cache-dir %t.cache --global-cache-dir %t.global-cache -femit-bin=%t.baseline.exe
; RUN: timeout 120 %raw_zig build-exe %S/../Inputs/obf-bc-zig-main.zig %t.component.protected.bc %obf_runtime --cache-dir %t.cache --global-cache-dir %t.global-cache -femit-bin=%t.protected.exe
; RUN: %t.baseline.exe > %t.baseline.stdout
; RUN: %FileCheck %s --check-prefix=RESULT < %t.baseline.stdout
; RUN: %t.protected.exe > %t.protected.stdout
; RUN: cmp %t.baseline.stdout %t.protected.stdout
; RUN: %llvm_nm --defined-only %t.protected.exe | %FileCheck %s --check-prefix=SYMBOLS --implicit-check-not=__obf_
;
; This covers the supported same-host Zig 0.16 component seam only. Zig exports
; a stable C ABI alias for an internal implementation. The unmodified exact BC
; links the baseline; the exact obf-bc output links with the project runtime.
;
; BASELINE-DAG: @zig_protected_component = alias i32 (i64), ptr @[[BASE_FN:[-A-Za-z0-9._]+]]
; BASELINE: define internal i32 @[[BASE_FN]](i64
; BASELINE: mul i32
; BASELINE: ret i32
;
; PROTECTED-DAG: @rt_core_ea = external externally_initialized global i64, align 8
; PROTECTED-DAG: @zig_protected_component = alias i32 (i64), ptr @[[PROTECTED_FN:_[0-9a-f]+]]
; PROTECTED: define internal i32 @[[PROTECTED_FN]](i64
; PROTECTED: alloca { i64, i64 }, align 8
; PROTECTED: freeze i64
; PROTECTED: ret i32
;
; RESULT: digest=7209
;
; SYMBOLS-COUNT-1: zig_protected_component

define void @dummy() {
entry:
  ret void
}
