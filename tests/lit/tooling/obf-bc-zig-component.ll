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
; RUN: env OBF_COVERAGE_REPORT=%t.vm-release.json %obf_bc --obf-config=%S/../Inputs/obf-bc-zig-vm.yaml %t.component.bc -o %t.vm-release.bc
; RUN: %python %S/../Inputs/frontend-vm-contract.py %t.vm-release.json --level vm --target zig_vm_target --override zig_vm_override --baseline-ir %t.component.baseline.ll
; RUN: timeout 120 %raw_zig build-exe %S/../Inputs/obf-bc-zig-main.zig %t.vm-release.bc %obf_runtime --cache-dir %t.cache --global-cache-dir %t.global-cache -femit-bin=%t.vm-release.exe
; RUN: %t.vm-release.exe > %t.vm-release.stdout
; RUN: cmp %t.baseline.stdout %t.vm-release.stdout
; RUN: %FileCheck %s --check-prefix=RESULT < %t.vm-release.stdout
; RUN: %llvm_nm --defined-only %t.vm-release.exe | %FileCheck %s --check-prefix=VM-SYMBOLS --implicit-check-not=__obf_
; RUN: env OBF_COVERAGE_REPORT=%t.strong-vm-release.json %obf_bc --obf-config=%S/../Inputs/obf-bc-zig-strong-vm.yaml %t.component.bc -o %t.strong-vm-release.bc
; RUN: %python %S/../Inputs/frontend-vm-contract.py %t.strong-vm-release.json --level strong_vm --target zig_vm_target --override zig_vm_override --baseline-ir %t.component.baseline.ll
; RUN: timeout 120 %raw_zig build-exe %S/../Inputs/obf-bc-zig-main.zig %t.strong-vm-release.bc %obf_runtime --cache-dir %t.cache --global-cache-dir %t.global-cache -femit-bin=%t.strong-vm-release.exe
; RUN: %t.strong-vm-release.exe > %t.strong-vm-release.stdout
; RUN: cmp %t.baseline.stdout %t.strong-vm-release.stdout
; RUN: %FileCheck %s --check-prefix=RESULT < %t.strong-vm-release.stdout
; RUN: %llvm_nm --defined-only %t.strong-vm-release.exe | %FileCheck %s --check-prefix=VM-SYMBOLS --implicit-check-not=__obf_
; RUN: timeout 120 %raw_zig build-obj %S/../Inputs/obf-bc-zig-protected.zig -fllvm -O Debug --cache-dir %t.cache --global-cache-dir %t.global-cache -femit-llvm-bc=%t.component-debug.bc -fno-emit-bin
; RUN: %opt -S %t.component-debug.bc -o %t.component-debug.baseline.ll
; RUN: timeout 120 %raw_zig build-exe %S/../Inputs/obf-bc-zig-main.zig %t.component-debug.bc --cache-dir %t.cache --global-cache-dir %t.global-cache -femit-bin=%t.baseline-debug.exe
; RUN: %t.baseline-debug.exe > %t.baseline-debug.stdout
; RUN: %FileCheck %s --check-prefix=RESULT < %t.baseline-debug.stdout
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/obf-bc-zig-vm.yaml -passes='obf-prepare-o0,verify' %t.component-debug.bc -o %t.component-debug.prepared.bc
; RUN: env OBF_COVERAGE_REPORT=%t.vm-debug.json %obf_bc --obf-config=%S/../Inputs/obf-bc-zig-vm.yaml %t.component-debug.prepared.bc -o %t.vm-debug.bc
; RUN: %python %S/../Inputs/frontend-vm-contract.py %t.vm-debug.json --level vm --target zig_vm_target --override zig_vm_override --baseline-ir %t.component-debug.baseline.ll
; RUN: %llc -O0 -filetype=obj -relocation-model=pic %t.vm-debug.bc -o %t.vm-debug.o
; RUN: timeout 120 %raw_zig build-exe %S/../Inputs/obf-bc-zig-main.zig %t.vm-debug.o %obf_runtime --cache-dir %t.cache --global-cache-dir %t.global-cache -femit-bin=%t.vm-debug.exe
; RUN: %t.vm-debug.exe > %t.vm-debug.stdout
; RUN: cmp %t.baseline-debug.stdout %t.vm-debug.stdout
; RUN: %FileCheck %s --check-prefix=RESULT < %t.vm-debug.stdout
; RUN: %llvm_nm --defined-only %t.vm-debug.exe | %FileCheck %s --check-prefix=VM-SYMBOLS --implicit-check-not=__obf_
; RUN: env OBF_COVERAGE_REPORT=%t.strong-vm-debug.json %obf_bc --obf-config=%S/../Inputs/obf-bc-zig-strong-vm.yaml %t.component-debug.prepared.bc -o %t.strong-vm-debug.bc
; RUN: %python %S/../Inputs/frontend-vm-contract.py %t.strong-vm-debug.json --level strong_vm --target zig_vm_target --override zig_vm_override --baseline-ir %t.component-debug.baseline.ll
; RUN: %llc -O0 -filetype=obj -relocation-model=pic %t.strong-vm-debug.bc -o %t.strong-vm-debug.o
; RUN: timeout 120 %raw_zig build-exe %S/../Inputs/obf-bc-zig-main.zig %t.strong-vm-debug.o %obf_runtime --cache-dir %t.cache --global-cache-dir %t.global-cache -femit-bin=%t.strong-vm-debug.exe
; RUN: %t.strong-vm-debug.exe > %t.strong-vm-debug.stdout
; RUN: cmp %t.baseline-debug.stdout %t.strong-vm-debug.stdout
; RUN: %FileCheck %s --check-prefix=RESULT < %t.strong-vm-debug.stdout
; RUN: %llvm_nm --defined-only %t.strong-vm-debug.exe | %FileCheck %s --check-prefix=VM-SYMBOLS --implicit-check-not=__obf_
;
; This covers the same-host Zig 0.16 component seam and its C ABI export aliases.
; ReleaseFast links the exact protected bitcode with the project runtime.
; Debug uses selected-local preparation and matching LLVM object generation.
; An older embedded LLVM cannot read every intrinsic written by a newer SDK.
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
; VM-SYMBOLS-DAG: zig_protected_component
; VM-SYMBOLS-DAG: zig_vm_target
; VM-SYMBOLS-DAG: zig_vm_override

define void @dummy() {
entry:
  ret void
}
