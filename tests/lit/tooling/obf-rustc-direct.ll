; REQUIRES: has-rust-nightly, has-rust-llvm-match, system-linux
; RUN: %raw_rustc --crate-name=rust_direct --crate-type=bin -Copt-level=0 %S/../Inputs/obf-rustc-direct.rs -o %t.baseline
; RUN: %raw_rustc --crate-name=rust_direct --crate-type=bin --emit=llvm-ir -Copt-level=0 %S/../Inputs/obf-rustc-direct.rs -o %t.baseline.ll
; RUN: %FileCheck %s --check-prefix=BASELINE < %t.baseline.ll
; RUN: %obf_rustc --obf-config=%S/../Inputs/obf-rustc-direct.yaml --crate-name=rust_direct --crate-type=bin --emit=llvm-ir -Copt-level=0 %S/../Inputs/obf-rustc-direct.rs -o %t.protected.ll
; RUN: %FileCheck %s --check-prefix=PROTECTED --implicit-check-not=rust-direct-visible-secret < %t.protected.ll
; RUN: %obf_rustc --obf-config=%S/../Inputs/obf-rustc-direct.yaml --crate-name=rust_direct --crate-type=bin --emit=llvm-ir=%t.explicit.protected.ll -Copt-level=0 %S/../Inputs/obf-rustc-direct.rs
; RUN: %FileCheck %s --check-prefix=PROTECTED --implicit-check-not=rust-direct-visible-secret < %t.explicit.protected.ll
; RUN: %obf_rustc --obf-config=%S/../Inputs/obf-rustc-direct.yaml --crate-name=rust_direct --crate-type=bin --emit=link -Copt-level=0 %S/../Inputs/obf-rustc-direct.rs -o %t.protected
; RUN: %t.baseline > %t.baseline.stdout
; RUN: %t.protected > %t.protected.stdout
; RUN: cmp %t.baseline.stdout %t.protected.stdout
; RUN: %FileCheck %s --check-prefix=RESULT < %t.protected.stdout
; RUN: %llvm_nm --defined-only %t.protected | %FileCheck %s --check-prefix=EXPORT --implicit-check-not=__obf
; RUN: env OBF_COVERAGE_REPORT=%t.vm-o0.json %obf_rustc --obf-config=%S/../Inputs/obf-rustc-direct-vm.yaml --crate-name=rust_direct --crate-type=bin --emit=link -Copt-level=0 -Cpanic=abort %S/../Inputs/obf-rustc-direct.rs -o %t.vm-o0
; RUN: %t.vm-o0 > %t.vm-o0.stdout
; RUN: cmp %t.baseline.stdout %t.vm-o0.stdout
; RUN: %FileCheck %s --check-prefix=RESULT < %t.vm-o0.stdout
; RUN: %python %S/../Inputs/frontend-vm-contract.py %t.vm-o0.json --level vm --target rust_direct_vm_target --override rust_direct_vm_override
; RUN: %llvm_nm --defined-only %t.vm-o0 | %FileCheck %s --check-prefix=VM-EXPORT --implicit-check-not=__obf
; RUN: env OBF_COVERAGE_REPORT=%t.strong-vm-o0.json %obf_rustc --obf-config=%S/../Inputs/obf-rustc-direct-strong-vm.yaml --crate-name=rust_direct --crate-type=bin --emit=link -Copt-level=0 -Cpanic=abort %S/../Inputs/obf-rustc-direct.rs -o %t.strong-vm-o0
; RUN: %t.strong-vm-o0 > %t.strong-vm-o0.stdout
; RUN: cmp %t.baseline.stdout %t.strong-vm-o0.stdout
; RUN: %FileCheck %s --check-prefix=RESULT < %t.strong-vm-o0.stdout
; RUN: %python %S/../Inputs/frontend-vm-contract.py %t.strong-vm-o0.json --level strong_vm --target rust_direct_vm_target --override rust_direct_vm_override
; RUN: %llvm_nm --defined-only %t.strong-vm-o0 | %FileCheck %s --check-prefix=VM-EXPORT --implicit-check-not=__obf
; RUN: %raw_rustc --crate-name=rust_direct --crate-type=bin -Copt-level=2 %S/../Inputs/obf-rustc-direct.rs -o %t.baseline-o2
; RUN: %t.baseline-o2 > %t.baseline-o2.stdout
; RUN: %FileCheck %s --check-prefix=RESULT < %t.baseline-o2.stdout
; RUN: env OBF_COVERAGE_REPORT=%t.vm-o2.json %obf_rustc --obf-config=%S/../Inputs/obf-rustc-direct-vm.yaml --crate-name=rust_direct --crate-type=bin --emit=link -Copt-level=2 %S/../Inputs/obf-rustc-direct.rs -o %t.vm-o2
; RUN: %t.vm-o2 > %t.vm-o2.stdout
; RUN: cmp %t.baseline-o2.stdout %t.vm-o2.stdout
; RUN: %FileCheck %s --check-prefix=RESULT < %t.vm-o2.stdout
; RUN: %python %S/../Inputs/frontend-vm-contract.py %t.vm-o2.json --level vm --target rust_direct_vm_target --override rust_direct_vm_override
; RUN: %llvm_nm --defined-only %t.vm-o2 | %FileCheck %s --check-prefix=VM-EXPORT --implicit-check-not=__obf
; RUN: env OBF_COVERAGE_REPORT=%t.strong-vm-o2.json %obf_rustc --obf-config=%S/../Inputs/obf-rustc-direct-strong-vm.yaml --crate-name=rust_direct --crate-type=bin --emit=link -Copt-level=2 %S/../Inputs/obf-rustc-direct.rs -o %t.strong-vm-o2
; RUN: %t.strong-vm-o2 > %t.strong-vm-o2.stdout
; RUN: cmp %t.baseline-o2.stdout %t.strong-vm-o2.stdout
; RUN: %FileCheck %s --check-prefix=RESULT < %t.strong-vm-o2.stdout
; RUN: %python %S/../Inputs/frontend-vm-contract.py %t.strong-vm-o2.json --level strong_vm --target rust_direct_vm_target --override rust_direct_vm_override
; RUN: %llvm_nm --defined-only %t.strong-vm-o2 | %FileCheck %s --check-prefix=VM-EXPORT --implicit-check-not=__obf
;
; BASELINE: rust-direct-visible-secret
; PROTECTED: @rt_
; PROTECTED-LABEL: define{{.*}} @rust_direct_target(
; RESULT: direct=22904
; RESULT-NEXT: direct-vm=0000000000000ec0:7800000000000000
; EXPORT: rust_direct_target
; VM-EXPORT-DAG: rust_direct_target
; VM-EXPORT-DAG: rust_direct_vm_target
; VM-EXPORT-DAG: rust_direct_vm_override

define void @dummy() {
entry:
  ret void
}
