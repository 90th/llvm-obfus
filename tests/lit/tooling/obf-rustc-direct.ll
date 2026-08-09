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
;
; BASELINE: rust-direct-visible-secret
; PROTECTED: @rt_
; PROTECTED-LABEL: define{{.*}} @rust_direct_target(
; RESULT: direct=22904
; EXPORT: rust_direct_target

define void @dummy() {
entry:
  ret void
}
