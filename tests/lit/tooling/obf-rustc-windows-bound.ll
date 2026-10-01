; REQUIRES: system-windows, has-rust-windows-bound
; RUN: %obf_rustc --obf-config=%S/../Inputs/obf-rustc-direct.yaml --crate-name=rust_direct --crate-type=bin %S/../Inputs/obf-rustc-direct.rs -o %t.exe
; RUN: %t.exe | %FileCheck %s --check-prefix=RUN
;
; RUN: direct=98

define void @dummy() {
entry:
  ret void
}
