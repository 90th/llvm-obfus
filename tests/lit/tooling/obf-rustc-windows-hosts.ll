; REQUIRES: system-windows, has-rust-windows-unbound
; RUN: %obf_rustc --version | %FileCheck %s --check-prefix=VERSION
; RUN: %expect_failure %obf_rustc --obf-config=%S/../Inputs/obf-rustc-direct.yaml --crate-name=rust_direct --crate-type=bin %S/../Inputs/obf-rustc-direct.rs -o %t.exe 2>&1 | %FileCheck %s --check-prefix=UNBOUND
;
; VERSION: rustc
; UNBOUND: active Windows Rust protection requires a bound Rust LLVM host

define void @dummy() {
entry:
  ret void
}
