; REQUIRES: has-rust-nightly, has-rust-llvm-match, has-cargo, system-linux
; RUN: rm -rf %t.baseline %t.protected %t.library %t.example
; RUN: cp -R %S/../Inputs/obf-rustc-cargo %t.baseline
; RUN: cp -R %S/../Inputs/obf-rustc-cargo %t.protected
; RUN: env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER -u OBF_CONFIG CARGO_TARGET_DIR=%t.baseline/target RUSTC=%raw_rustc %raw_cargo rustc --manifest-path=%t.baseline/Cargo.toml --release --bin same-name -- --emit=llvm-ir,link
; RUN: env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS -u RUSTC_WRAPPER RUSTC=%raw_rustc RUSTC_WORKSPACE_WRAPPER=%obf_rustc OBF_CONFIG=%S/../Inputs/obf-rustc-cargo.yaml OBF_RUST_MANIFEST_DIR=%t.protected OBF_RUST_CRATE_NAME=same_name OBF_RUST_CRATE_TYPE=bin OBF_RUST_CRATE_ROOT=%t.protected/src/main.rs CARGO_TARGET_DIR=%t.protected/target %raw_cargo rustc --manifest-path=%t.protected/Cargo.toml --release --bin same-name -- --emit=llvm-ir,link
; RUN: %python %S/../Inputs/obf-rustc-cargo-check.py --directory %t.baseline/target/release/deps --symbol cargo_selected_target --runtime absent --require cargo-selected-visible-secret
; RUN: %python %S/../Inputs/obf-rustc-cargo-check.py --directory %t.protected/target/release/deps --symbol cargo_selected_target --runtime present --forbid cargo-selected-visible-secret
; RUN: %t.baseline/target/release/same-name > %t.baseline.stdout
; RUN: %t.protected/target/release/same-name > %t.protected.stdout
; RUN: cmp %t.baseline.stdout %t.protected.stdout
; RUN: %FileCheck %s --check-prefix=RESULT < %t.protected.stdout
; RUN: %llvm_nm --defined-only %t.protected/target/release/same-name | %FileCheck %s --check-prefix=EXPORT --implicit-check-not=__obf
; RUN: cp -R %S/../Inputs/obf-rustc-cargo %t.library
; RUN: env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS -u RUSTC_WRAPPER RUSTC=%raw_rustc RUSTC_WORKSPACE_WRAPPER=%obf_rustc OBF_CONFIG=%S/../Inputs/obf-rustc-cargo.yaml OBF_RUST_MANIFEST_DIR=%t.library OBF_RUST_CRATE_NAME=same_name OBF_RUST_CRATE_TYPE=bin OBF_RUST_CRATE_ROOT=%t.library/src/main.rs CARGO_TARGET_DIR=%t.library/target %raw_cargo rustc --manifest-path=%t.library/Cargo.toml --release --lib -- --emit=llvm-ir
; RUN: %python %S/../Inputs/obf-rustc-cargo-check.py --directory %t.library/target/release/deps --symbol same_name_library_export --runtime absent
; RUN: cp -R %S/../Inputs/obf-rustc-cargo %t.example
; RUN: env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS -u RUSTC_WRAPPER RUSTC=%raw_rustc RUSTC_WORKSPACE_WRAPPER=%obf_rustc OBF_CONFIG=%S/../Inputs/obf-rustc-cargo.yaml OBF_RUST_MANIFEST_DIR=%t.example OBF_RUST_CRATE_NAME=same_name OBF_RUST_CRATE_TYPE=bin OBF_RUST_CRATE_ROOT=%t.example/src/main.rs CARGO_TARGET_DIR=%t.example/target %raw_cargo rustc --manifest-path=%t.example/Cargo.toml --release --example same_name -- --emit=llvm-ir
; RUN: %python %S/../Inputs/obf-rustc-cargo-check.py --directory %t.example/target/release --symbol cargo_example_unselected --runtime absent
;
; RESULT: cargo=141
; EXPORT: cargo_selected_target

define void @dummy() {
entry:
  ret void
}
