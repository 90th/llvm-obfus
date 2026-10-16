; REQUIRES: has-rust-nightly, has-rust-llvm-match, has-cargo, system-linux
; RUN: rm -rf %t.baseline %t.protected %t.library %t.example %t.baseline-o0 %t.vm-o0 %t.strong-vm-o0 %t.vm-o2 %t.strong-vm-o2
; RUN: cp -R %S/../Inputs/obf-rustc-cargo %t.baseline
; RUN: cp -R %S/../Inputs/obf-rustc-cargo %t.protected
; RUN: env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER -u OBF_CONFIG CARGO_TARGET_DIR=%t.baseline/target RUSTC=%raw_rustc %raw_cargo rustc --manifest-path=%t.baseline/Cargo.toml --release --bin same-name -- -Copt-level=2 --emit=llvm-ir,link
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
; RUN: cp -R %S/../Inputs/obf-rustc-cargo %t.baseline-o0
; RUN: env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER -u OBF_CONFIG CARGO_TARGET_DIR=%t.baseline-o0/target RUSTC=%raw_rustc %raw_cargo rustc --manifest-path=%t.baseline-o0/Cargo.toml --bin same-name -- -Copt-level=0 -Cpanic=abort --emit=llvm-ir,link
; RUN: %t.baseline-o0/target/debug/same-name > %t.baseline-o0.stdout
; RUN: %FileCheck %s --check-prefix=RESULT < %t.baseline-o0.stdout
; RUN: cp -R %S/../Inputs/obf-rustc-cargo %t.vm-o0
; RUN: env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS -u RUSTC_WRAPPER RUSTC=%raw_rustc RUSTC_WORKSPACE_WRAPPER=%obf_rustc OBF_CONFIG=%S/../Inputs/obf-rustc-cargo-vm.yaml OBF_COVERAGE_REPORT=%t.vm-o0.json OBF_RUST_MANIFEST_DIR=%t.vm-o0 OBF_RUST_CRATE_NAME=same_name OBF_RUST_CRATE_TYPE=bin OBF_RUST_CRATE_ROOT=%t.vm-o0/src/main.rs CARGO_TARGET_DIR=%t.vm-o0/target %raw_cargo rustc --manifest-path=%t.vm-o0/Cargo.toml --bin same-name -- -Copt-level=0 -Cpanic=abort --emit=llvm-ir,link
; RUN: %python %S/../Inputs/obf-rustc-cargo-check.py --directory %t.vm-o0/target/debug/deps --symbol cargo_vm_target --runtime present --forbid cargo-selected-visible-secret
; RUN: %t.vm-o0/target/debug/same-name > %t.vm-o0.stdout
; RUN: cmp %t.baseline-o0.stdout %t.vm-o0.stdout
; RUN: %FileCheck %s --check-prefix=RESULT < %t.vm-o0.stdout
; RUN: %python %S/../Inputs/frontend-vm-contract.py %t.vm-o0.json --level vm --target cargo_vm_target --override cargo_vm_override
; RUN: %llvm_nm --defined-only %t.vm-o0/target/debug/same-name | %FileCheck %s --check-prefix=VM-EXPORT --implicit-check-not=__obf
; RUN: cp -R %S/../Inputs/obf-rustc-cargo %t.strong-vm-o0
; RUN: env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS -u RUSTC_WRAPPER RUSTC=%raw_rustc RUSTC_WORKSPACE_WRAPPER=%obf_rustc OBF_CONFIG=%S/../Inputs/obf-rustc-cargo-strong-vm.yaml OBF_COVERAGE_REPORT=%t.strong-vm-o0.json OBF_RUST_MANIFEST_DIR=%t.strong-vm-o0 OBF_RUST_CRATE_NAME=same_name OBF_RUST_CRATE_TYPE=bin OBF_RUST_CRATE_ROOT=%t.strong-vm-o0/src/main.rs CARGO_TARGET_DIR=%t.strong-vm-o0/target %raw_cargo rustc --manifest-path=%t.strong-vm-o0/Cargo.toml --bin same-name -- -Copt-level=0 -Cpanic=abort --emit=llvm-ir,link
; RUN: %python %S/../Inputs/obf-rustc-cargo-check.py --directory %t.strong-vm-o0/target/debug/deps --symbol cargo_vm_target --runtime present --forbid cargo-selected-visible-secret
; RUN: %t.strong-vm-o0/target/debug/same-name > %t.strong-vm-o0.stdout
; RUN: cmp %t.baseline-o0.stdout %t.strong-vm-o0.stdout
; RUN: %FileCheck %s --check-prefix=RESULT < %t.strong-vm-o0.stdout
; RUN: %python %S/../Inputs/frontend-vm-contract.py %t.strong-vm-o0.json --level strong_vm --target cargo_vm_target --override cargo_vm_override
; RUN: %llvm_nm --defined-only %t.strong-vm-o0/target/debug/same-name | %FileCheck %s --check-prefix=VM-EXPORT --implicit-check-not=__obf
; RUN: cp -R %S/../Inputs/obf-rustc-cargo %t.vm-o2
; RUN: env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS -u RUSTC_WRAPPER RUSTC=%raw_rustc RUSTC_WORKSPACE_WRAPPER=%obf_rustc OBF_CONFIG=%S/../Inputs/obf-rustc-cargo-vm.yaml OBF_COVERAGE_REPORT=%t.vm-o2.json OBF_RUST_MANIFEST_DIR=%t.vm-o2 OBF_RUST_CRATE_NAME=same_name OBF_RUST_CRATE_TYPE=bin OBF_RUST_CRATE_ROOT=%t.vm-o2/src/main.rs CARGO_TARGET_DIR=%t.vm-o2/target %raw_cargo rustc --manifest-path=%t.vm-o2/Cargo.toml --release --bin same-name -- -Copt-level=2 --emit=llvm-ir,link
; RUN: %python %S/../Inputs/obf-rustc-cargo-check.py --directory %t.vm-o2/target/release/deps --symbol cargo_vm_target --runtime present --forbid cargo-selected-visible-secret
; RUN: %t.vm-o2/target/release/same-name > %t.vm-o2.stdout
; RUN: cmp %t.baseline.stdout %t.vm-o2.stdout
; RUN: %FileCheck %s --check-prefix=RESULT < %t.vm-o2.stdout
; RUN: %python %S/../Inputs/frontend-vm-contract.py %t.vm-o2.json --level vm --target cargo_vm_target --override cargo_vm_override
; RUN: %llvm_nm --defined-only %t.vm-o2/target/release/same-name | %FileCheck %s --check-prefix=VM-EXPORT --implicit-check-not=__obf
; RUN: cp -R %S/../Inputs/obf-rustc-cargo %t.strong-vm-o2
; RUN: env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS -u RUSTC_WRAPPER RUSTC=%raw_rustc RUSTC_WORKSPACE_WRAPPER=%obf_rustc OBF_CONFIG=%S/../Inputs/obf-rustc-cargo-strong-vm.yaml OBF_COVERAGE_REPORT=%t.strong-vm-o2.json OBF_RUST_MANIFEST_DIR=%t.strong-vm-o2 OBF_RUST_CRATE_NAME=same_name OBF_RUST_CRATE_TYPE=bin OBF_RUST_CRATE_ROOT=%t.strong-vm-o2/src/main.rs CARGO_TARGET_DIR=%t.strong-vm-o2/target %raw_cargo rustc --manifest-path=%t.strong-vm-o2/Cargo.toml --release --bin same-name -- -Copt-level=2 --emit=llvm-ir,link
; RUN: %python %S/../Inputs/obf-rustc-cargo-check.py --directory %t.strong-vm-o2/target/release/deps --symbol cargo_vm_target --runtime present --forbid cargo-selected-visible-secret
; RUN: %t.strong-vm-o2/target/release/same-name > %t.strong-vm-o2.stdout
; RUN: cmp %t.baseline.stdout %t.strong-vm-o2.stdout
; RUN: %FileCheck %s --check-prefix=RESULT < %t.strong-vm-o2.stdout
; RUN: %python %S/../Inputs/frontend-vm-contract.py %t.strong-vm-o2.json --level strong_vm --target cargo_vm_target --override cargo_vm_override
; RUN: %llvm_nm --defined-only %t.strong-vm-o2/target/release/same-name | %FileCheck %s --check-prefix=VM-EXPORT --implicit-check-not=__obf
;
; RESULT: cargo=141
; RESULT-NEXT: cargo-vm=000000000000002c:5fffffffffffffff
; EXPORT: cargo_selected_target
; VM-EXPORT-DAG: cargo_selected_target
; VM-EXPORT-DAG: cargo_vm_target
; VM-EXPORT-DAG: cargo_vm_override

define void @dummy() {
entry:
  ret void
}
