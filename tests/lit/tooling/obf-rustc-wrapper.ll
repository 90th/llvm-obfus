; RUN: %python %S/../Inputs/obf-rustc-fake-matrix.py --wrapper-script %obf_rustc_script --llvm-version %llvm_version --host-triple %llvm_host_triple --clang %raw_clang --fake-launcher-source %S/../Inputs/obf-rustc-fake-launcher.c --fake %S/../Inputs/obf-rustc-fake-rustc.py --config %S/../Inputs/obf-rustc-wrapper.yaml --generic-config %S/../Inputs/obf-rustc-generic.yaml --plugin %obf_plugin --runtime %obf_runtime --workdir %t.dir | %FileCheck %s
;
; CHECK: obf-rustc fake matrix passed

define void @dummy() {
entry:
  ret void
}
