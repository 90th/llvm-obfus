; REQUIRES: system-linux, has-lld-llvm-match
; RUN: %raw_clang -O0 -flto=full -c %S/../Inputs/tooling-lto-linker-plugin.c -o %t.full.o
; RUN: OBF_CONFIG=%S/../Inputs/tooling-lto-linker-plugin.yaml %raw_clang -O0 -flto=full -fuse-ld=lld -Wl,--load-pass-plugin=%obf_plugin -Wl,--save-temps %t.full.o %obf_runtime -o %t.full.exe
; RUN: llvm-dis %t.full.exe.0.0.preopt.bc -o - | %FileCheck %s --check-prefix=PREOPT
; RUN: llvm-dis %t.full.exe.0.4.opt.bc -o - | %FileCheck %s --check-prefix=LTO-IR
; RUN: %t.full.exe | %FileCheck %s --check-prefix=RESULT
; RUN: %raw_clang -O0 -flto=thin -c %S/../Inputs/tooling-lto-linker-plugin.c -o %t.thin.o
; RUN: %obf_driver --quiet --config=%S/../Inputs/tooling-lto-linker-plugin.yaml --validate-lto-input=%t.thin.o
; RUN: OBF_LTO_INPUTS_VALIDATED=1 OBF_CONFIG=%S/../Inputs/tooling-lto-linker-plugin.yaml %raw_clang -O2 -flto=thin -fuse-ld=lld -Wl,--load-pass-plugin=%obf_plugin -Wl,--save-temps %t.thin.o %obf_runtime -o %t.thin.exe
; RUN: llvm-dis %t.thin.o.0.preopt.bc -o - | %FileCheck %s --check-prefix=PREOPT
; RUN: llvm-dis %t.thin.o.4.opt.bc -o - | %FileCheck %s --check-prefix=LTO-IR
; RUN: %t.thin.exe | %FileCheck %s --check-prefix=RESULT
;
; PREOPT: @.str = private unnamed_addr constant [20 x i8] c"lto-linkonly-secret\00"
; PREOPT: define internal i32 @checksum(ptr
; PREOPT: define internal i32 @fold(i32
;
; LTO-IR-NOT: c"lto-linkonly-secret\00"
; LTO-IR: define dso_local{{.*}} @main(
;
; RESULT: link-lto consistent=1 value=4723

define void @dummy() {
entry:
  ret void
}
