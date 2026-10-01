; REQUIRES: system-windows-x86-64
; RUN: %raw_clangxx -std=c++20 -O2 -ffp-contract=off -c %S/../Inputs/windows-plugin-float-main.cpp -o %t.main.obj
; RUN: %obf_clang --obf-config=%S/../Inputs/windows-plugin-vm.yaml -O2 -ffp-contract=off -c %S/../Inputs/windows-plugin-float-target.c -o %t.vm.obj
; RUN: %obf_clangxx --obf-config=%S/../Inputs/windows-plugin-vm.yaml -O2 %t.main.obj %t.vm.obj -o %t.vm.exe
; RUN: %t.vm.exe | %FileCheck %s --check-prefix=RESULT
; RUN: %obf_clang --obf-config=%S/../Inputs/windows-plugin-strong-vm.yaml -O2 -ffp-contract=off -c %S/../Inputs/windows-plugin-float-target.c -o %t.strong.obj
; RUN: %obf_clangxx --obf-config=%S/../Inputs/windows-plugin-strong-vm.yaml -O2 %t.main.obj %t.strong.obj -o %t.strong.exe
; RUN: %t.strong.exe | %FileCheck %s --check-prefix=RESULT
; RUN: %expect_failure %obf_clang --obf-config=%S/../Inputs/windows-plugin-vm.yaml --target=x86_64-unknown-linux-gnu -nostdlib -flto=thin -fuse-ld=lld -Wl,-e,protected_float %S/../Inputs/windows-plugin-float-target.c -o %t.elf
;
; RESULT: windows-fp errors=0

define void @dummy() {
entry:
  ret void
}
