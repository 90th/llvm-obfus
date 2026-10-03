; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-dll-export.yaml -passes=obf-vm,verify -S %s -o %t.ll
; RUN: %llc -filetype=obj %t.ll -o %t.obj
; RUN: %llvm_objdump -s -j .drectve %t.obj | %FileCheck %s
;
; COFF export directives belong only to the two public interfaces.
; CHECK: Contents of section .drectve:
; CHECK-NOT: __obf
; CHECK: {{export|EXPORT}}
; CHECK-NOT: __obf
;
; Native result/effect and export-table coverage lives in the DLL tooling tests.

target triple = "x86_64-pc-windows-msvc"

define dllexport i32 @dll_vm(i32 %value, ptr %effect) {
entry:
  %scaled = mul i32 %value, 7
  %result = xor i32 %scaled, 90
  store i32 %result, ptr %effect
  ret i32 %result
}

define dllexport i32 @dll_strong_vm(i32 %value, ptr %effect) {
entry:
  %shifted = add i32 %value, 17
  %result = xor i32 %shifted, 165
  store i32 %result, ptr %effect
  ret i32 %result
}
