; REQUIRES: system-windows-x86-64, has-self-checksum-binder
;
; The import-library consumer and dynamic consumer call both protected interfaces.
; Initialization uses different descriptors from the concurrent cold call paths.
; RUN: %raw_clang -std=c11 -O2 %S/../Inputs/obf-clang-dll-consumer.c -o %t.dynamic.exe
; RUN: %obf_clang -shared -fuse-ld=lld -std=c11 -O0 -fno-inline -I%obf_build_include --obf-config=%S/../Inputs/obf-clang-dll-policy.yaml %S/../Inputs/obf-clang-dll-library.c -Wl,/base:0x180000000,/dynamicbase,/fixed:no -o %t.o0.dll
; RUN: %python %S/../Inputs/self_checksum_pe_tool.py inspect %t.o0.dll | %FileCheck %s --check-prefix=BOUND
; RUN: %raw_clang -std=c11 -O2 -DDLL_IMPORT_CONSUMER %S/../Inputs/obf-clang-dll-consumer.c %t.o0.lib -o %t.import.exe
; RUN: %t.import.exe | %FileCheck %s --check-prefix=IMPORT
; RUN: %t.dynamic.exe %t.o0.dll | %FileCheck %s --check-prefix=DYNAMIC
;
; Optimization must preserve the same export, authentication, and lifecycle contract.
; RUN: %obf_clang -shared -fuse-ld=lld -std=c11 -O2 -fno-inline -I%obf_build_include --obf-config=%S/../Inputs/obf-clang-dll-policy.yaml %S/../Inputs/obf-clang-dll-library.c -Wl,/base:0x180000000,/dynamicbase,/fixed:no -o %t.o2.dll
; RUN: %python %S/../Inputs/self_checksum_pe_tool.py inspect %t.o2.dll | %FileCheck %s --check-prefix=BOUND
; RUN: %t.dynamic.exe %t.o2.dll | %FileCheck %s --check-prefix=DYNAMIC
;
; The final link inherits records from an object without repeating its policy.
; RUN: %obf_clang -std=c11 -O0 -fno-inline -I%obf_build_include --obf-config=%S/../Inputs/obf-clang-dll-policy.yaml -c %S/../Inputs/obf-clang-dll-library.c -o %t.library.obj
; RUN: %obf_clang -shared -fuse-ld=lld %t.library.obj -Wl,/base:0x180000000,/dynamicbase,/fixed:no -o %t.object.dll
; RUN: %python %S/../Inputs/self_checksum_pe_tool.py inspect %t.object.dll | %FileCheck %s --check-prefix=BOUND
; RUN: %t.dynamic.exe %t.object.dll | %FileCheck %s --check-prefix=DYNAMIC
;
; Archive extraction must retain the same inherited-record binding behavior.
; RUN: %llvm_ar rcs %t.library.lib %t.library.obj
; RUN: %raw_clang -c %S/../Inputs/obf-clang-dll-link-anchor.c -o %t.anchor.obj
; RUN: %obf_clang -shared -fuse-ld=lld %t.anchor.obj -Wl,/wholearchive:%t.library.lib,/base:0x180000000,/dynamicbase,/fixed:no -o %t.archive.dll
; RUN: %python %S/../Inputs/self_checksum_pe_tool.py inspect %t.archive.dll | %FileCheck %s --check-prefix=BOUND
; RUN: %t.dynamic.exe %t.archive.dll | %FileCheck %s --check-prefix=DYNAMIC
;
; BOUND: SELF_CHECKSUM_PE_RECORD
; BOUND-SAME: flags=0x3
; BOUND-SAME: expected=0x{{[0-9a-f]+}}
; IMPORT: DLL_IMPORT_OK vm=1 strong_vm=1 effects=1 init=1 concurrent=1
; DYNAMIC: DLL_DYNAMIC_OK vm=1 strong_vm=1 effects=1 init=1 concurrent=1 exports=7 rebased=1 joined_unloads=4

define void @dummy() {
entry:
  ret void
}
