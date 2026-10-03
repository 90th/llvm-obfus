; REQUIRES: system-windows-x86-64, has-self-checksum-binder
;
; Probe the final linker output, not a driver filename overridden by a linker response.
; RUN: %raw_clang -std=c11 -O2 %S/../Inputs/obf-clang-dll-consumer.c -o %t.dynamic.exe
; RUN: %obf_clang -std=c11 -O0 -fno-inline -I%obf_build_include --obf-config=%S/../Inputs/obf-clang-dll-policy.yaml -c %S/../Inputs/obf-clang-dll-library.c -o %t.library.obj
; RUN: printf '"/DLL"\n"/BASE:0x180000000"\n"/DYNAMICBASE"\n"/FIXED:NO"\n"/OPT:REF"\n"/OPT:ICF"\n"/OUT:%t.linker.dll"\n' > %t.linker.rsp
; RUN: %obf_clang -fuse-ld=lld %t.library.obj -o %t.driver-default.exe -Wl,@%t.linker.rsp
; RUN: %python %S/../Inputs/self_checksum_pe_tool.py inspect %t.linker.dll | %FileCheck %s --check-prefix=BOUND
; RUN: %t.dynamic.exe %t.linker.dll | %FileCheck %s --check-prefix=DYNAMIC
;
; MSVC responses preserve unquoted backslashes, nested responses, and UTF-16 BOM input.
; RUN: %python %S/../Inputs/obf-clang-dll-response.py %t.native.dll %t.native.rsp
; RUN: %obf_clang -fuse-ld=lld %t.library.obj -o %t.native-default.exe -Wl,@%t.native.rsp
; RUN: %python %S/../Inputs/self_checksum_pe_tool.py inspect %t.native.dll | %FileCheck %s --check-prefix=BOUND
; RUN: %t.dynamic.exe %t.native.dll | %FileCheck %s --check-prefix=DYNAMIC
;
; Driver response output remains explicit when the active policy requests binding.
; RUN: printf '"-shared"\n"-fuse-ld=lld"\n"-O0"\n"-fno-inline"\n"-I%obf_build_include"\n"%S/../Inputs/obf-clang-dll-library.c"\n"-Wl,/base:0x180000000,/dynamicbase,/fixed:no"\n"-o"\n"%t.response.dll"\n' > %t.driver.rsp
; RUN: %obf_clang --obf-config=%S/../Inputs/obf-clang-dll-policy.yaml @%t.driver.rsp
; RUN: %python %S/../Inputs/self_checksum_pe_tool.py inspect %t.response.dll | %FileCheck %s --check-prefix=BOUND
; RUN: %t.dynamic.exe %t.response.dll | %FileCheck %s --check-prefix=DYNAMIC
;
; A Clang config tail can select the final output after command-line options.
; RUN: printf '"$-Wl,/OUT:%t.config.dll"\n' > %t.output.cfg
; RUN: %obf_clang --config=%t.output.cfg --obf-config=%S/../Inputs/obf-clang-dll-policy.yaml -shared -fuse-ld=lld -O0 -fno-inline -I%obf_build_include %S/../Inputs/obf-clang-dll-library.c -Wl,/base:0x180000000,/dynamicbase,/fixed:no -o %t.config-default.dll
; RUN: %python %S/../Inputs/self_checksum_pe_tool.py inspect %t.config.dll | %FileCheck %s --check-prefix=BOUND
; RUN: %t.dynamic.exe %t.config.dll | %FileCheck %s --check-prefix=DYNAMIC
;
; An active policy still requires explicit driver output. Linker /OUT alone is not enough.
; RUN: %expect_failure %obf_clang -shared -fuse-ld=lld --obf-config=%S/../Inputs/obf-clang-dll-policy.yaml %t.library.obj -Wl,/OUT:%t.not-explicit.dll 2>&1 | %FileCheck %s --check-prefix=EXPLICIT
; RUN: %expect_failure %obf_clang -shared -fuse-ld=lld %t.library.obj -o - -Wl,/OUT:%t.stdout-override.dll 2>&1 | %FileCheck %s --check-prefix=STDOUT
;
; COFF bitcode hidden behind either wholearchive spelling must fail before backend execution.
; RUN: %raw_clang -O0 -flto=thin -c %S/../Inputs/obf-clang-self-checksum-dll.c -o %t.bitcode.obj
; RUN: %llvm_ar rcs %t.bitcode.lib %t.bitcode.obj
; RUN: %expect_failure %obf_clang -shared -fuse-ld=lld %t.library.obj -Xlinker /WHOLEARCHIVE:%t.bitcode.lib -o %t.bitcode-slash.dll 2>&1 | %FileCheck %s --check-prefix=LTO-REJECT
; RUN: %expect_failure %obf_clang -shared -fuse-ld=lld %t.library.obj -Xlinker -WHOLEARCHIVE:%t.bitcode.lib -o %t.bitcode-dash.dll 2>&1 | %FileCheck %s --check-prefix=LTO-REJECT
;
; BOUND: SELF_CHECKSUM_PE_RECORD
; BOUND-SAME: flags=0x3
; DYNAMIC: DLL_DYNAMIC_OK vm=1 strong_vm=1 effects=1 init=1 concurrent=1 exports=8 rebased=1 joined_unloads=4
; EXPLICIT: obf-clang: self_checksum auto-binding requires an explicit '-o <path>' final-link output
; LTO-REJECT: obf-clang: managed obfuscation LTO currently supports ELF targets only
; STDOUT: obf-clang: self_checksum final links cannot bind an output written to stdout

define void @dummy() {
entry:
  ret void
}
