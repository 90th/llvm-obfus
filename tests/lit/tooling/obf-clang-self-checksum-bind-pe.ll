; REQUIRES: system-windows-x86-64, has-self-checksum-binder
;
; Direct PE final link is automatically bound without ELF build-id handling.
; RUN: %obf_clang -O0 --obf-config=%S/../Inputs/self-checksum-bound.yaml %S/../Inputs/obf-clang-self-checksum.c -o %t.direct.exe
; RUN: %python %S/../Inputs/self_checksum_pe_tool.py inspect %t.direct.exe | %FileCheck %s --check-prefix=BOUND
; RUN: %t.direct.exe
;
; Split object link has no config. The final PE probe must discover and bind inherited records.
; RUN: %obf_clang -O0 -c --obf-config=%S/../Inputs/self-checksum-bound.yaml %S/../Inputs/obf-clang-self-checksum.c -o %t.split.obj
; RUN: %obf_clang %t.split.obj -o %t.split.exe
; RUN: %python %S/../Inputs/self_checksum_pe_tool.py inspect %t.split.exe | %FileCheck %s --check-prefix=BOUND
; RUN: %t.split.exe
;
; Static archives also carry UNBOUND PE records until final layout is known.
; RUN: %llvm_ar rcs %t.selfchk.lib %t.split.obj
; RUN: %obf_clang %t.selfchk.lib -o %t.archive.exe
; RUN: %python %S/../Inputs/self_checksum_pe_tool.py inspect %t.archive.exe | %FileCheck %s --check-prefix=BOUND
; RUN: %t.archive.exe
;
; Normal no-record PE links still succeed now that the Windows binder is installed.
; RUN: %obf_clang -O0 --obf-config=%S/../Inputs/obf-clang-wrapper.yaml %S/../Inputs/obf-clang-self-checksum.c -o %t.normal.exe
; RUN: %t.normal.exe
; RUN: %expect_failure %obf_checksum_bind --probe %t.normal.exe 2>&1 | %FileCheck %s --check-prefix=NO-RECORDS
;
; Ordinary DLL links without records remain unaffected, while protected DLLs fail closed as unsupported.
; RUN: %obf_clang -shared -O0 --obf-config=%S/../Inputs/obf-clang-wrapper.yaml %S/../Inputs/obf-clang-self-checksum-dll.c -o %t.normal.dll
; RUN: %expect_failure %obf_checksum_bind --probe %t.normal.dll 2>&1 | %FileCheck %s --check-prefix=NO-RECORDS
; RUN: %expect_failure %obf_clang -shared -O0 --obf-config=%S/../Inputs/self-checksum-bound.yaml %S/../Inputs/obf-clang-self-checksum-dll.c -o %t.protected.dll 2>&1 | %FileCheck %s --check-prefix=DLL-REJECT
;
; BOUND: SELF_CHECKSUM_PE_RECORD
; BOUND-SAME: flags=0x3
; BOUND-SAME: expected=0x{{[0-9a-f]+}}
; NO-RECORDS: SELF_CHECKSUM_PROBE: records=0
; DLL-REJECT: obf-clang: self-checksum binding failed
; DLL-REJECT-SAME: Phase 3 supports PE32+ AMD64 executables only; DLL binding is not enabled

define void @dummy() {
entry:
  ret void
}
