; REQUIRES: system-linux-x86-64, has-self-checksum-binder
; RUN: %raw_clang -c -fPIC %S/../Inputs/self-checksum-reloc-overlap.s -o %t.o
; RUN: %raw_clang -nostdlib -pie -Wl,-e,_start -Wl,--build-id=none -Wl,-z,notext %t.o -o %t.exe
; RUN: not %obf_checksum_bind %t.exe 2>&1 | %FileCheck %s
; RUN: %raw_clang -nostdlib -pie -Wl,-e,_start -Wl,--build-id=none -Wl,-z,notext -Wl,-z,pack-relative-relocs %t.o -o %t.relr.exe
; RUN: not %obf_checksum_bind %t.relr.exe 2>&1 | %FileCheck %s
; RUN: %raw_clang -c %S/../Inputs/self-checksum-static-reloc.s -o %t.static.o
; RUN: %raw_clang -nostdlib -no-pie -Wl,-e,_start -Wl,--build-id=none -Wl,--emit-relocs %S/../Inputs/self-checksum-start.s %t.static.o -o %t.static.exe
; RUN: %obf_checksum_bind %t.static.exe | %FileCheck %s --check-prefix=STATIC

; The target starts with an absolute pointer to itself.  PIE loading therefore
; requires an R_X86_64_RELATIVE fixup inside the 16-byte sampled range.  A
; file-byte baseline would not equal the loaded bytes, so v1 must reject it.

; CHECK: obf-checksum-bind: sample range intersects an ELF load-time relocation/fixup

; STATIC: SELF_CHECKSUM_RECORD site=88
; STATIC: SELF_CHECKSUM_BIND: bound records=1
