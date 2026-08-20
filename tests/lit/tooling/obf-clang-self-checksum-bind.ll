; REQUIRES: system-linux-x86-64, has-self-checksum-binder
; RUN: %obf_driver --config=%S/../Inputs/self-checksum-bound.yaml --query-self-checksum | %FileCheck %s --check-prefix=QUERY-ON
; RUN: %obf_driver --config=%S/../Inputs/obf-clang-wrapper.yaml --query-self-checksum | %FileCheck %s --check-prefix=QUERY-OFF
;
; Direct config-aware final link: wrapper disables build-id, links, probes, and binds.
; RUN: %obf_clang -O0 --obf-config=%S/../Inputs/self-checksum-bound.yaml %S/../Inputs/obf-clang-self-checksum.c -o %t.cli.exe
; RUN: %python %S/../Inputs/self_checksum_elf_tool.py inspect %t.cli.exe | %FileCheck %s --check-prefix=BOUND
; RUN: %t.cli.exe
;
; Environment-provided config follows the same canonical config query.
; RUN: env OBF_CONFIG=%S/../Inputs/self-checksum-bound.yaml %obf_clang -O0 %S/../Inputs/obf-clang-self-checksum.c -o %t.env.exe
; RUN: %python %S/../Inputs/self_checksum_elf_tool.py inspect %t.env.exe | %FileCheck %s --check-prefix=BOUND
; RUN: %t.env.exe
;
; Split compile/link: the link invocation intentionally has no config. The wrapper must discover
; records carried by the object, relink without the default GNU build-id, then bind.
; RUN: %obf_clang -O0 -c --obf-config=%S/../Inputs/self-checksum-bound.yaml %S/../Inputs/obf-clang-self-checksum.c -o %t.split.o
; RUN: %obf_clang %t.split.o -o %t.split.exe
; RUN: %python %S/../Inputs/self_checksum_elf_tool.py inspect %t.split.exe | %FileCheck %s --check-prefix=BOUND
; RUN: %t.split.exe
; RUN: not %obf_clang %t.split.o -Wl,--build-id=sha1 -o %t.split-conflict.exe 2>&1 | %FileCheck %s --check-prefix=INHERITED-BUILD-ID-CONFLICT
;
; Static archives carry UNBOUND records until a final wrapper-owned link.
; RUN: %llvm_ar rcs %t.selfchk.a %t.split.o
; RUN: %obf_clang %t.selfchk.a -o %t.archive.exe
; RUN: %python %S/../Inputs/self_checksum_elf_tool.py inspect %t.archive.exe | %FileCheck %s --check-prefix=BOUND
; RUN: %t.archive.exe
;
; Requested self_checksum with no eligible protected sites is a successful no-record link.
; RUN: %obf_clang -O0 --obf-config=%S/../Inputs/self-checksum-no-sites.yaml %S/../Inputs/obf-clang-self-checksum.c -o %t.no-sites.exe
; RUN: %t.no-sites.exe
; RUN: not %obf_checksum_bind --probe %t.no-sites.exe 2>&1 | %FileCheck %s --check-prefix=NO-RECORDS
;
; A normal non-self_checksum link keeps normal linker build-id behavior and is not rebound.
; RUN: %obf_clang -O0 --obf-config=%S/../Inputs/obf-clang-wrapper.yaml %S/../Inputs/obf-clang-self-checksum.c -o %t.normal.exe
; RUN: %t.normal.exe
; RUN: %obf_clang -### -O0 --obf-config=%S/../Inputs/obf-clang-wrapper.yaml %S/../Inputs/obf-clang-self-checksum.c -o %t.normal-dry.exe 2>&1 | %FileCheck %s --check-prefix=NORMAL-DRY
;
; Compile-only actions never bind. Explicit conflicting build IDs and ambiguous output paths fail early.
; RUN: %obf_clang -O0 -c --obf-config=%S/../Inputs/self-checksum-bound.yaml %S/../Inputs/obf-clang-self-checksum.c -o %t.compile-only.o
; RUN: test -s %t.compile-only.o
; RUN: not %obf_clang -O0 --obf-config=%S/../Inputs/self-checksum-bound.yaml %S/../Inputs/obf-clang-self-checksum.c -Wl,--build-id=sha1 -o %t.conflict.exe 2>&1 | %FileCheck %s --check-prefix=BUILD-ID-CONFLICT
; RUN: not %obf_clang -O0 --obf-config=%S/../Inputs/self-checksum-bound.yaml %S/../Inputs/obf-clang-self-checksum.c 2>&1 | %FileCheck %s --check-prefix=MISSING-OUTPUT
; RUN: %obf_clang -### -O0 --obf-config=%S/../Inputs/self-checksum-bound.yaml %S/../Inputs/obf-clang-self-checksum.c -o %t.dry.exe 2>&1 | %FileCheck %s --check-prefix=DRY
; RUN: not %obf_clang -### --target=x86_64-pc-windows-msvc -O0 --obf-config=%S/../Inputs/self-checksum-bound.yaml %S/../Inputs/obf-clang-self-checksum.c -o %t.cross.exe 2>&1 | %FileCheck %s --check-prefix=CROSS-PE
;
; QUERY-ON: enabled
; QUERY-OFF: disabled
; BOUND: SELF_CHECKSUM_TEST_RECORD
; BOUND-SAME: flags=0x3
; BOUND-SAME: expected=0x{{[0-9a-f]+}}
; NO-RECORDS: SELF_CHECKSUM_PROBE: records=0
; BUILD-ID-CONFLICT: obf-clang: self_checksum ELF links require --build-id=none
; INHERITED-BUILD-ID-CONFLICT: obf-clang: linked ELF contains self_checksum records but a conflicting --build-id option was requested
; MISSING-OUTPUT: obf-clang: self_checksum auto-binding requires an explicit '-o <path>' final-link output
; DRY: "--build-id=none"
; NORMAL-DRY: -fpass-plugin=
; NORMAL-DRY-NOT: "--build-id=none"
; CROSS-PE: obf-clang: PE self_checksum auto-binding currently requires a native Windows host

define void @dummy() {
entry:
  ret void
}
