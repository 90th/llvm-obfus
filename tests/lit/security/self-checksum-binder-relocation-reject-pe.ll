; REQUIRES: system-windows-x86-64, has-self-checksum-binder
; RUN: %raw_clang -c %S/../Inputs/self-checksum-pe-reloc-overlap.s -o %t.obj
; RUN: %raw_clang -nostdlib -Wl,/entry:entry,/subsystem:console,/dynamicbase %t.obj -o %t.exe
; RUN: %obf_checksum_bind --probe %t.exe | %FileCheck %s --check-prefix=PROBE
; RUN: %expect_failure %obf_checksum_bind %t.exe 2>&1 | %FileCheck %s --check-prefix=REJECT
;
; PROBE: SELF_CHECKSUM_PROBE: records=1
; REJECT: obf-checksum-bind: sample range intersects a PE load-time base relocation/fixup

define void @dummy() {
entry:
  ret void
}
