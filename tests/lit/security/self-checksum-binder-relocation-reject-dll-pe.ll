; REQUIRES: system-windows-x86-64, has-self-checksum-binder
; RUN: %raw_clang -c %S/../Inputs/self-checksum-pe-dll-reloc.s -o %t.obj
; RUN: %raw_clang -shared -nostdlib -Wl,/noentry,/subsystem:console,/dynamicbase,/include:record,/include:relocation_anchor %t.obj -o %t.dll
; RUN: %obf_checksum_bind --probe %t.dll | %FileCheck %s --check-prefix=PROBE
; RUN: cp %t.dll %t.unbound.dll
;
; Keep record bytes intact and retarget a genuine DIR64 fixup onto the whole
; 96-byte record, including a fixup that starts before it or crosses its end.
; RUN: cp %t.dll %t.record-start.dll
; RUN: %python %S/../Inputs/self_checksum_pe_tool.py retarget-relocation %t.record-start.dll record 0
; RUN: cp %t.record-start.dll %t.record-start-before.dll
; RUN: %expect_failure %obf_checksum_bind %t.record-start.dll 2>&1 | %FileCheck %s --check-prefix=REJECT
; RUN: cmp %t.record-start.dll %t.record-start-before.dll
; RUN: cp %t.dll %t.record-before.dll
; RUN: %python %S/../Inputs/self_checksum_pe_tool.py retarget-relocation %t.record-before.dll record -7
; RUN: cp %t.record-before.dll %t.record-before-copy.dll
; RUN: %expect_failure %obf_checksum_bind %t.record-before.dll 2>&1 | %FileCheck %s --check-prefix=REJECT
; RUN: cmp %t.record-before.dll %t.record-before-copy.dll
; RUN: cp %t.dll %t.record-target.dll
; RUN: %python %S/../Inputs/self_checksum_pe_tool.py retarget-relocation %t.record-target.dll record 32
; RUN: cp %t.record-target.dll %t.record-target-before.dll
; RUN: %expect_failure %obf_checksum_bind %t.record-target.dll 2>&1 | %FileCheck %s --check-prefix=REJECT
; RUN: cmp %t.record-target.dll %t.record-target-before.dll
; RUN: cp %t.dll %t.record-checksum.dll
; RUN: %python %S/../Inputs/self_checksum_pe_tool.py retarget-relocation %t.record-checksum.dll record 64
; RUN: cp %t.record-checksum.dll %t.record-checksum-before.dll
; RUN: %expect_failure %obf_checksum_bind %t.record-checksum.dll 2>&1 | %FileCheck %s --check-prefix=REJECT
; RUN: cmp %t.record-checksum.dll %t.record-checksum-before.dll
; RUN: cp %t.dll %t.record-tail.dll
; RUN: %python %S/../Inputs/self_checksum_pe_tool.py retarget-relocation %t.record-tail.dll record 88
; RUN: cp %t.record-tail.dll %t.record-tail-before.dll
; RUN: %expect_failure %obf_checksum_bind %t.record-tail.dll 2>&1 | %FileCheck %s --check-prefix=REJECT
; RUN: cmp %t.record-tail.dll %t.record-tail-before.dll
; RUN: cp %t.dll %t.record-end.dll
; RUN: %python %S/../Inputs/self_checksum_pe_tool.py retarget-relocation %t.record-end.dll record 95
; RUN: cp %t.record-end.dll %t.record-end-before.dll
; RUN: %expect_failure %obf_checksum_bind %t.record-end.dll 2>&1 | %FileCheck %s --check-prefix=REJECT
; RUN: cmp %t.record-end.dll %t.record-end-before.dll
;
; Sample checks also include partial overlaps at both ends.
; RUN: cp %t.dll %t.sample-start.dll
; RUN: %python %S/../Inputs/self_checksum_pe_tool.py retarget-relocation %t.sample-start.dll sample 0
; RUN: cp %t.sample-start.dll %t.sample-start-before.dll
; RUN: %expect_failure %obf_checksum_bind %t.sample-start.dll 2>&1 | %FileCheck %s --check-prefix=REJECT
; RUN: cmp %t.sample-start.dll %t.sample-start-before.dll
; RUN: cp %t.dll %t.sample-before.dll
; RUN: %python %S/../Inputs/self_checksum_pe_tool.py retarget-relocation %t.sample-before.dll sample -7
; RUN: cp %t.sample-before.dll %t.sample-before-copy.dll
; RUN: %expect_failure %obf_checksum_bind %t.sample-before.dll 2>&1 | %FileCheck %s --check-prefix=REJECT
; RUN: cmp %t.sample-before.dll %t.sample-before-copy.dll
; RUN: cp %t.dll %t.sample-end.dll
; RUN: %python %S/../Inputs/self_checksum_pe_tool.py retarget-relocation %t.sample-end.dll sample 15
; RUN: cp %t.sample-end.dll %t.sample-end-before.dll
; RUN: %expect_failure %obf_checksum_bind %t.sample-end.dll 2>&1 | %FileCheck %s --check-prefix=REJECT
; RUN: cmp %t.sample-end.dll %t.sample-end-before.dll
;
; The valid console DLL still binds with its unrelated .data fixup intact.
; A fixup starting exactly after the sample is not an overlap.
; RUN: %obf_checksum_bind %t.dll | %FileCheck %s --check-prefix=BIND
; RUN: cp %t.dll %t.bound-copy.dll
; RUN: %obf_checksum_bind %t.dll | %FileCheck %s --check-prefix=REBOUND
; RUN: cmp %t.dll %t.bound-copy.dll
; RUN: cp %t.unbound.dll %t.sample-after.dll
; RUN: %python %S/../Inputs/self_checksum_pe_tool.py retarget-relocation %t.sample-after.dll sample 16
; RUN: %obf_checksum_bind %t.sample-after.dll | %FileCheck %s --check-prefix=BIND
;
; PROBE: SELF_CHECKSUM_PROBE: records=1
; REJECT: obf-checksum-bind: sample range intersects a PE load-time base relocation/fixup
; BIND: SELF_CHECKSUM_BIND: bound records=1
; REBOUND: SELF_CHECKSUM_BIND: already bound records=1

define void @dummy() {
entry:
  ret void
}
