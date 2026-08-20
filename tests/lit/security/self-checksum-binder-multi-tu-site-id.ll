; REQUIRES: system-linux-x86-64, has-self-checksum-binder
; RUN: %raw_clang -c %S/../Inputs/self-checksum-start.s -o %t.start.o
; RUN: %raw_clang -c %S/../Inputs/self-checksum-duplicate-site.s -o %t.a.o
; RUN: %raw_clang -c %S/../Inputs/self-checksum-duplicate-site.s -o %t.b.o
; RUN: %raw_clang -nostdlib -no-pie -Wl,-e,_start -Wl,--build-id=none %t.start.o %t.a.o %t.b.o -o %t.exe
; RUN: %obf_checksum_bind %t.exe | %FileCheck %s
; RUN: %obf_checksum_bind %t.exe | %FileCheck %s --check-prefix=AGAIN
;
; A site_id is a deterministic diagnostic label, not a final-link unique key.
; Separate translation units can legitimately derive the same label (for
; example, identical local protected/target names and seeds). Both records
; must remain independently bindable after their input sections are combined.
;
; CHECK-COUNT-2: SELF_CHECKSUM_RECORD site=123
; CHECK: SELF_CHECKSUM_BIND: bound records=2
; AGAIN: SELF_CHECKSUM_BIND: already bound records=2
