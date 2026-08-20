; REQUIRES: system-windows-x86-64, has-self-checksum-binder
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/self-checksum-bound.yaml -passes=obf-self-checksum -S %s -o %t.bound.ll
; RUN: %FileCheck %s --check-prefix=IR < %t.bound.ll
; RUN: %raw_clang -O2 %t.bound.ll %obf_runtime -o %t.exe
; RUN: %python %S/../Inputs/self_checksum_pe_tool.py inspect %t.exe | %FileCheck %s --check-prefix=UNBOUND
; RUN: %obf_checksum_bind --probe %t.exe | %FileCheck %s --check-prefix=PROBE
; RUN: %obf_checksum_bind %t.exe | %FileCheck %s --check-prefix=BIND
; RUN: %python %S/../Inputs/self_checksum_pe_tool.py inspect %t.exe | %FileCheck %s --check-prefix=BOUND
; RUN: %obf_checksum_bind %t.exe | %FileCheck %s --check-prefix=REBOUND
; RUN: cp %t.exe %t.overlap.exe
; RUN: %python %S/../Inputs/self_checksum_pe_tool.py overlap-record %t.overlap.exe
; RUN: %expect_failure %obf_checksum_bind %t.overlap.exe 2>&1 | %FileCheck %s --check-prefix=OVERLAP-REJECT
; RUN: cp %t.exe %t.checksum.exe
; RUN: %python %S/../Inputs/self_checksum_pe_tool.py mark-checksum %t.checksum.exe
; RUN: %expect_failure %obf_checksum_bind %t.checksum.exe 2>&1 | %FileCheck %s --check-prefix=CHECKSUM-REJECT
; RUN: cp %t.exe %t.signed.exe
; RUN: %python %S/../Inputs/self_checksum_pe_tool.py mark-signed %t.signed.exe
; RUN: %expect_failure %obf_checksum_bind %t.signed.exe 2>&1 | %FileCheck %s --check-prefix=SIGNED-REJECT
; RUN: %t.exe
; RUN: %python %S/../Inputs/self_checksum_pe_tool.py tamper %t.exe | %FileCheck %s --check-prefix=TAMPER
; RUN: %expect_failure %t.exe

target triple = "x86_64-pc-windows-msvc"

@protected_entry = internal constant ptr @protected

define internal i32 @sibling(i32 %x) noinline {
entry:
  %v = add i32 %x, 7
  ret i32 %v
}

define i32 @protected(i32 %x) {
entry:
  %sum = add i32 %x, 3
  ret i32 %sum
}

define i32 @main() {
entry:
  %protected.entry = load ptr, ptr @protected_entry, align 8
  %value = call i32 %protected.entry(i32 39)
  %ok = icmp eq i32 %value, 42
  %bad = xor i1 %ok, true
  %result = zext i1 %bad to i32
  ret i32 %result
}

; PE/COFF v1 keeps the same 96-byte record but uses a link-resolved REL32 target displacement.
; IR: @__obf_selfchk_record_{{[0-9]+}} = internal externally_initialized constant %obf.selfchk.record.v1
; IR-SAME: i32 2
; IR-SAME: i64 sub
; IR-SAME: i32 2
; IR-SAME: section ".obfsc$M"
; IR: call void @rt_core_sc0
; IR: call i64 @rt_core_cc(ptr @sibling, i64 16,
; IR: load volatile i64

; UNBOUND: SELF_CHECKSUM_PE_RECORD
; UNBOUND-SAME: flags=0x1
; UNBOUND-SAME: expected=0x0000000000000000
; UNBOUND-SAME: section=.obfsc
; PROBE: SELF_CHECKSUM_PROBE: records=1
; BIND: SELF_CHECKSUM_RECORD
; BIND-SAME: target_rva=0x
; BIND-SAME: state=BOUND(new)
; BIND: SELF_CHECKSUM_BIND: bound records=1
; REBOUND: SELF_CHECKSUM_BIND: already bound records=1
; OVERLAP-REJECT: obf-checksum-bind: PE RVA maps to multiple sections
; CHECKSUM-REJECT: obf-checksum-bind: PE v1 binding requires a zero PE header checksum
; SIGNED-REJECT: obf-checksum-bind: PE v1 binding refuses Authenticode-signed/certificate-bearing images
; BOUND: SELF_CHECKSUM_PE_RECORD
; BOUND-SAME: flags=0x3
; BOUND-SAME: expected=0x{{[0-9a-f]+}}
; BOUND-SAME: actual=0x{{[0-9a-f]+}}
; TAMPER: SELF_CHECKSUM_PE_TAMPER
; TAMPER-SAME: expected=0x
; TAMPER-SAME: tampered=0x
