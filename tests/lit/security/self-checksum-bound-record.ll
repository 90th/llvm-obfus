; REQUIRES: system-linux-x86-64
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/self-checksum-bound.yaml -passes=obf-self-checksum -S %s -o %t.bound.ll
; RUN: %FileCheck %s --check-prefix=IR < %t.bound.ll
; RUN: %opt -O0 -S %t.bound.ll -o - | %FileCheck %s --check-prefix=OPT
; RUN: %opt -O1 -S %t.bound.ll -o - | %FileCheck %s --check-prefix=OPT
; RUN: %opt -O2 -S %t.bound.ll -o - | %FileCheck %s --check-prefix=OPT
; RUN: %opt -O3 -S %t.bound.ll -o - | %FileCheck %s --check-prefix=OPT
;
; REQUIRES: has-self-checksum-binder
; RUN: %raw_clang -O2 -Wl,--build-id=none %t.bound.ll %obf_runtime -o %t.exe
; RUN: %python %S/../Inputs/self_checksum_elf_tool.py inspect %t.exe | %FileCheck %s --check-prefix=UNBOUND
; RUN: not --crash %t.exe
; RUN: %obf_checksum_bind %t.exe | %FileCheck %s --check-prefix=BIND
; RUN: %python %S/../Inputs/self_checksum_elf_tool.py inspect %t.exe | %FileCheck %s --check-prefix=BOUND
; RUN: %t.exe
; RUN: %python %S/../Inputs/self_checksum_elf_tool.py tamper %t.exe | %FileCheck %s --check-prefix=TAMPER
; RUN: not %t.exe

target triple = "x86_64-unknown-linux-gnu"

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

; IR: %obf.selfchk.record.v1 = type <{ i32, i16, i16, i32, i32, i32, i32, i64, i64, i32, i32, i32, i32, i64, i64, [24 x i8] }>
; IR: @__obf_selfchk_record_{{[0-9]+}} = internal externally_initialized constant %obf.selfchk.record.v1
; IR-SAME: i32 1129529935
; IR-SAME: i16 1
; IR-SAME: i16 96
; IR-SAME: i32 1
; IR-SAME: i32 16
; IR-SAME: i64 0
; IR-SAME: section ".obfsc.
; IR: %obf.selfchk.flags = load volatile i32
; IR: call void @rt_core_sc0(i32 %obf.selfchk.flags)
; IR: %obf.selfchk.raw = call i64 @rt_core_cc(ptr @sibling, i64 16,
; IR: %obf.selfchk.expected = load volatile i64
; IR: %obf.selfchk.delta64 = xor i64 %obf.selfchk.raw, %obf.selfchk.expected
; IR: %obf.selfchk.delta = trunc i64 %obf.selfchk.delta64 to i32
; IR: %obf.selfchk.adjusted = xor i32 %x, %obf.selfchk.delta

; OPT: load volatile i32
; OPT: call void @rt_core_sc0
; OPT: call i64 @rt_core_cc
; OPT: load volatile i64
; OPT: xor i64

; UNBOUND: SELF_CHECKSUM_TEST_RECORD
; UNBOUND-SAME: flags=0x1
; UNBOUND-SAME: expected=0x0000000000000000
; UNBOUND-SAME: section=.obfsc.

; BIND: SELF_CHECKSUM_RECORD
; BIND-SAME: state=BOUND(new)
; BIND: SELF_CHECKSUM_BIND: bound records=1

; BOUND: SELF_CHECKSUM_TEST_RECORD
; BOUND-SAME: flags=0x3
; BOUND-SAME: expected=0x

; TAMPER: SELF_CHECKSUM_TEST_TAMPER
; TAMPER-SAME: expected=0x
; TAMPER-SAME: tampered=0x
