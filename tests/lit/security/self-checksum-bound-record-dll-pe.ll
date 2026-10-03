; REQUIRES: system-windows-x86-64, has-self-checksum-binder
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/self-checksum-bound.yaml -passes=obf-self-checksum -S %s -o %t.bound.ll
; RUN: %FileCheck %s --check-prefix=IR < %t.bound.ll
; RUN: %raw_clang -shared -O2 -Wl,/subsystem:windows,/dynamicbase,/base:0x180000000 %t.bound.ll %obf_runtime -o %t.dll
; RUN: %raw_clang -O2 %S/../Inputs/self-checksum-pe-dll-loader.c -o %t.loader.exe
; RUN: %python %S/../Inputs/self_checksum_pe_tool.py inspect %t.dll | %FileCheck %s --check-prefix=UNBOUND
; RUN: %obf_checksum_bind --probe %t.dll | %FileCheck %s --check-prefix=PROBE
; RUN: %python %S/../Inputs/assert_trap_within.py %t.loader.exe %t.dll 2>&1 | %FileCheck %s --check-prefix=UNBOUND-RUNTIME
; RUN: %obf_checksum_bind %t.dll | %FileCheck %s --check-prefix=BIND
; RUN: %python %S/../Inputs/self_checksum_pe_tool.py inspect %t.dll | %FileCheck %s --check-prefix=BOUND
; RUN: cp %t.dll %t.bound-copy.dll
; RUN: %obf_checksum_bind %t.dll | %FileCheck %s --check-prefix=REBOUND
; RUN: cmp %t.dll %t.bound-copy.dll
; RUN: %t.loader.exe %t.dll | %FileCheck %s --check-prefix=RUNTIME
;
; Header mutation hazards still reject DLLs without changing the input.
; RUN: cp %t.dll %t.checksum.dll
; RUN: %python %S/../Inputs/self_checksum_pe_tool.py mark-checksum %t.checksum.dll
; RUN: cp %t.checksum.dll %t.checksum-before.dll
; RUN: %expect_failure %obf_checksum_bind %t.checksum.dll 2>&1 | %FileCheck %s --check-prefix=CHECKSUM-REJECT
; RUN: cmp %t.checksum.dll %t.checksum-before.dll
; RUN: cp %t.dll %t.signed.dll
; RUN: %python %S/../Inputs/self_checksum_pe_tool.py mark-signed %t.signed.dll
; RUN: cp %t.signed.dll %t.signed-before.dll
; RUN: %expect_failure %obf_checksum_bind %t.signed.dll 2>&1 | %FileCheck %s --check-prefix=SIGNED-REJECT
; RUN: cmp %t.signed.dll %t.signed-before.dll
; RUN: cp %t.signed.dll %t.signed-checksum.dll
; RUN: %python %S/../Inputs/self_checksum_pe_tool.py mark-checksum %t.signed-checksum.dll
; RUN: cp %t.signed-checksum.dll %t.signed-checksum-before.dll
; RUN: %expect_failure %obf_checksum_bind %t.signed-checksum.dll 2>&1 | %FileCheck %s --check-prefix=SIGNED-REJECT
; RUN: cmp %t.signed-checksum.dll %t.signed-checksum-before.dll
;
; Native, EFI, and unknown subsystems remain outside the mutation contract.
; Probe only counts records and does not authorize binding.
; RUN: cp %t.dll %t.native.dll
; RUN: %python %S/../Inputs/self_checksum_pe_tool.py mark-native %t.native.dll
; RUN: %obf_checksum_bind --probe %t.native.dll | %FileCheck %s --check-prefix=PROBE
; RUN: cp %t.native.dll %t.native-before.dll
; RUN: %expect_failure %obf_checksum_bind %t.native.dll 2>&1 | %FileCheck %s --check-prefix=SUBSYSTEM-REJECT
; RUN: cmp %t.native.dll %t.native-before.dll
; RUN: cp %t.dll %t.efi.dll
; RUN: %python %S/../Inputs/self_checksum_pe_tool.py mark-efi %t.efi.dll
; RUN: cp %t.efi.dll %t.efi-before.dll
; RUN: %expect_failure %obf_checksum_bind %t.efi.dll 2>&1 | %FileCheck %s --check-prefix=SUBSYSTEM-REJECT
; RUN: cmp %t.efi.dll %t.efi-before.dll
; RUN: cp %t.dll %t.unknown.dll
; RUN: %python %S/../Inputs/self_checksum_pe_tool.py mark-unknown %t.unknown.dll
; RUN: cp %t.unknown.dll %t.unknown-before.dll
; RUN: %expect_failure %obf_checksum_bind %t.unknown.dll 2>&1 | %FileCheck %s --check-prefix=SUBSYSTEM-REJECT
; RUN: cmp %t.unknown.dll %t.unknown-before.dll
;
; The sampled sibling never executes. Its tamper must corrupt the protected result,
; not fail through an invalid instruction in the sampled function.
; RUN: cp %t.dll %t.tampered.dll
; RUN: %python %S/../Inputs/self_checksum_pe_tool.py tamper %t.tampered.dll | %FileCheck %s --check-prefix=TAMPER
; RUN: cp %t.tampered.dll %t.tampered-before.dll
; RUN: %expect_failure %obf_checksum_bind %t.tampered.dll 2>&1 | %FileCheck %s --check-prefix=TAMPER-REJECT
; RUN: cmp %t.tampered.dll %t.tampered-before.dll
; RUN: %expect_failure %t.loader.exe %t.tampered.dll 2>&1 | %FileCheck %s --check-prefix=TAMPER-RUNTIME
;
; A bound checksum field change also rejects binding and corrupts the 64-bit result.
; RUN: cp %t.dll %t.metadata-tampered.dll
; RUN: %python %S/../Inputs/self_checksum_pe_tool.py tamper-checksum %t.metadata-tampered.dll | %FileCheck %s --check-prefix=METADATA-TAMPER
; RUN: cp %t.metadata-tampered.dll %t.metadata-tampered-before.dll
; RUN: %expect_failure %obf_checksum_bind %t.metadata-tampered.dll 2>&1 | %FileCheck %s --check-prefix=TAMPER-REJECT
; RUN: cmp %t.metadata-tampered.dll %t.metadata-tampered-before.dll
; RUN: %expect_failure %t.loader.exe %t.metadata-tampered.dll 2>&1 | %FileCheck %s --check-prefix=TAMPER-RUNTIME

target triple = "x86_64-pc-windows-msvc"

; This absolute data pointer creates a genuine unrelated DIR64 loader fixup.
; The native consumer compares its loaded value with the record-relative target.
@relocation_anchor = dllexport global ptr @sibling, align 8

define internal i64 @sibling(i64 %x) noinline optnone {
entry:
  %a = mul i64 %x, 7
  %b = xor i64 %a, 173
  %c = add i64 %b, 31
  %d = mul i64 %c, %x
  %e = xor i64 %d, 4093
  ret i64 %e
}

define dllexport i64 @protected(i64 %x) {
entry:
  %sum = add i64 %x, 3
  ret i64 %sum
}

; IR: @__obf_selfchk_record_{{[0-9]+}} = internal externally_initialized constant %obf.selfchk.record.v1
; IR-SAME: section ".obfsc$M"
; IR: call void @rt_core_sc0
; IR: call i64 @rt_core_cc(ptr @sibling, i64 16,
; IR: load volatile i64
; UNBOUND: SELF_CHECKSUM_PE_RECORD
; UNBOUND-SAME: flags=0x1
; UNBOUND-SAME: expected=0x0000000000000000
; PROBE: SELF_CHECKSUM_PROBE: records=1
; UNBOUND-RUNTIME: SELF_CHECKSUM_DLL_REBASED
; UNBOUND-RUNTIME: SELF_CHECKSUM_DLL_CALL
; UNBOUND-RUNTIME-NOT: SELF_CHECKSUM_DLL_PASS
; BIND: SELF_CHECKSUM_RECORD
; BIND-SAME: state=BOUND(new)
; BIND: SELF_CHECKSUM_BIND: bound records=1
; BOUND: SELF_CHECKSUM_PE_RECORD
; BOUND-SAME: flags=0x3
; BOUND-SAME: expected=0x[[CHECKSUM:[0-9a-f]+]] actual=0x[[CHECKSUM]]
; REBOUND: SELF_CHECKSUM_BIND: already bound records=1
; RUNTIME: SELF_CHECKSUM_DLL_REBASED
; RUNTIME-SAME: fixup=DIR64
; RUNTIME: SELF_CHECKSUM_DLL_CALL
; RUNTIME: SELF_CHECKSUM_DLL_PASS
; CHECKSUM-REJECT: obf-checksum-bind: PE v1 binding requires a zero PE header checksum
; SIGNED-REJECT: obf-checksum-bind: PE v1 binding refuses Authenticode-signed/certificate-bearing images
; SUBSYSTEM-REJECT: obf-checksum-bind: PE v1 binding supports only Windows GUI/console user-mode images. Native and EFI subsystems are unsupported
; TAMPER: SELF_CHECKSUM_PE_TAMPER
; METADATA-TAMPER: SELF_CHECKSUM_PE_TAMPERED_CHECKSUM
; TAMPER-REJECT: obf-checksum-bind: already-bound record checksum does not match final target bytes
; TAMPER-RUNTIME: SELF_CHECKSUM_DLL_REBASED
; TAMPER-RUNTIME: SELF_CHECKSUM_DLL_CALL
; TAMPER-RUNTIME: SELF_CHECKSUM_DLL_TAMPER actual=0x
; TAMPER-RUNTIME-NOT: SELF_CHECKSUM_DLL_PASS
