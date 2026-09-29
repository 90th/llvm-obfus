; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-extrema-semantics.yaml -passes=obf-feature-report -disable-output %s | jq -r '.transforms[] | select(.pass == "vm") | [.target_name, .status, (.count | tostring)] | join("|")' | %FileCheck %s --check-prefix=ADMIT
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-extrema-semantics.yaml -passes='obf-vm,verify' -S %s -o %t.raw.ll
; RUN: %FileCheck %s --check-prefix=VM < %t.raw.ll
; RUN: %lli %s
; RUN: %lli %t.raw.ll
; RUN: %opt -passes='instcombine<no-verify-fixpoint>,verify' -S %t.raw.ll -o %t.instcombine.ll
; RUN: %lli %t.instcombine.ll
; RUN: %opt -O2 -S %t.raw.ll -o %t.o2.ll
; RUN: %lli %t.o2.ll

; The original max/min must select one value of an undef operand: it cannot
; compare one undef choice then return a different, out-of-range choice.
; Poison may flow through an unused intrinsic result or be frozen by the caller;
; neither case permits the VM to branch on the poison comparison.
declare i8 @llvm.umax.i8(i8, i8)
declare i8 @llvm.smin.i8(i8, i8)
declare i8 @llvm.umin.i8(i8, i8)
declare i32 @llvm.smax.i32(i32, i32)

@observed = global i8 0

define i8 @vm_undef_umax() {
entry:
  %result = call i8 @llvm.umax.i8(i8 undef, i8 100)
  ret i8 %result
}

define i8 @vm_undef_smin() {
entry:
  %result = call i8 @llvm.smin.i8(i8 undef, i8 100)
  ret i8 %result
}

define i32 @vm_discard_poison() {
entry:
  %unused = call i32 @llvm.smax.i32(i32 poison, i32 7)
  ret i32 0
}

define i8 @vm_freeze_poison() {
entry:
  %result = call i8 @llvm.umin.i8(i8 poison, i8 2)
  %safe = freeze i8 %result
  ret i8 %safe
}

define i32 @main() {
entry:
  %unsigned = call i8 @vm_undef_umax()
  %signed = call i8 @vm_undef_smin()
  %discarded = call i32 @vm_discard_poison()
  %frozen = call i8 @vm_freeze_poison()
  store volatile i8 %frozen, ptr @observed
  %unsigned.ok = icmp uge i8 %unsigned, 100
  %signed.ok = icmp sle i8 %signed, 100
  %discarded.ok = icmp eq i32 %discarded, 0
  %both.ok = and i1 %unsigned.ok, %signed.ok
  %all.ok = and i1 %both.ok, %discarded.ok
  %ret = select i1 %all.ok, i32 0, i32 1
  ret i32 %ret
}

; ADMIT-DAG: vm_undef_umax|applied|5
; ADMIT-DAG: vm_undef_smin|applied|5
; ADMIT-DAG: vm_discard_poison|applied|5
; ADMIT-DAG: vm_freeze_poison|applied|6

; VM-LABEL: define i8 @vm_undef_umax()
; VM: entry.obf.vm.wrapper:
; VM: call i8 %vm_undef_umax.obf.wrapper.indirect
; VM-LABEL: define internal i8 @__obf_vm_i_{{[A-Za-z0-9_]+}}(i64 %obf.hidden_token)
; VM: %obf.vm.freeze{{[0-9]*}} = freeze i8
; VM: %obf.vm.freeze{{[0-9]*}} = freeze i8
; VM: vm.select.store.true.
