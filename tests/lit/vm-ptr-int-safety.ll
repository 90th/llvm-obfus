; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-ptr-int-safety-integral.yaml -passes=obf-vm -S %s -o - | %FileCheck %s --check-prefix=INTEGRAL
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-ptr-int-safety-nonintegral.yaml -passes=obf-feature-report -disable-output %s | jq -r '.transforms[] | select(.pass == "vm") | [.target_name, .status, .detail] | join("|")' | %FileCheck %s --check-prefix=REPORT
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-ptr-int-safety-nonintegral.yaml -passes=obf-vm -S %s -o - | %FileCheck %s --check-prefix=NONINTEGRAL --implicit-check-not='ptrtoint' --implicit-check-not='inttoptr' --implicit-check-not='__obf_vm_'
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-ptr-int-safety-nonintegral-strong.yaml -passes=obf-safe-pipeline -disable-output %s 2>&1 | %FileCheck %s --check-prefix=STRONG

target datalayout = "e-m:e-p:64:64-p1:64:64-ni:1-i64:64-n8:16:32:64-S128"

define i32 @integral_vm(i32 %x) {
entry:
  %add = add i32 %x, 7
  ret i32 %add
}

define i32 @nonintegral_vm(i32 %x) addrspace(1) {
entry:
  %add = add i32 %x, 9
  ret i32 %add
}

define i32 @nonintegral_strong_vm(i32 %x) addrspace(1) {
entry:
  %xor = xor i32 %x, 3
  ret i32 %xor
}

define i32 @main() {
entry:
  %a = call i32 @integral_vm(i32 5)
  %b = call addrspace(1) i32 @nonintegral_vm(i32 7)
  %c = call addrspace(1) i32 @nonintegral_strong_vm(i32 9)
  %a.ok = icmp eq i32 %a, 12
  %b.ok = icmp eq i32 %b, 16
  %c.ok = icmp eq i32 %c, 10
  %ab = and i1 %a.ok, %b.ok
  %ok = and i1 %ab, %c.ok
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; INTEGRAL-LABEL: define i32 @integral_vm(i32 %x)
; INTEGRAL: inttoptr i{{[0-9]+}} %integral_vm.obf.wrapper.decoded to ptr

; REPORT: nonintegral_vm|skipped|non-integral pointer space unsupported by VM lowering

; NONINTEGRAL-LABEL: define i32 @nonintegral_vm(i32 %x) addrspace(1)
; NONINTEGRAL: %add = add i32 %x, 9

; STRONG: LLVM ERROR: strong_vm invariant violation: function nonintegral_strong_vm was not virtualized
; STRONG: reason_tag=non_integral_pointer_unsupported
