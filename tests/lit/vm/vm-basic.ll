; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-basic.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t
; RUN: %opt -passes='instcombine<no-verify-fixpoint>,verify' -S %t -o %t.opt.ll
; RUN: %lli %t.opt.ll

define i32 @fold_value(i32 %value) {
entry:
  %xor = xor i32 %value, 4660
  %add = add nsw i32 %xor, 85
  ret i32 %add
}

define i32 @main() {
entry:
  %result = call i32 @fold_value(i32 0)
  %ok = icmp eq i32 %result, 4745
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

