; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/zero-comparison.yaml -passes='obf-zero-comparison,verify' -S %s -o %t.ll
; RUN: %FileCheck %s < %t.ll
; RUN: %lli %t.ll
; RUN: %opt -passes='default<O2>,verify' -S %t.ll -o %t.opt.ll
; RUN: %lli %t.opt.ll

; The non-dominance block order makes the pass visit select before its icmp.
; CHECK-LABEL: define i32 @choose
; CHECK: obf.zero.mask
; CHECK-NOT: select i1
; CHECK: ret i32
define i32 @choose(i32 %condition, i32 %true_value, i32 %false_value) {
entry:
  br label %compare
selected:
  %value = select i1 %eq, i32 %true_value, i32 %false_value
  ret i32 %value
compare:
  %eq = icmp eq i32 %condition, 0
  br label %selected
}

define i32 @main() {
entry:
  %a = call i32 @choose(i32 1, i32 poison, i32 7)
  %b = call i32 @choose(i32 0, i32 7, i32 poison)
  %c = call i32 @choose(i32 0, i32 42, i32 99)
  %d = call i32 @choose(i32 1, i32 42, i32 99)
  %af = freeze i32 %a
  %bf = freeze i32 %b
  %ok_a = icmp eq i32 %af, 7
  %ok_b = icmp eq i32 %bf, 7
  %ok_c = icmp eq i32 %c, 42
  %ok_d = icmp eq i32 %d, 99
  %ab = and i1 %ok_a, %ok_b
  %cd = and i1 %ok_c, %ok_d
  %ok = and i1 %ab, %cd
  %status = select i1 %ok, i32 0, i32 1
  ret i32 %status
}
