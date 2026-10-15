; RUN: %lli %s
; RUN: env OBF_COVERAGE_REPORT=%t.coverage.json %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-opcode-scramble.yaml -passes=obf-vm -S %s -o %t
; RUN: %python %S/../Inputs/report_contract.py whole-vm %t.coverage.json --owner alpha_add --owner beta_add
; RUN: %lli %t

define i32 @alpha_add(i32 %x) {
entry:
  %sum = add i32 %x, 5
  ret i32 %sum
}

define i32 @beta_add(i32 %x) {
entry:
  %sum = add i32 %x, 5
  ret i32 %sum
}

define i32 @main() {
entry:
  %a = call i32 @alpha_add(i32 7)
  %b = call i32 @beta_add(i32 7)
  %ok1 = icmp eq i32 %a, 12
  %ok2 = icmp eq i32 %b, 12
  %ok = and i1 %ok1, %ok2
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}
