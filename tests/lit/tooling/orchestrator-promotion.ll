; RUN: env OBF_COVERAGE_REPORT=%t.coverage.json %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/orchestrator-promotion.yaml -passes=obf-feature-report -disable-output %s > %t.predictions.json
; RUN: %python %S/../Inputs/report_contract.py promotion %t.predictions.json --coverage %t.coverage.json

define i32 @secret_core(i32 %x) {
entry:
  %xor = xor i32 %x, 8738
  %add = add nsw i32 %xor, 17
  ret i32 %add
}

define i32 @relay(i32 %x) {
entry:
  %value = call i32 @secret_core(i32 %x)
  ret i32 %value
}

define i32 @main() {
entry:
  %value = call i32 @relay(i32 0)
  %ok = icmp eq i32 %value, 8755
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

