; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/orchestrator-promotion.yaml -passes=obf-feature-report -disable-output %s | %FileCheck %s

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

; CHECK: "name":"secret_core"{{.*}}"level":"strong_vm"
; CHECK: "name":"relay"{{.*}}"detail":"default; orchestrator promotion raised to strong via protected callee secret_core (protected result escapes through a return)"{{.*}}"level":"strong"{{.*}}"name":"main"{{.*}}"detail":"default; orchestrator promotion raised to strong via protected callee relay (top-level protected call)"{{.*}}"level":"strong"
