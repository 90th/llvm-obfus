; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/progress-warnings.yaml -passes=obf-safe-pipeline -disable-output %s 2>&1 | %FileCheck %s --check-prefix=PROGRESS
;
; PROGRESS: llvm-obfus: warning: starting strong_vm lowering for 1 function(s); this can take a while
; PROGRESS: llvm-obfus: warning: starting strong_vm hardening for 1 function(s); this can take a while

define i32 @progress_strong_vm(i32 %value) {
entry:
  %xor = xor i32 %value, 4660
  %add = add nsw i32 %xor, 85
  ret i32 %add
}

define i32 @main() {
entry:
  %folded = call i32 @progress_strong_vm(i32 0)
  %ok = icmp eq i32 %folded, 4745
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}
