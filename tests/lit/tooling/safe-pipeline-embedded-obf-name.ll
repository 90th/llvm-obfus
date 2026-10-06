; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/safe-pipeline-embedded-obf-name.yaml -passes=obf-safe-pipeline -S %s -o %t
; RUN: %lli %t

define i32 @verify_obf_token(i32 %value) {
entry:
  %xor = xor i32 %value, 4660
  %add = add nsw i32 %xor, 85
  ret i32 %add
}

define i32 @main() {
entry:
  %folded = call i32 @verify_obf_token(i32 0)
  %ok = icmp eq i32 %folded, 4745
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

