; RUN: %obf_driver --config=%S/Inputs/constant-mode-config.yaml | %FileCheck %s

; CHECK: Loaded config from
; CHECK: constant_encoding.max_constants_per_function: 7
; CHECK: constant_encoding.mode: all
; CHECK: constant_encoding.min_bit_width: 16

define void @dummy() {
entry:
  ret void
}
