; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/constant-encode.yaml -passes=obf-constant-encode -S %s -o - | %FileCheck %s --check-prefix=IR
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/constant-encode.yaml -passes=obf-constant-encode -S %s -o - | %opt -passes='instcombine<no-verify-fixpoint>' -S -o - | %FileCheck %s --check-prefix=INST
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/constant-encode.yaml -passes=obf-constant-encode -S %s -o %t
; RUN: %lli %t

define i32 @value() {
entry:
  ret i32 42
}

define i32 @main() {
entry:
  %value = call i32 @value()
  %ok = icmp eq i32 %value, 42
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; IR-DAG: @__obf_entropy_anchor = external externally_initialized global i64, align 8
; IR-DAG: @__obf_entropy_anchor_ref = external externally_initialized global ptr, align 8
; IR-LABEL: define i32 @value()
; IR: %obf.entropy.direct = load i64, ptr @__obf_entropy_anchor
; IR: %obf.entropy.ref = load ptr, ptr @__obf_entropy_anchor_ref
; IR: store i64 %obf.entropy.direct, ptr %obf.entropy.ref
; IR: %obf.entropy.indirect = load i64, ptr @__obf_entropy_anchor
; IR: %obf.const.mask = {{(sub|or) i32}}
; IR: %obf.const = {{(sub|or) i32}}
; IR: ret i32 %obf.const
; IR-NOT: ret i32 42

; INST-DAG: @__obf_entropy_anchor = external externally_initialized global i64, align 8
; INST-DAG: @__obf_entropy_anchor_ref = external externally_initialized global ptr, align 8
; INST-LABEL: define i32 @value()
; INST: %obf.entropy.direct = load i64, ptr @__obf_entropy_anchor
; INST: %obf.entropy.ref = load ptr, ptr @__obf_entropy_anchor_ref
; INST: store i64 %obf.entropy.direct, ptr %obf.entropy.ref
; INST: %obf.const = {{(sub|or) i32}}
; INST: ret i32 %obf.const
; INST-NOT: ret i32 42
