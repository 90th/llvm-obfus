; Positive ABI case: a target whose only ABI attributes are sign/zero extension
; is accepted. It must be virtualized (VM implementation emitted) and the
; signext/zeroext attributes must survive onto the implementation and the
; rewritten ordinary callsite (not stripped), and still verify and execute.
;
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-boundary-signext.yaml -passes='obf-vm,verify' -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-boundary-signext.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t

define signext i16 @ext_target(i8 signext %x, i8 zeroext %y) {
entry:
  %xw = sext i8 %x to i16
  %yw = zext i8 %y to i16
  %s = add i16 %xw, %yw
  ret i16 %s
}

define signext i16 @caller_ext(i8 signext %x, i8 zeroext %y) {
entry:
  %r = call signext i16 @ext_target(i8 signext %x, i8 zeroext %y)
  ret i16 %r
}

define i32 @main() {
entry:
  %r = call signext i16 @caller_ext(i8 signext 3, i8 zeroext 5)
  %rw = sext i16 %r to i32
  %ok = icmp eq i32 %rw, 8
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; Accepted target is virtualized and keeps its extension attributes on the impl.
; CHECK-DAG: define internal signext i16 @__obf_vm_i_{{[A-Za-z0-9_]+}}(i8 signext %x, i8 zeroext %y, i64 %obf.hidden_token)
; The rewritten ordinary callsite forwards the extension attributes (plus token).
; CHECK-DAG: call signext i16 %{{[A-Za-z0-9_.]+}}(i8 signext %x, i8 zeroext %y, i64
