; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/indirect-dispatch.yaml -passes=obf-indirect-dispatch -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/indirect-dispatch.yaml -passes=obf-indirect-dispatch -S %s -o - | %opt -passes=verify -disable-output
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/indirect-dispatch.yaml -passes=obf-indirect-dispatch -S %s -o %t
; RUN: %lli %t

define i32 @multi(i32 %x) {
entry:
  %y = add i32 %x, 1
  br label %s1
s1:
  %c1 = icmp sgt i32 %y, 5
  br i1 %c1, label %hi, label %lo
hi:
  %c2 = icmp sgt i32 %y, 10
  br i1 %c2, label %big, label %mid
lo:
  ret i32 1
mid:
  ret i32 2
big:
  ret i32 3
}

define i32 @main() {
entry:
  %a = call i32 @multi(i32 0)
  %b = call i32 @multi(i32 7)
  %c = call i32 @multi(i32 20)
  %ok0 = icmp eq i32 %a, 1
  %ok1 = icmp eq i32 %b, 2
  %ok2 = icmp eq i32 %c, 3
  %all0 = and i1 %ok0, %ok1
  %all = and i1 %all0, %ok2
  %ret = select i1 %all, i32 0, i32 1
  ret i32 %ret
}

; CHECK-LABEL: define i32 @multi(i32 %x)
; CHECK: entry:
; Token materialization is site-local: nothing is hoisted into the entry block.
; CHECK-NOT: obf.idis
; CHECK: s1:
; Site 0's tokens are materialized in %s1.
; CHECK: %obf.idis.site0.
; CHECK: hi:
; Site 1's tokens are materialized in %hi.
; CHECK: %obf.idis.site1.
; CHECK: indirectbr ptr
; CHECK-NOT: br i1
