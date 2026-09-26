; REQUIRES: system-linux-x86-64
;
; RUN: %lli %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/flatten-source-quota.yaml -passes=obf-control-flatten,obf-zero-comparison -S %s -o %t.zero.ll
; RUN: %FileCheck %s --check-prefix=ZERO < %t.zero.ll
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/flatten-source-quota.yaml -passes=obf-control-flatten,obf-instruction-substitute -S %s -o %t.subst.ll
; RUN: %FileCheck %s --check-prefix=SUBST < %t.subst.ll
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/flatten-source-quota.yaml -passes=obf-safe-pipeline -S %s -o %t.safe.ll
; RUN: %FileCheck %s --check-prefix=SAFE-PROBE --implicit-check-not='icmp eq i32 %0,' --implicit-check-not='xor i32 %0, %1{{$}}' < %t.safe.ll
; RUN: %FileCheck %s --check-prefix=SAFE-EQ < %t.safe.ll
; RUN: %FileCheck %s --check-prefix=SAFE-CONST < %t.safe.ll
; RUN: %opt -passes=verify -disable-output %t.safe.ll
; RUN: %llc -O2 -filetype=obj %t.safe.ll -o %t.safe.o
; RUN: %raw_clang %t.safe.o %obf_runtime -o %t.safe
; RUN: %t.safe
;
; Flatten now runs before zero-comparison, constant encoding, and instruction
; substitution in the strong classical pipeline. Keep the limited source-site
; quotas spending on the original four-block probe and the original one-block
; compare/add sites instead of generated handler or substitution artifacts.
;
; ZERO-LABEL: define i32 @probe(
; ZERO: entry:
; ZERO-NOT: %test = icmp eq i32 %a, 123
; ZERO: %test = {{.*}}%obf.zero{{.*}}
; ZERO: br i1 %test, label %obf.flat.edge{{[0-9]*}}, label %obf.flat.edge{{[0-9]+}}
;
; SUBST-LABEL: define i32 @probe(
; SUBST: left:
; SUBST-NOT: %v = xor i32 %a, %b
; SUBST: %obf.subst.
; SUBST: %v = {{.*}}%obf.subst{{.*}}
; SUBST-NEXT: br label %obf.flat.edge{{[0-9]+}}
; SUBST: right:
; SUBST-NEXT: %w = add i32 %a, %b
;
; SAFE-PROBE-LABEL: define i32 @probe(
; SAFE-PROBE-LABEL: define i32 @eq_source(i32 %0, i32 %1)
;
; SAFE-EQ-LABEL: define i32 @eq_source(i32 %0, i32 %1)
; SAFE-EQ-NOT: icmp eq i32 %{{[0-9]+}}, 42
; SAFE-EQ: %[[EQSH:[0-9]+]] = lshr i32 %{{[0-9]+}}, 31
; SAFE-EQ: %[[EQBIT:[0-9]+]] = and i32 %[[EQSH]], 1
; SAFE-EQ: %[[EQINV:[0-9]+]] = xor i32 %[[EQBIT]], 1
; SAFE-EQ: %[[EQCOND:[0-9]+]] = trunc i32 %[[EQINV]] to i1
; SAFE-EQ-NOT: icmp eq i32 %{{[0-9]+}}, 42
; SAFE-EQ: %[[EQRET:[0-9]+]] = select i1 %[[EQCOND]], i32 111, i32 222
; SAFE-EQ-NOT: icmp eq i32 %{{[0-9]+}}, 42
; SAFE-EQ: ret i32 %[[EQRET]]
; SAFE-EQ-NOT: icmp eq i32 %{{[0-9]+}}, 42
; SAFE-EQ-LABEL: define i32 @const_source(i32 %0, i32 %1)
;
; SAFE-CONST-LABEL: define i32 @const_source(i32 %0, i32 %1)
; SAFE-CONST-NOT: add i32 %{{[^,]+}}, 4660
; SAFE-CONST: ret i32 %{{[^ ]+}}
;

target triple = "x86_64-unknown-linux-gnu"

define i32 @probe(i32 %a, i32 %b) noinline {
entry:
  %test = icmp eq i32 %a, 123
  br i1 %test, label %left, label %right

left:
  %v = xor i32 %a, %b
  br label %exit

right:
  %w = add i32 %a, %b
  br label %exit

exit:
  %ret = phi i32 [ %v, %left ], [ %w, %right ]
  ret i32 %ret
}

define i32 @eq_source(i32 %x, i32 %y) {
entry:
  %masked = and i32 %x, %y
  %cmp = icmp eq i32 %masked, 42
  %ret = select i1 %cmp, i32 111, i32 222
  ret i32 %ret
}

define i32 @const_source(i32 %x, i32 %y) {
entry:
  %masked = and i32 %x, %y
  %sum = add i32 %masked, 4660
  ret i32 %sum
}

define i32 @main() {
entry:
  %left = call i32 @probe(i32 123, i32 7)
  %left.ok = icmp eq i32 %left, 124
  br i1 %left.ok, label %check.right, label %fail

check.right:
  %right = call i32 @probe(i32 5, i32 7)
  %right.ok = icmp eq i32 %right, 12
  br i1 %right.ok, label %check.eq.hit, label %fail

check.eq.hit:
  %eq.hit = call i32 @eq_source(i32 58, i32 43)
  %eq.hit.ok = icmp eq i32 %eq.hit, 111
  br i1 %eq.hit.ok, label %check.eq.miss, label %fail

check.eq.miss:
  %eq.miss = call i32 @eq_source(i32 57, i32 43)
  %eq.miss.ok = icmp eq i32 %eq.miss, 222
  br i1 %eq.miss.ok, label %check.const, label %fail

check.const:
  %const = call i32 @const_source(i32 58, i32 43)
  %const.ok = icmp eq i32 %const, 4702
  br i1 %const.ok, label %pass, label %fail

pass:
  ret i32 0

fail:
  ret i32 1
}
