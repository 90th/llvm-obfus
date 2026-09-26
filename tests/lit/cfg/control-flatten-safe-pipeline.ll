; REQUIRES: system-linux-x86-64
;
; RUN: %raw_clang -O2 -S -emit-llvm -x ir %s -o %t.optimized.ll
; RUN: %FileCheck %s --check-prefix=OPT < %t.optimized.ll
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/control-flatten.yaml -passes=obf-safe-pipeline -S %t.optimized.ll -o %t.protected.ll
; RUN: %FileCheck %s --check-prefix=IR < %t.protected.ll
; RUN: %opt -passes=verify -disable-output %t.protected.ll
; RUN: %llc -O2 -filetype=obj %t.protected.ll -o %t.protected.o
; RUN: %raw_clang %t.protected.o %obf_runtime -o %t.protected
; RUN: %t.protected ABCD
; RUN: %python -c "import subprocess,sys; sys.exit(0 if subprocess.run(sys.argv[1:]).returncode == 1 else 1)" %t.protected ABCE
; RUN: %python %S/../Inputs/control-flatten-native-check.py --llvm-objdump %llvm_objdump --binary %t.protected --function verify_like
;
; Optimized four-block verify_like regression: %raw_clang -O2 must keep a real
; verify_like call and reduce the function to an acyclic four-block CFG before
; obf-safe-pipeline. Any native back edge in verify_like after protection must
; therefore come from the flattened dispatcher rather than the source function.
;
; OPT-LABEL: define{{.*}} @verify_like(
; OPT: entry:
; OPT-NEXT: %len_ok = icmp eq i64 %n, 4
; OPT-NEXT: br i1 %len_ok, label %sum, label %fail
; OPT-NOT: {{^[A-Za-z0-9_.-]+:$}}
; OPT: sum:
; OPT: br i1 %ok, label %common.ret, label %fail
; OPT-NOT: {{^[A-Za-z0-9_.-]+:$}}
; OPT: common.ret:
; OPT: %common.ret.op = phi i1 [ false, %fail ], [ true, %sum ]
; OPT-NEXT: ret i1 %common.ret.op
; OPT-NOT: {{^[A-Za-z0-9_.-]+:$}}
; OPT: fail:
; OPT-NEXT: br label %common.ret
; OPT-NEXT: }
; OPT-LABEL: define{{.*}} @main(
; OPT: call{{.*}} @verify_like(ptr {{[^,]*}}%{{[^,]+}}, i64 {{[^)]*}}%{{[^)]+}})
;
; IR-LABEL: define{{.*}} @verify_like(
; IR-SAME: !obf.flattened ![[FLAT:[0-9]+]] {
; IR: [[STATE:%[0-9]+]] = phi i32 [ %{{[0-9]+}}, %{{[0-9]+}} ], [ %{{[0-9]+}}, %{{[0-9]+}} ], [ %{{[0-9]+}}, %{{[0-9]+}} ], [ %{{[0-9]+}}, %{{[0-9]+}} ], [ %{{[0-9]+}}, %{{[0-9]+}} ], [ %{{[0-9]+}}, %{{[0-9]+}} ]
; IR: br i1 %{{[0-9]+}}, label %[[RECUR:[0-9]+]], label %[[SPLIT:[0-9]+]], !obf.flattened.block ![[ROOT:[0-9]+]]
; IR: [[RECUR]]:
; IR: load { i64, i64 }, ptr %{{[0-9]+}}, align 8
; IR: [[SPLIT]]:
; IR: icmp slt i32 %{{[0-9]+}}, %{{[0-9]+}}
; IR: br i1 %{{[0-9]+}}, label %{{[0-9]+}}, label %{{[0-9]+}}, !obf.flattened.block ![[ORDER:[0-9]+]]
; IR: icmp ugt i32 %{{[0-9]+}}, [[STATE]]
; IR: br i1 %{{[0-9]+}}, label %{{[0-9]+}}, label %{{[0-9]+}}, !obf.flattened.block ![[ORDER2:[0-9]+]]
; IR: trunc i32 %{{[0-9]+}} to i1
; IR: br i1 %{{[0-9]+}}, label %{{[0-9]+}}, label %[[RECUR]], !obf.flattened.block ![[EQA:[0-9]+]]
; IR: trunc i32 %{{[0-9]+}} to i1
; IR: br i1 %{{[0-9]+}}, label %{{[0-9]+}}, label %[[RECUR]], !obf.flattened.block ![[EQB:[0-9]+]]
;
; The accepting and rejecting runs use argv[1] at runtime so verify_like stays
; live through codegen and the linked binary check observes the real native CFG.
;

target triple = "x86_64-unknown-linux-gnu"

define i1 @verify_like(ptr %p, i64 %n) noinline {
entry:
  %len_ok = icmp eq i64 %n, 4
  br i1 %len_ok, label %sum, label %fail

sum:
  %p1 = getelementptr inbounds i8, ptr %p, i64 1
  %p2 = getelementptr inbounds i8, ptr %p, i64 2
  %p3 = getelementptr inbounds i8, ptr %p, i64 3
  %c0 = load i8, ptr %p, align 1
  %c1 = load i8, ptr %p1, align 1
  %c2 = load i8, ptr %p2, align 1
  %c3 = load i8, ptr %p3, align 1
  %w0 = zext i8 %c0 to i32
  %w1 = zext i8 %c1 to i32
  %w2 = zext i8 %c2 to i32
  %w3 = zext i8 %c3 to i32
  %s01 = add nuw nsw i32 %w0, %w1
  %s012 = add nuw nsw i32 %s01, %w2
  %sum4 = add nuw nsw i32 %s012, %w3
  %ok = icmp eq i32 %sum4, 266
  br i1 %ok, label %pass, label %fail

pass:
  ret i1 true

fail:
  ret i1 false
}

define i64 @input_len(ptr %p) {
entry:
  br label %loop

loop:
  %i = phi i64 [ 0, %entry ], [ %next, %body ]
  %cur = getelementptr inbounds i8, ptr %p, i64 %i
  %ch = load i8, ptr %cur, align 1
  %done = icmp eq i8 %ch, 0
  br i1 %done, label %exit, label %body

body:
  %next = add nuw nsw i64 %i, 1
  br label %loop

exit:
  ret i64 %i
}

define i32 @main(i32 %argc, ptr %argv) {
entry:
  %has_arg = icmp eq i32 %argc, 2
  br i1 %has_arg, label %load, label %usage

load:
  %argv1.slot = getelementptr inbounds ptr, ptr %argv, i64 1
  %input = load ptr, ptr %argv1.slot, align 8
  %len = call i64 @input_len(ptr %input)
  %ok = call i1 @verify_like(ptr %input, i64 %len)
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret

usage:
  ret i32 2
}
