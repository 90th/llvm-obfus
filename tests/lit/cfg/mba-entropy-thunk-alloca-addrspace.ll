; RUN: %lli %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/mba-entropy-thunk-families.yaml -passes='obf-constant-encode,verify' -S %s -o %t.first.ll
; RUN: %FileCheck %s --check-prefix=IR --implicit-check-not=addrspacecast < %t.first.ll
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/mba-entropy-thunk-families.yaml -passes='obf-constant-encode,verify' -S %s -o %t.second.ll
; RUN: cmp %t.first.ll %t.second.ll
; RUN: %lli %t.first.ll
; RUN: %opt -passes='instcombine<no-verify-fixpoint>,verify' -S %t.first.ll -o %t.instcombine.ll
; RUN: %lli %t.instcombine.ll
; RUN: %opt -O2 -S %t.first.ll -o %t.o2.ll
; RUN: %lli %t.o2.ll
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/mba-entropy-thunk-families.yaml --obf-seed=2 -passes='obf-constant-encode,verify' -S %s -o %t.seed2.ll
; RUN: %FileCheck %s --check-prefix=IR --implicit-check-not=addrspacecast < %t.seed2.ll
; RUN: %lli %t.seed2.ll

target datalayout = "e-p:64:64-p1:64:64-A1"

; Stack caches must remain in the datalayout's alloca address space. Verification
; checks the selected thunk's call, GEP, load, and store types; no address-space
; cast may conceal an AS0 out-parameter ABI. Results must agree for both ABIs.
@thunk_inputs = private constant [16 x i32] [
  i32 0, i32 1, i32 -1, i32 7, i32 10, i32 3, i32 50, i32 85,
  i32 4660, i32 -17, i32 41, i32 429496720,
  i32 2147483630, i32 2147483647, i32 -2147483648, i32 -2147483647
]

define i32 @entropy_thunk_a(i32 %x) {
entry:
  %a = add i32 %x, 17
  %b = xor i32 %a, 85
  %c = sub i32 %b, 123
  ret i32 %c
}

define i32 @entropy_thunk_b(i32 %x) {
entry:
  %a = xor i32 %x, 4660
  %b = add i32 %a, 85
  %c = sub i32 %b, 19
  ret i32 %c
}

define i32 @entropy_thunk_c(i32 %x) {
entry:
  %a = add i32 %x, 9
  %b = mul i32 %a, 5
  %c = xor i32 %b, 99
  ret i32 %c
}

define i32 @entropy_thunk_d(i32 %x) {
entry:
  %a = sub i32 %x, 41
  %b = xor i32 %a, 7
  %c = add i32 %b, 3
  ret i32 %c
}

define i1 @check_thunks(i32 %x) {
entry:
  %a = call i32 @entropy_thunk_a(i32 %x)
  %a.frozen = freeze i32 %a
  %a.add = add i32 %x, 17
  %a.xor = xor i32 %a.add, 85
  %a.expected = sub i32 %a.xor, 123
  %a.ok = icmp eq i32 %a.frozen, %a.expected
  %b = call i32 @entropy_thunk_b(i32 %x)
  %b.frozen = freeze i32 %b
  %b.xor = xor i32 %x, 4660
  %b.add = add i32 %b.xor, 85
  %b.expected = sub i32 %b.add, 19
  %b.ok = icmp eq i32 %b.frozen, %b.expected
  %c = call i32 @entropy_thunk_c(i32 %x)
  %c.frozen = freeze i32 %c
  %c.add = add i32 %x, 9
  %c.mul = mul i32 %c.add, 5
  %c.expected = xor i32 %c.mul, 99
  %c.ok = icmp eq i32 %c.frozen, %c.expected
  %d = call i32 @entropy_thunk_d(i32 %x)
  %d.frozen = freeze i32 %d
  %d.sub = sub i32 %x, 41
  %d.xor = xor i32 %d.sub, 7
  %d.expected = add i32 %d.xor, 3
  %d.ok = icmp eq i32 %d.frozen, %d.expected
  %ab.ok = and i1 %a.ok, %b.ok
  %cd.ok = and i1 %c.ok, %d.ok
  %ok = and i1 %ab.ok, %cd.ok
  ret i1 %ok
}

define i32 @main() {
entry:
  br label %loop

loop:
  %index = phi i32 [ 0, %entry ], [ %next, %continue ]
  %input.ptr = getelementptr inbounds [16 x i32], ptr @thunk_inputs, i32 0, i32 %index
  %input = load i32, ptr %input.ptr
  %first = call i1 @check_thunks(i32 %input)
  %second = call i1 @check_thunks(i32 %input)
  %ok = and i1 %first, %second
  br i1 %ok, label %continue, label %fail

continue:
  %next = add nuw i32 %index, 1
  %more = icmp ult i32 %next, 16
  br i1 %more, label %loop, label %pass

pass:
  ret i32 0

fail:
  ret i32 1
}

; Do not pin any function to the pair-return or out-parameter alternative.
; IR-LABEL: define i32 @entropy_thunk_a(i32 %x)
; IR: alloca { i64, i64 }, {{.*}}addrspace(1)
; IR: call {{(void|\{ i64, i64 \})}} @__obf_entropy_thunk_
; IR-NOT: call {{.*}}@rt_core_ep
; IR: ret i32
; IR-LABEL: define i32 @entropy_thunk_b(i32 %x)
; IR: alloca { i64, i64 }, {{.*}}addrspace(1)
; IR: call {{(void|\{ i64, i64 \})}} @__obf_entropy_thunk_
; IR-NOT: call {{.*}}@rt_core_ep
; IR: ret i32
; IR-LABEL: define i32 @entropy_thunk_c(i32 %x)
; IR: alloca { i64, i64 }, {{.*}}addrspace(1)
; IR: call {{(void|\{ i64, i64 \})}} @__obf_entropy_thunk_
; IR-NOT: call {{.*}}@rt_core_ep
; IR: ret i32
; IR-LABEL: define i32 @entropy_thunk_d(i32 %x)
; IR: alloca { i64, i64 }, {{.*}}addrspace(1)
; IR: call {{(void|\{ i64, i64 \})}} @__obf_entropy_thunk_
; IR-NOT: call {{.*}}@rt_core_ep
; IR: ret i32
