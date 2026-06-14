; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/function-outlining.yaml -passes='obf-control-flatten,obf-function-outline' -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/function-outlining.yaml -passes='obf-control-flatten,obf-function-outline' -S %s -o %t
; RUN: %lli %t

define i32 @shardy(i32 %x) {
entry:
  %acc = alloca i32, align 4
  store i32 %x, ptr %acc, align 4
  %c0 = icmp sgt i32 %x, 0
  br i1 %c0, label %a, label %b

a:
  %a0 = load i32, ptr %acc, align 4
  %a1 = add i32 %a0, 1
  store i32 %a1, ptr %acc, align 4
  br label %merge1

b:
  %b0 = load i32, ptr %acc, align 4
  %b1 = sub i32 %b0, 1
  store i32 %b1, ptr %acc, align 4
  br label %merge1

merge1:
  %m1 = load i32, ptr %acc, align 4
  %c1 = icmp slt i32 %m1, 10
  br i1 %c1, label %c, label %d

c:
  %c2 = add i32 %m1, 2
  store i32 %c2, ptr %acc, align 4
  br label %merge2

d:
  %d2 = sub i32 %m1, 2
  store i32 %d2, ptr %acc, align 4
  br label %merge2

merge2:
  %m2 = load i32, ptr %acc, align 4
  %c2cmp = icmp eq i32 %m2, 8
  br i1 %c2cmp, label %e, label %f

e:
  %e3 = add i32 %m2, 3
  store i32 %e3, ptr %acc, align 4
  br label %merge3

f:
  %f3 = sub i32 %m2, 3
  store i32 %f3, ptr %acc, align 4
  br label %merge3

merge3:
  %m3 = load i32, ptr %acc, align 4
  ret i32 %m3
}

define i32 @main() {
entry:
  %r = call i32 @shardy(i32 7)
  %ok = icmp eq i32 %r, 7
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK-DAG: @rt_core_ea = external externally_initialized global i64, align 8
; CHECK-LABEL: define i32 @shardy(i32 %x)
; CHECK: obf.flat.dispatch:
; CHECK: %obf.shard.addr.base = ptrtoint ptr @__obf_shard_{{[0-9a-f]+}} to i64
; CHECK: %obf.shard.indirect = inttoptr i64 %obf.shard.addr to ptr
; CHECK: call {{.*}} %obf.shard.indirect
; CHECK: define internal {{.*}} @__obf_shard_{{[0-9a-f]+}}
; CHECK: define internal {{.*}} @__obf_shard_{{[0-9a-f]+}}
