; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/function-outlining.yaml --obf-seed=777 -passes=obf-control-flatten -S %s -o %t.flat
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/function-outlining.yaml --obf-seed=1 -passes=obf-function-outline -S %t.flat -o %t.seed1.first
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/function-outlining.yaml --obf-seed=1 -passes=obf-function-outline -S %t.flat -o %t.seed1.second
; RUN: cmp %t.seed1.first %t.seed1.second
; RUN: %FileCheck %s < %t.seed1.first
; RUN: %opt -passes=verify -disable-output %t.seed1.first
; RUN: %lli %t.seed1.first
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/function-outlining.yaml --obf-seed=3 -passes=obf-function-outline -S %t.flat -o %t.seed3
; RUN: %python -c "import pathlib,re,sys; pattern=re.compile(r'switch i32 %obf\.outline\.route[0-9]*, label %[^\n]+ \[(.*?)\n  \]', re.S); parse=lambda path:[tuple(int(value) for value in re.findall(r'i32 (-?[0-9]+), label', body)) for body in pattern.findall(pathlib.Path(path).read_text(encoding='utf-8'))]; a=parse(sys.argv[1]); b=parse(sys.argv[2]); assert a and b, (a,b); assert all(len(tokens)>=2 and len(tokens)==len(set(tokens)) and all((token & 0x80000000)!=0 for token in tokens) for tokens in a+b), (a,b); assert a!=b, (a,b)" %t.seed1.first %t.seed3
; RUN: %opt -passes=verify -disable-output %t.seed3
; RUN: %lli %t.seed3

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
  %r0 = call i32 @shardy(i32 0)
  %ok0 = icmp eq i32 %r0, -2
  %r1 = call i32 @shardy(i32 5)
  %ok1 = icmp eq i32 %r1, 11
  %r2 = call i32 @shardy(i32 7)
  %ok2 = icmp eq i32 %r2, 7
  %r3 = call i32 @shardy(i32 10)
  %ok3 = icmp eq i32 %r3, 6
  %ok01 = and i1 %ok0, %ok1
  %ok23 = and i1 %ok2, %ok3
  %ok = and i1 %ok01, %ok23
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
; CHECK: switch i32 %obf.outline.route{{[0-9]*}}, label %{{[^ ]+}} [
; CHECK-NOT: i32 {{[0-9]+}}, label %
; CHECK: ]
; CHECK: define internal {{.*}} @__obf_shard_{{[0-9a-f]+}}
