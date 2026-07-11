; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/opaque-preds.yaml -passes=obf-opaque-preds -S %s -o %t
; RUN: %FileCheck %s < %t
; RUN: %opt -passes=verify -disable-output %t
; RUN: %python -c "import re,sys; s=open(sys.argv[1]).read(); b=re.search(r'define i32 @check.*?^}',s,re.S|re.M).group(); branches=re.findall(r'br i1 .*?, label %([A-Za-z0-9_.]+), label %([A-Za-z0-9_.]+), !prof !([0-9]+)',b); assert len(branches)==2, branches; nodes={n:(int(a),int(c)) for n,a,c in re.findall(r'!([0-9]+) = !\{!\"branch_weights\", i32 ([0-9]+), i32 ([0-9]+)\}',s)}; expected=[(('positive','no'),{'positive':90,'no':10}),(('yes','high'),{'yes':80,'high':20})]; direct=reversed_count=0; exec('for (a,b,n),(pair,want) in zip(branches,expected):\n assert {a,b}==set(pair),(a,b,pair)\n direct += (a,b)==pair\n reversed_count += (a,b)==pair[::-1]\n weights=nodes[n]\n assert {a:weights[0],b:weights[1]}==want,(a,b,weights,want)'); assert (direct,reversed_count)==(1,1),(direct,reversed_count)" %t
; RUN: %lli %t

define i32 @check(i32 %x) {
entry:
  %gt = icmp sgt i32 %x, 3
  br i1 %gt, label %positive, label %no, !prof !0

positive:
  %lt = icmp slt i32 %x, 10
  br i1 %lt, label %yes, label %high, !prof !1

no:
  ret i32 0

yes:
  ret i32 1

high:
  ret i32 2
}

define i32 @main() {
entry:
  %zero = call i32 @check(i32 0)
  %zero.ok = icmp eq i32 %zero, 0
  %one = call i32 @check(i32 9)
  %one.ok = icmp eq i32 %one, 1
  %two = call i32 @check(i32 20)
  %two.ok = icmp eq i32 %two, 2
  %first.ok = and i1 %zero.ok, %one.ok
  %all.ok = and i1 %first.ok, %two.ok
  %ret = select i1 %all.ok, i32 0, i32 1
  ret i32 %ret
}

!0 = !{!"branch_weights", i32 90, i32 10}
!1 = !{!"branch_weights", i32 80, i32 20}

; CHECK-DAG: @rt_core_ea = external externally_initialized global i64, align 8
; CHECK-LABEL: define i32 @check
; CHECK: %obf.entropy.cache = alloca { i64, i64 }, align 8
; CHECK: call {{(void|\{ i64, i64 \})}} @__obf_entropy_thunk_
; CHECK: %obf.opaque.pair = load { i64, i64 }, ptr %obf.entropy.cache, align 8
; CHECK: %obf.opaque.direct = extractvalue { i64, i64 } %obf.opaque.pair, 0
; CHECK: %obf.opaque.indirect = extractvalue { i64, i64 } %obf.opaque.pair, 1
; CHECK: %obf.opaque.entropy.mix{{.*}} = {{.*}}
; CHECK: %obf.opaque.seed =
; CHECK: %obf.opaque.seed.freeze = freeze i64 %obf.opaque.seed
; CHECK-DAG: %obf.opaque.guard.true{{[0-9]*}} = icmp eq i64
; CHECK-DAG: %obf.opaque.guard.true{{[0-9]*}} = icmp eq i64
; CHECK-DAG: %obf.opaque.guard.false.source{{[0-9]*}} = icmp eq i64
; CHECK-DAG: %obf.opaque.guard.false.source{{[0-9]*}} = icmp eq i64
; CHECK-DAG: %obf.opaque.guard.false{{[0-9]*}} = xor i1 %obf.opaque.guard.false.source
; CHECK-DAG: %obf.opaque.guard.false{{[0-9]*}} = xor i1 %obf.opaque.guard.false.source
; CHECK-DAG: %obf.opaque.input{{[0-9]*}} = freeze i1
; CHECK-DAG: %obf.opaque.input{{[0-9]*}} = freeze i1
; CHECK-DAG: %obf.opaque.input.inverted = xor i1 %obf.opaque.input
; CHECK-DAG: %obf.opaque.mux.select = select i1
; CHECK-DAG: %obf.opaque.mux.and_or = or i1
