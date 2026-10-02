; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/function-outlining.yaml -passes=obf-function-outline,verify -S %s -o %t
; RUN: %lli %t
; RUN: %opt -passes='default<O2>,verify' -S %t -o %t.optimized
; RUN: %lli %t.optimized


define i32 @shard_attr_target(i32 %bits, i32 %salt) #0 {
obf.flat.dispatch:
  %value = bitcast i32 %bits to float
  %half = fmul float %value, 5.000000e-01
  %base = bitcast float %half to i32
  %cmp0 = icmp eq i32 %salt, 0
  br i1 %cmp0, label %handler0, label %obf.flat.dispatch.split

obf.flat.dispatch.split:
  %cmp1 = icmp eq i32 %salt, 1
  br i1 %cmp1, label %handler0, label %obf.flat.dispatch.left

obf.flat.dispatch.left:
  %cmp2 = icmp eq i32 %salt, 2
  br i1 %cmp2, label %handler1, label %default

handler0:
  %a0 = add i32 %base, 13
  %a1 = sub i32 %a0, 13
  br label %default

handler1:
  %b0 = xor i32 %base, 4660
  %b1 = xor i32 %b0, 4660
  br label %default

default:
  %r = phi i32 [ %base, %obf.flat.dispatch.left ], [ %a1, %handler0 ], [ %b1, %handler1 ]
  ret i32 %r
}

define i32 @main() {
entry:
  %a = call i32 @shard_attr_target(i32 1082130432, i32 0)
  %b = call i32 @shard_attr_target(i32 1082130432, i32 1)
  %c = call i32 @shard_attr_target(i32 1082130432, i32 2)
  %d = call i32 @shard_attr_target(i32 1082130432, i32 3)
  %negative.zero = call i32 @shard_attr_target(i32 -2147483648, i32 2)
  %ok0 = icmp eq i32 %a, 1073741824
  %ok1 = icmp eq i32 %b, 1073741824
  %ok2 = icmp eq i32 %c, 1073741824
  %ok3 = icmp eq i32 %d, 1073741824
  %negative.zero.ok = icmp eq i32 %negative.zero, -2147483648
  %ab = and i1 %ok0, %ok1
  %cd = and i1 %ok2, %ok3
  %normal.ok = and i1 %ab, %cd
  %ok = and i1 %normal.ok, %negative.zero.ok
  %result = select i1 %ok, i32 0, i32 1
  ret i32 %result
}

attributes #0 = { mustprogress nofree nosync willreturn memory(none) null_pointer_is_valid strictfp "denormal-fp-math"="preserve-sign,preserve-sign" "denormal-fp-math-f32"="preserve-sign" "target-cpu"="x86-64" "target-features"="+sse2" "tune-cpu"="generic" }
