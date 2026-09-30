; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/function-outlining.yaml -passes='obf-function-outline,verify' -S %s -o %t
; RUN: %FileCheck %s < %t
; RUN: %lli %t

@error_value = private global i8 0

define i32 @outline_error(ptr swifterror %error, i32 %x) {
obf.flat.dispatch:
  %zero = icmp eq i32 %x, 0
  br i1 %zero, label %handler0, label %obf.flat.dispatch.split
obf.flat.dispatch.split:
  %one = icmp eq i32 %x, 1
  br i1 %one, label %handler0, label %obf.flat.dispatch.left
obf.flat.dispatch.left:
  %two = icmp eq i32 %x, 2
  br i1 %two, label %handler1, label %default
handler0:
  store ptr null, ptr %error
  br label %default
handler1:
  store ptr @error_value, ptr %error
  br label %default
default:
  %r = phi i32 [ 3, %obf.flat.dispatch.left ], [ 1, %handler0 ], [ 2, %handler1 ]
  ret i32 %r
}

define i32 @main() {
  %error = alloca swifterror ptr
  store ptr @error_value, ptr %error
  %r0 = call i32 @outline_error(ptr swifterror %error, i32 0)
  %e0 = load ptr, ptr %error
  %ok0 = icmp eq ptr %e0, null
  %value0 = icmp eq i32 %r0, 1
  %r1 = call i32 @outline_error(ptr swifterror %error, i32 2)
  %e1 = load ptr, ptr %error
  %ok1 = icmp eq ptr %e1, @error_value
  %value1 = icmp eq i32 %r1, 2
  %a = and i1 %ok0, %value0
  %b = and i1 %ok1, %value1
  %ok = and i1 %a, %b
  %status = select i1 %ok, i32 0, i32 1
  ret i32 %status
}

; CHECK-LABEL: define i32 @outline_error(
; CHECK: call {{.*}} %obf.shard.indirect({{.*}}ptr swifterror %error
; CHECK-LABEL: define internal {{.*}} @__obf_shard_{{[0-9a-f]+}}(
; CHECK-SAME: ptr swifterror
