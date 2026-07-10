; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/constant-encode-keyed-pool.yaml -passes=obf-constant-encode -S %s -o - | %FileCheck %s --check-prefix=SCALAR
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/constant-encode-keyed-pool.yaml -passes=obf-constant-encode -S %s -o %t
; RUN: %lli %t
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"

@input = private constant i64 5
@expected = private constant i64 25


define i64 @repeated(i64 %x) {
entry:
  %wide.add = add i64 %x, 4886718345
  %wide.restored = sub i64 %wide.add, 4886718345
  %narrow = trunc i64 %x to i32
  %narrow.add = add i32 %narrow, 31337
  %narrow.restored = sub i32 %narrow.add, 31337
  %narrow.ext = zext i32 %narrow.restored to i64
  %product = mul i64 %wide.restored, %narrow.ext
  ret i64 %product
}

define i32 @main() {
entry:
  %input = load i64, ptr @input, align 8
  %value = call i64 @repeated(i64 %input)
  %expected = load i64, ptr @expected, align 8
  %ok = icmp eq i64 %value, %expected
  %bad = xor i1 %ok, true
  %ret = zext i1 %bad to i32
  ret i32 %ret
}

; SCALAR: @[[POOL8:__obf_const_pool_[^ ]+]] = internal constant [8 x i8]
; SCALAR: @[[DEST8:__obf_const_destination_ref_[^ ]+]] = internal constant
; SCALAR: @[[DESC8:__obf_const_desc_[^ ]+]] = internal constant { i32, i32, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, [16 x i8], [16 x i8], ptr, ptr, ptr, ptr } { i32 3, i32 1, i64 8,
; SCALAR: @__obf_const_topology_
; SCALAR: @[[POOL4:__obf_const_pool_[^ ]+]] = internal constant [4 x i8]
; SCALAR: @[[DEST4:__obf_const_destination_ref_[^ ]+]] = internal constant
; SCALAR: @[[DESC4:__obf_const_desc_[^ ]+]] = internal constant { i32, i32, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, [16 x i8], [16 x i8], ptr, ptr, ptr, ptr } { i32 3, i32 1, i64 4,
; SCALAR: @__obf_const_topology_
; SCALAR-NOT: @__obf_const_pool_{{.*}} = internal constant
; SCALAR-NOT: @__obf_const_destination_ref_{{.*}} = internal constant
; SCALAR-NOT: @__obf_const_desc_{{.*}} = internal constant
; SCALAR-LABEL: define i64 @repeated(i64 %x) {
; SCALAR: %obf.const.pool.ptr = getelementptr inbounds i8, ptr %obf.const.pool.base, i64 0
; SCALAR: %obf.const.pool.load = load i64, ptr %obf.const.pool.ptr, align 8
; SCALAR: %obf.const.pool.ptr2 = getelementptr inbounds i8, ptr %obf.const.pool.base1, i64 0
; SCALAR: %obf.const.pool.load3 = load i64, ptr %obf.const.pool.ptr2, align 8
; SCALAR: %obf.const.pool.ptr5 = getelementptr inbounds i8, ptr %obf.const.pool.base4, i64 0
; SCALAR: %obf.const.pool.load6 = load i32, ptr %obf.const.pool.ptr5, align 4
; SCALAR: %obf.const.pool.ptr8 = getelementptr inbounds i8, ptr %obf.const.pool.base7, i64 0
; SCALAR: %obf.const.pool.load9 = load i32, ptr %obf.const.pool.ptr8, align 4
; SCALAR-LABEL: define internal ptr @__obf_const_pool_decode_
; SCALAR: call ptr @rt_core_cpd3(ptr @[[DESC8]], i64 8, i64 {{-?[0-9]+}}, ptr @__obf_const_topology_{{.*}})
; SCALAR-LABEL: define internal ptr @__obf_const_pool_decode_
; SCALAR: call ptr @rt_core_cpd3(ptr @[[DESC4]], i64 4, i64 {{-?[0-9]+}}, ptr @__obf_const_topology_{{.*}})
; SCALAR-NOT: define internal ptr @__obf_const_pool_decode_
; SCALAR-NOT: call ptr @rt_core_cpd3({{.*}}i64 12,
; SCALAR-NOT: %obf.const.mask =
