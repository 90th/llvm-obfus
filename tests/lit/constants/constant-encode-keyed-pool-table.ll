; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/constant-encode-keyed-pool.yaml -passes=obf-constant-encode -S %s -o - | %FileCheck %s --check-prefix=TABLE
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/constant-encode-keyed-pool.yaml -passes=obf-constant-encode -S %s -o %t
; RUN: %lli %t

@lut = private constant [3 x i32] [i32 7, i32 11, i32 13], align 4

define i32 @table_user(i32 %idx) {
entry:
  %wide = sext i32 %idx to i64
  %slot = getelementptr inbounds [3 x i32], ptr @lut, i64 0, i64 %wide
  %value = load i32, ptr %slot, align 4
  ret i32 %value
}

define i32 @main() {
entry:
  %value = call i32 @table_user(i32 1)
  %ok = icmp eq i32 %value, 11
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; TABLE: @__obf_const_pool_
; TABLE: @__obf_const_desc_
; TABLE-LABEL: define i32 @table_user(i32 %idx) {
; TABLE: %obf.const.pool.base = call ptr @__obf_const_pool_decode_
; TABLE: %slot = getelementptr inbounds [3 x i32], ptr %obf.const.pool.base, i64 0, i64 %wide
; TABLE: %value = load i32, ptr %slot, align 4
; TABLE-LABEL: define internal ptr @__obf_const_pool_decode_
; TABLE: call ptr @rt_core_cpd1
; TABLE-NOT: %obf.const.mask =
