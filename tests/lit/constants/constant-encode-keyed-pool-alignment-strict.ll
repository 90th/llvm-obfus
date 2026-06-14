; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/constant-encode-keyed-pool-alignment.yaml -passes=obf-constant-encode -S %s -o - | %FileCheck %s --check-prefix=STRICT
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/constant-encode-keyed-pool-alignment.yaml -passes=obf-constant-encode -S %s -o %t
; RUN: %lli %t

target datalayout = "e-m:e-p:64:64-i16:16:16-i32:32:32-i64:64:64-n8:16:32:64-S128"

define i32 @strict_mix(i64 %x) {
entry:
  %a = add i8 5, 9
  %b = add i64 %x, 72623859790382856
  %c = xor i32 324478056, 610800471
  %d = add i16 8738, 2571
  %a.ext = zext i8 %a to i64
  %c.ext = zext i32 %c to i64
  %d.ext = zext i16 %d to i64
  %sum0 = add i64 %b, %a.ext
  %sum1 = add i64 %sum0, %c.ext
  %sum2 = add i64 %sum1, %d.ext
  %ok = icmp eq i64 %sum2, 72623860717283970
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

define i32 @main() {
entry:
  %ret = call i32 @strict_mix(i64 0)
  ret i32 %ret
}

; STRICT: @__obf_const_buf_{{[A-Za-z0-9_]+}} = internal global [{{[0-9]+}} x i8] zeroinitializer, align 8
; STRICT-LABEL: define i32 @strict_mix(i64 %x) {
; STRICT: load i8, ptr %obf.const.pool.ptr{{[0-9]*}}, align 1
; STRICT: load i64, ptr %obf.const.pool.ptr{{[0-9]*}}, align 8
; STRICT: load i32, ptr %obf.const.pool.ptr{{[0-9]*}}, align 4
; STRICT: load i16, ptr %obf.const.pool.ptr{{[0-9]*}}, align 2
