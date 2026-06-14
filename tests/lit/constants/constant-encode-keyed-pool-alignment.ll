; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/constant-encode-keyed-pool-alignment.yaml -passes=obf-constant-encode -S %s -o - | %FileCheck %s --check-prefix=IR
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/constant-encode-keyed-pool-alignment.yaml -passes=obf-constant-encode -S %s -o %t
; RUN: %lli %t

define i32 @mixed_widths(i64 %x) {
entry:
  %a = add i8 17, 61
  %b = add i64 %x, 1311768467463790320
  %c = xor i32 305419896, 252645135
  %d = add i16 4660, 257
  %a.ext = zext i8 %a to i64
  %c.ext = zext i32 %c to i64
  %d.ext = zext i16 %d to i64
  %sum0 = add i64 %b, %a.ext
  %sum1 = add i64 %sum0, %c.ext
  %sum2 = add i64 %sum1, %d.ext
  %ok = icmp eq i64 %sum2, 1311768467954224106
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

define i32 @main() {
entry:
  %ret = call i32 @mixed_widths(i64 0)
  ret i32 %ret
}

; IR: @__obf_const_buf_{{[A-Za-z0-9_]+}} = internal global [{{[0-9]+}} x i8] zeroinitializer, align {{[48]}}
; IR-LABEL: define i32 @mixed_widths(i64 %x) {
; IR: load i8, ptr %obf.const.pool.ptr{{[0-9]*}}, align 1
; IR: load i64, ptr %obf.const.pool.ptr{{[0-9]*}}, align {{[48]}}
; IR: load i32, ptr %obf.const.pool.ptr{{[0-9]*}}, align 4
; IR: load i16, ptr %obf.const.pool.ptr{{[0-9]*}}, align 2
