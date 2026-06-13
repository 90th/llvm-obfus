; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/constant-encode-keyed-pool-i12-i20.yaml -passes=obf-constant-encode -S %s -o - | %FileCheck %s --check-prefix=IR
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/constant-encode-keyed-pool-i12-i20.yaml -passes=obf-constant-encode -S %s -o %t
; RUN: %lli %t

target datalayout = "e-m:e-p:64:64-i12:16:16-i20:8:8-i24:8:8-i64:64:64-n8:16:32:64-S128"

define i32 @i12_values() {
entry:
  %a = add i12 291, 1110
  %b = xor i12 %a, 1929
  %ok = icmp eq i12 %b, 752
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

define i32 @i20_values() {
entry:
  %a = add i20 344865, 74565
  %b = xor i20 %a, 43981
  %ok = icmp eq i20 %b, 445867
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

define i32 @i24_values() {
entry:
  %a = add i24 1193046, 65296
  %b = xor i24 %a, 986895
  %ok = icmp eq i24 %b, 1850473
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

define i32 @main() {
entry:
  %i12 = call i32 @i12_values()
  %i20 = call i32 @i20_values()
  %i24 = call i32 @i24_values()
  %i12.ok = icmp eq i32 %i12, 0
  %i20.ok = icmp eq i32 %i20, 0
  %i24.ok = icmp eq i32 %i24, 0
  %all12 = and i1 %i12.ok, %i20.ok
  %all = and i1 %all12, %i24.ok
  %ret = select i1 %all, i32 0, i32 1
  ret i32 %ret
}

; IR: @__obf_const_pool_
; IR-LABEL: define i32 @i12_values() {
; IR: %obf.const.pool.load = load i12, ptr %obf.const.pool.ptr
; IR-LABEL: define i32 @i20_values() {
; IR: %obf.const.pool.load = load i20, ptr %obf.const.pool.ptr
; IR-LABEL: define i32 @i24_values() {
; IR: %obf.const.pool.load = load i24, ptr %obf.const.pool.ptr
