; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-return-encode.yaml -passes=obf-vm -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-return-encode.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t
;
; Focused test for Entangled Return Values:
;   (a) VM function does NOT return plaintext — ret operand is encoded.
;   (b) Caller has retkey load + XOR decode.
;   (c) Plain icmp on the raw call result is gone; compare uses decoded value.
;   (d) Runtime correctness via %lli.

define i32 @encode_i32(i32 %x) {
entry:
  %r = add i32 %x, 100
  ret i32 %r
}

define i1 @encode_i1(i32 %x) {
entry:
  %cmp = icmp sgt i32 %x, 42
  ret i1 %cmp
}

define i64 @encode_i64(i64 %x) {
entry:
  %r = xor i64 %x, 1234567890123456789
  ret i64 %r
}

define i32 @main() {
entry:
  %v32 = call i32 @encode_i32(i32 5)
  %ok1 = icmp eq i32 %v32, 105

  %v1 = call i1 @encode_i1(i32 100)

  %v64 = call i64 @encode_i64(i64 0)
  %ok3 = icmp eq i64 %v64, 1234567890123456789

  %ok12 = and i1 %ok1, %v1
  %ok = and i1 %ok12, %ok3
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; --- Global declarations ---
; Retkey globals for all three integer-returning functions.
; CHECK-DAG: @__obf_entropy_anchor = external externally_initialized global i64, align 8
; CHECK-DAG: @[[PTR32:__obf_vm_ptrconst_[0-9A-F]+]] = private unnamed_addr constant ptr @__obf_vm_bc_encode_i32
; CHECK-DAG: @[[PTRI1:__obf_vm_ptrconst_[0-9A-F]+]] = private unnamed_addr constant ptr @__obf_vm_bc_encode_i1
; CHECK-DAG: @[[PTR64:__obf_vm_ptrconst_[0-9A-F]+]] = private unnamed_addr constant ptr @__obf_vm_bc_encode_i64
; CHECK-DAG: @__obf_vm_retkey_encode_i32 = private global i64 {{-?[0-9]+}}
; CHECK-DAG: @__obf_vm_retkey_encode_i1 = private global i64 {{-?[0-9]+}}
; CHECK-DAG: @__obf_vm_retkey_encode_i64 = private global i64 {{-?[0-9]+}}

; --- Wrappers ---
; CHECK-LABEL: define i32 @encode_i32(i32 %x)
; CHECK: %encode_i32.obf.wrapper.token = xor i64
; CHECK: call i32 @__obf_vm_impl_encode_i32(i32 %x, i64 %encode_i32.obf.wrapper.token)
; CHECK-LABEL: define i1 @encode_i1(i32 %x)
; CHECK: %encode_i1.obf.wrapper.token = xor i64
; CHECK: call i1 @__obf_vm_impl_encode_i1(i32 %x, i64 %encode_i1.obf.wrapper.token)
; CHECK-LABEL: define i64 @encode_i64(i64 %x)
; CHECK: %encode_i64.obf.wrapper.token = xor i64
; CHECK: call i64 @__obf_vm_impl_encode_i64(i64 %x, i64 %encode_i64.obf.wrapper.token)

; --- Caller-side decode ---
; CHECK-LABEL: define i32 @main()
; i32 decode:
; CHECK: %encode_i32.obf.call.token = xor i64
; CHECK: call i32 %encode_i32.obf.indirect(i32 5, i64 %encode_i32.obf.call.token)
; CHECK: %encode_i32.obf.retkey = load i64, ptr @__obf_vm_retkey_encode_i32
; CHECK: %encode_i32.obf.retkey.bound = {{(or|sub) i64}}
; CHECK: %encode_i32.obf.retkey.cast = trunc i64 %encode_i32.obf.retkey.bound to i32
; CHECK: %encode_i32.obf.retdec = {{(or|sub) i32}}
; CHECK: icmp eq i32 %encode_i32.obf.retdec, 105
; i1 decode:
; CHECK: %encode_i1.obf.call.token = xor i64
; CHECK: call i1 %encode_i1.obf.indirect(i32 100, i64 %encode_i1.obf.call.token)
; CHECK: %encode_i1.obf.retkey = load i64, ptr @__obf_vm_retkey_encode_i1
; CHECK: %encode_i1.obf.retkey.bound = {{(or|sub) i64}}
; CHECK: %encode_i1.obf.retkey.cast = trunc i64 %encode_i1.obf.retkey.bound to i1
; CHECK: %encode_i1.obf.retdec = {{(or|sub) i1}}
; i64 decode:
; CHECK: %encode_i64.obf.call.token = xor i64
; CHECK: call i64 %encode_i64.obf.indirect(i64 0, i64 %encode_i64.obf.call.token)
; CHECK: %encode_i64.obf.retkey = load i64, ptr @__obf_vm_retkey_encode_i64
; CHECK: %encode_i64.obf.retkey.bound = {{(or|sub) i64}}
; CHECK-NOT: %encode_i64.obf.retkey.cast
; CHECK: %encode_i64.obf.retdec = {{(or|sub) i64}}
; CHECK: icmp eq i64 %encode_i64.obf.retdec, 1234567890123456789

; --- VM body: no plaintext return ---
; CHECK-LABEL: define i32 @__obf_vm_impl_encode_i32(i32 %x, i64 %obf.hidden_token)
; CHECK: %obf.vm.ptr.const = load ptr, ptr @[[PTR32]]
; CHECK: %obf.vm.ret.state = load i64, ptr %obf.vm.state
; CHECK: %obf.vm.ret.retkey = load i64, ptr @__obf_vm_retkey_encode_i32
; CHECK: %obf.vm.ret.tokenkey = {{(or|sub) i64}}
; CHECK: %obf.vm.ret.key.cast = trunc i64 %obf.vm.ret.fullkey to i32
; CHECK: ret i32 %obf.vm.ret.encoded

; CHECK-LABEL: define i1 @__obf_vm_impl_encode_i1(i32 %x, i64 %obf.hidden_token)
; CHECK: %obf.vm.ptr.const = load ptr, ptr @[[PTRI1]]
; CHECK: %obf.vm.ret.state = load i64, ptr %obf.vm.state
; CHECK: %obf.vm.ret.retkey = load i64, ptr @__obf_vm_retkey_encode_i1
; CHECK: %obf.vm.ret.tokenkey = {{(or|sub) i64}}
; CHECK: %obf.vm.ret.key.cast = trunc i64 %obf.vm.ret.fullkey to i1
; CHECK: ret i1 %obf.vm.ret.encoded

; CHECK-LABEL: define i64 @__obf_vm_impl_encode_i64(i64 %x, i64 %obf.hidden_token)
; CHECK: %obf.vm.ptr.const = load ptr, ptr @[[PTR64]]
; CHECK: %obf.vm.ret.state = load i64, ptr %obf.vm.state
; CHECK: %obf.vm.ret.retkey = load i64, ptr @__obf_vm_retkey_encode_i64
; CHECK-NOT: %obf.vm.ret.key.trunc
; CHECK: ret i64 %obf.vm.ret.encoded
