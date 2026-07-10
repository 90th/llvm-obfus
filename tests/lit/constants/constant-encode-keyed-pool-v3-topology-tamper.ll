; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/constant-encode-keyed-pool.yaml -passes=obf-constant-encode -S %s -o - | %FileCheck %s --check-prefix=IR
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/constant-encode-keyed-pool.yaml -passes=obf-constant-encode -S %s -o %t
; RUN: %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/constant-encode-keyed-pool.yaml -passes=obf-constant-encode -S %s -o %t
; RUN: set -- $(%python -c "import pathlib,re; text = pathlib.Path(r'%t').read_text(encoding='utf-8'); syms = re.findall(r'@(__obf_const_desc_[A-Za-z$._0-9]+) = ', text); assert len(syms) == 2, syms; print(syms[0], syms[1])") && %python %S/../Inputs/tamper_string_auth_ir.py %t "$1" nested-target destination "$2"
; RUN: not --crash %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/constant-encode-keyed-pool.yaml -passes=obf-constant-encode -S %s -o %t
; RUN: set -- $(%python -c "import pathlib,re; text = pathlib.Path(r'%t').read_text(encoding='utf-8'); syms = re.findall(r'@(__obf_const_desc_[A-Za-z$._0-9]+) = ', text); assert len(syms) == 2, syms; print(syms[0], syms[1])") && %python %S/../Inputs/tamper_string_auth_ir.py %t "$1" nested-target ciphertext "$2"
; RUN: not --crash %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/constant-encode-keyed-pool.yaml -passes=obf-constant-encode -S %s -o %t
; RUN: set -- $(%python -c "import pathlib,re; text = pathlib.Path(r'%t').read_text(encoding='utf-8'); syms = re.findall(r'@(__obf_const_desc_[A-Za-z$._0-9]+) = ', text); assert len(syms) == 2, syms; print(syms[0], syms[1])") && %python %S/../Inputs/tamper_string_auth_ir.py %t "$1" nested-target build-key "$2"
; RUN: not --crash %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/constant-encode-keyed-pool.yaml -passes=obf-constant-encode -S %s -o %t
; RUN: set -- $(%python -c "import pathlib,re; text = pathlib.Path(r'%t').read_text(encoding='utf-8'); syms = re.findall(r'@(__obf_const_desc_[A-Za-z$._0-9]+) = ', text); assert len(syms) == 2, syms; print(syms[0], syms[1])") && %python %S/../Inputs/tamper_string_auth_ir.py %t "$1" state-clone
; RUN: not --crash %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/constant-encode-keyed-pool.yaml -passes=obf-constant-encode -S %s -o %t
; RUN: set -- $(%python -c "import pathlib,re; text = pathlib.Path(r'%t').read_text(encoding='utf-8'); syms = re.findall(r'@(__obf_const_desc_[A-Za-z$._0-9]+) = ', text); assert len(syms) == 2, syms; print(syms[0], syms[1])") && %python %S/../Inputs/tamper_string_auth_ir.py %t "$1" descriptor-capacity destination
; RUN: not --crash %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/constant-encode-keyed-pool.yaml -passes=obf-constant-encode -S %s -o %t
; RUN: set -- $(%python -c "import pathlib,re; text = pathlib.Path(r'%t').read_text(encoding='utf-8'); syms = re.findall(r'@(__obf_const_desc_[A-Za-z$._0-9]+) = ', text); assert len(syms) == 2, syms; print(syms[0], syms[1])") && %python %S/../Inputs/tamper_string_auth_ir.py %t "$1" topology-callsite "$2"
; RUN: not --crash %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/constant-encode-keyed-pool.yaml -passes=obf-constant-encode -S %s -o %t
; RUN: set -- $(%python -c "import pathlib,re; text = pathlib.Path(r'%t').read_text(encoding='utf-8'); syms = re.findall(r'@(__obf_const_desc_[A-Za-z$._0-9]+) = ', text); assert len(syms) == 2, syms; print(syms[0], syms[1])") && %python %S/../Inputs/tamper_string_auth_ir.py %t "$1" forged-decoded
; RUN: %python %S/../Inputs/assert_trap_within.py %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/constant-encode-keyed-pool.yaml -passes=obf-constant-encode -S %s -o %t
; RUN: set -- $(%python -c "import pathlib,re; text = pathlib.Path(r'%t').read_text(encoding='utf-8'); syms = re.findall(r'@(__obf_const_desc_[A-Za-z$._0-9]+) = ', text); assert len(syms) == 2, syms; print(syms[0], syms[1])") && %python %S/../Inputs/tamper_string_auth_ir.py %t "$1" forged-decoding
; RUN: %python %S/../Inputs/assert_trap_within.py %lli %t

define i32 @repeated(i32 %x) {
entry:
  %a = add i32 %x, 31337
  %b = xor i32 %a, 31337
  %c = add i32 %b, 31337
  ret i32 %c
}

define i32 @main() {
entry:
  %value = call i32 @repeated(i32 5)
  %ok = icmp eq i32 %value, 31344
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; IR: @__obf_const_state_ref_
; IR: @__obf_const_desc_
; IR: @__obf_const_topology_
; IR: define internal ptr @__obf_const_pool_decode_
; IR: call ptr @rt_core_cpd3(
