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

@lut_a = private constant [3 x i32] [i32 7, i32 11, i32 13], align 4
@lut_b = private constant [3 x i32] [i32 17, i32 19, i32 23], align 4

define i32 @table_user(i32 %idx) {
entry:
  %wide = sext i32 %idx to i64
  %slot_a = getelementptr inbounds [3 x i32], ptr @lut_a, i64 0, i64 %wide
  %value_a = load i32, ptr %slot_a, align 4
  %slot_b = getelementptr inbounds [3 x i32], ptr @lut_b, i64 0, i64 %wide
  %value_b = load i32, ptr %slot_b, align 4
  %sum = add i32 %value_a, %value_b
  ret i32 %sum
}

define i32 @main() {
entry:
  %sum = call i32 @table_user(i32 1)
  %ok = icmp eq i32 %sum, 30
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; IR: @__obf_const_state_ref_
; IR: @__obf_const_desc_
; IR: @__obf_const_topology_
; IR: call ptr @rt_core_cpd3(
