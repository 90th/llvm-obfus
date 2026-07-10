; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-lazy.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o - | %FileCheck %s --check-prefix=IR
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-lazy.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-lazy.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: set -- $(%python -c "import pathlib,re; text = pathlib.Path(r'%t').read_text(encoding='utf-8'); syms = re.findall(r'@(__obf_string_desc_[A-Za-z$._0-9]+) = ', text); assert len(syms) == 2, syms; print(syms[0], syms[1])") && %python %S/../Inputs/tamper_string_auth_ir.py %t "$1" nested-target destination "$2"
; RUN: not --crash %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-lazy.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: set -- $(%python -c "import pathlib,re; text = pathlib.Path(r'%t').read_text(encoding='utf-8'); syms = re.findall(r'@(__obf_string_desc_[A-Za-z$._0-9]+) = ', text); assert len(syms) == 2, syms; print(syms[0], syms[1])") && %python %S/../Inputs/tamper_string_auth_ir.py %t "$1" nested-target ciphertext "$2"
; RUN: not --crash %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-lazy.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: set -- $(%python -c "import pathlib,re; text = pathlib.Path(r'%t').read_text(encoding='utf-8'); syms = re.findall(r'@(__obf_string_desc_[A-Za-z$._0-9]+) = ', text); assert len(syms) == 2, syms; print(syms[0], syms[1])") && %python %S/../Inputs/tamper_string_auth_ir.py %t "$1" nested-target build-key "$2"
; RUN: not --crash %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-lazy.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: set -- $(%python -c "import pathlib,re; text = pathlib.Path(r'%t').read_text(encoding='utf-8'); syms = re.findall(r'@(__obf_string_desc_[A-Za-z$._0-9]+) = ', text); assert len(syms) == 2, syms; print(syms[0], syms[1])") && %python %S/../Inputs/tamper_string_auth_ir.py %t "$1" state-clone
; RUN: not --crash %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-lazy.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: set -- $(%python -c "import pathlib,re; text = pathlib.Path(r'%t').read_text(encoding='utf-8'); syms = re.findall(r'@(__obf_string_desc_[A-Za-z$._0-9]+) = ', text); assert len(syms) == 2, syms; print(syms[0], syms[1])") && %python %S/../Inputs/tamper_string_auth_ir.py %t "$1" descriptor-capacity destination
; RUN: not --crash %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-lazy.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: set -- $(%python -c "import pathlib,re; text = pathlib.Path(r'%t').read_text(encoding='utf-8'); syms = re.findall(r'@(__obf_string_desc_[A-Za-z$._0-9]+) = ', text); assert len(syms) == 2, syms; print(syms[0], syms[1])") && %python %S/../Inputs/tamper_string_auth_ir.py %t "$1" topology-callsite "$2"
; RUN: not --crash %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-lazy.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: set -- $(%python -c "import pathlib,re; text = pathlib.Path(r'%t').read_text(encoding='utf-8'); syms = re.findall(r'@(__obf_string_desc_[A-Za-z$._0-9]+) = ', text); assert len(syms) == 2, syms; print(syms[0], syms[1])") && %python %S/../Inputs/tamper_string_auth_ir.py %t "$1" forged-decoded
; RUN: %python %S/../Inputs/assert_trap_within.py %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-lazy.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: set -- $(%python -c "import pathlib,re; text = pathlib.Path(r'%t').read_text(encoding='utf-8'); syms = re.findall(r'@(__obf_string_desc_[A-Za-z$._0-9]+) = ', text); assert len(syms) == 2, syms; print(syms[0], syms[1])") && %python %S/../Inputs/tamper_string_auth_ir.py %t "$1" forged-decoding
; RUN: %python %S/../Inputs/assert_trap_within.py %lli %t

@.alpha = private unnamed_addr constant [7 x i8] c"alphaa\00"
@.alpine = private unnamed_addr constant [7 x i8] c"alpine\00"

define i32 @first_char(ptr %p) {
entry:
  %first = load i8, ptr %p
  %is_a = icmp eq i8 %first, 97
  %code = select i1 %is_a, i32 0, i32 1
  ret i32 %code
}

define i32 @main() {
entry:
  %left = call i32 @first_char(ptr @.alpha)
  %right = call i32 @first_char(ptr @.alpine)
  %sum = add i32 %left, %right
  ret i32 %sum
}

; IR: @__obf_string_state_ref_
; IR: @__obf_string_desc_
; IR: @__obf_string_topology_
; IR: define internal ptr @__obf_family_auth_v3(ptr %desc, i32 %cfg_state, i32 %expected_state, i64 %trusted_length, i64 %trusted_binding, ptr %trusted_topology)
; IR: call ptr @rt_core_sd3(ptr %desc, i64 %trusted_length, i64 %trusted_binding, ptr %trusted_topology)
