; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-ctor.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o - | %FileCheck %s --check-prefix=IR
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-ctor.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-ctor.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: set -- $(%python -c "import pathlib,re; text = pathlib.Path(r'%t').read_text(encoding='utf-8'); syms = re.findall(r'@(__obf_string_desc_[A-Za-z$._0-9]+) = ', text); assert len(syms) == 2, syms; print(syms[0], syms[1])") && %python %S/../Inputs/tamper_string_auth_ir.py %t "$1" nested-target destination "$2"
; RUN: not --crash %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-ctor.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: set -- $(%python -c "import pathlib,re; text = pathlib.Path(r'%t').read_text(encoding='utf-8'); syms = re.findall(r'@(__obf_string_desc_[A-Za-z$._0-9]+) = ', text); assert len(syms) == 2, syms; print(syms[0], syms[1])") && %python %S/../Inputs/tamper_string_auth_ir.py %t "$1" nested-target ciphertext "$2"
; RUN: not --crash %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-ctor.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: set -- $(%python -c "import pathlib,re; text = pathlib.Path(r'%t').read_text(encoding='utf-8'); syms = re.findall(r'@(__obf_string_desc_[A-Za-z$._0-9]+) = ', text); assert len(syms) == 2, syms; print(syms[0], syms[1])") && %python %S/../Inputs/tamper_string_auth_ir.py %t "$1" nested-target build-key "$2"
; RUN: not --crash %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-ctor.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: set -- $(%python -c "import pathlib,re; text = pathlib.Path(r'%t').read_text(encoding='utf-8'); syms = re.findall(r'@(__obf_string_desc_[A-Za-z$._0-9]+) = ', text); assert len(syms) == 2, syms; print(syms[0], syms[1])") && %python %S/../Inputs/tamper_string_auth_ir.py %t "$1" state-clone
; RUN: not --crash %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-ctor.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: set -- $(%python -c "import pathlib,re; text = pathlib.Path(r'%t').read_text(encoding='utf-8'); syms = re.findall(r'@(__obf_string_desc_[A-Za-z$._0-9]+) = ', text); assert len(syms) == 2, syms; print(syms[0], syms[1])") && %python %S/../Inputs/tamper_string_auth_ir.py %t "$1" descriptor-capacity destination
; RUN: not --crash %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-ctor.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: set -- $(%python -c "import pathlib,re; text = pathlib.Path(r'%t').read_text(encoding='utf-8'); syms = re.findall(r'@(__obf_string_desc_[A-Za-z$._0-9]+) = ', text); assert len(syms) == 2, syms; print(syms[0], syms[1])") && %python %S/../Inputs/tamper_string_auth_ir.py %t "$1" topology-callsite "$2"
; RUN: not --crash %lli %t

@.alpha = private unnamed_addr constant [7 x i8] c"alphaa\00"
@.bravo = private unnamed_addr constant [7 x i8] c"bravoo\00"

define i32 @main() {
entry:
  %a = load i8, ptr @.alpha
  %b = load i8, ptr @.bravo
  %is_a = icmp eq i8 %a, 97
  %is_b = icmp eq i8 %b, 98
  %both = and i1 %is_a, %is_b
  %ret = select i1 %both, i32 0, i32 1
  ret i32 %ret
}

; IR: @__obf_string_state_ref_
; IR: @__obf_string_desc_
; IR: @__obf_string_topology_
; IR: @llvm.global_ctors = appending global
; IR: call ptr @rt_core_sd3(
