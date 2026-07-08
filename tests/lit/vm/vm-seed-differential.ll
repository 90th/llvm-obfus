; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-seed-differential.yaml --obf-seed=111 -passes=obf-vm -S %s -o %t.111.ll
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-seed-differential.yaml --obf-seed=111 -passes=obf-vm -S %s -o %t.111.repeat.ll
; RUN: cmp %t.111.ll %t.111.repeat.ll
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-seed-differential.yaml --obf-seed=222 -passes=obf-vm -S %s -o %t.222.ll
; RUN: %lli %t.111.ll
; RUN: %lli %t.222.ll
; RUN: %python -c "import pathlib,re,sys; a=pathlib.Path(sys.argv[1]).read_text(); b=pathlib.Path(sys.argv[2]).read_text(); pats=[r'@__obf_vm_key_fold_value = private global i\d+ (-?\d+)', r'@__obf_vm_retkey_fold_value = private global i64 (-?\d+)']; av=[re.search(p,a).group(1) for p in pats]; bv=[re.search(p,b).group(1) for p in pats]; assert av[0] != bv[0], (av,bv); assert av[1] != bv[1], (av,bv)" %t.111.ll %t.222.ll

define i32 @fold_value(i32 %value) {
entry:
  %xor = xor i32 %value, 4660
  %add = add nsw i32 %xor, 85
  ret i32 %add
}

define i32 @main() {
entry:
  %result = call i32 @fold_value(i32 0)
  %ok = icmp eq i32 %result, 4745
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}
