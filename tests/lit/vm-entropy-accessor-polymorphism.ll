; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-entropy-accessor-polymorphism.yaml -passes=obf-vm -S %s -o - | %FileCheck %s --check-prefix=IR
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-entropy-accessor-polymorphism.yaml -passes=obf-vm -S %s -o - | %opt -passes=verify -disable-output
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-entropy-accessor-polymorphism.yaml -passes=obf-vm -S %s -o %t.fixed
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-entropy-accessor-polymorphism.yaml -passes=obf-vm -S %s -o %t.fixed2
; RUN: %python -c "import pathlib,sys; sys.exit(0 if pathlib.Path(sys.argv[1]).read_text()==pathlib.Path(sys.argv[2]).read_text() else 1)" %t.fixed %t.fixed2
; RUN: %python -c "import pathlib,sys; text=pathlib.Path(sys.argv[1]).read_text(); required=['@rt_core_ep0()', '@rt_core_ep1()', '@rt_core_ep2()', '@rt_core_ep3()', '@rt_core_ep4()']; sys.exit(0 if all(item in text for item in required) else 1)" %t.fixed
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-entropy-accessor-polymorphism.yaml --obf-seed=28029 -passes=obf-vm -S %s -o %t.alt
; RUN: %python -c "import pathlib,sys; sys.exit(0 if pathlib.Path(sys.argv[1]).read_text()!=pathlib.Path(sys.argv[2]).read_text() else 1)" %t.fixed %t.alt
; RUN: %lli %t.fixed

define i32 @entropy_alpha(i32 %x) {
entry:
  %a = xor i32 %x, 17
  %b = add i32 %a, 3
  ret i32 %b
}

define i32 @entropy_beta(i32 %x) {
entry:
  %a = add i32 %x, 21
  %b = xor i32 %a, 9
  ret i32 %b
}

define i32 @entropy_gamma(i32 %x) {
entry:
  %a = mul i32 %x, 5
  %b = add i32 %a, 11
  ret i32 %b
}

define i32 @entropy_delta(i32 %x) {
entry:
  %a = sub i32 %x, 12
  %b = xor i32 %a, 27
  ret i32 %b
}

define i32 @entropy_epsilon(i32 %x) {
entry:
  %a = add i32 %x, 8
  %b = sub i32 %a, 2
  ret i32 %b
}

define i32 @main() {
entry:
  %a = call i32 @entropy_alpha(i32 4)
  %b = call i32 @entropy_beta(i32 4)
  %c = call i32 @entropy_gamma(i32 4)
  %d = call i32 @entropy_delta(i32 40)
  %e = call i32 @entropy_epsilon(i32 5)
  %ab = add i32 %a, %b
  %cd = add i32 %c, %d
  %abcde0 = add i32 %ab, %cd
  %sum = add i32 %abcde0, %e
  %ok = icmp eq i32 %sum, 89
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; IR-DAG: @rt_core_ea = external externally_initialized global i64, align 8
; IR-COUNT-5: %obf.entropy.cache.init{{[0-9]*}} = call { i64, i64 } @__obf_entropy_thunk_
; IR-LABEL: define internal { i64, i64 } @__obf_entropy_thunk_
; IR: call { i64, i64 } @rt_core_ep{{[0-4]}}()
; IR: ret { i64, i64 }
; IR-NOT: {{%obf\.vm\.opcode\.match[^ ]* = }}icmp eq i8
; IR-NOT: {{%obf\.vm\.opcode\.match[^ ]* = }}icmp eq i32
; IR: {{%obf\.vm\.opcode\.split\.(low|high)\.reload[^ ]* = }}load i32, ptr %obf.vm.pred.slot
; IR: {{^obf\.vm\.route\.entry\.[0-9]+:}}
; IR: br label %vm.exec.{{[0-9]+}}
; IR: obf.vm.entry.thunk:
