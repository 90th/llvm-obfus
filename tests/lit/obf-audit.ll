; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/obf-audit.yaml -passes=obf-audit -disable-output %s | %FileCheck %s --check-prefix=TABLE
; RUN: rm -f %t.audit.json
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/obf-audit.yaml --obf-audit-out=%t.audit.json -passes=obf-audit -disable-output %s >/dev/null
; RUN: %python -c "import json,pathlib,sys; rows=json.loads(pathlib.Path(sys.argv[1]).read_text())['functions']; got=[(row['function'], row['final_level'], row['source_of_truth']) for row in rows]; expected=[('declared_only()','none','implicit (declaration forced none)'),('annotated()','strong_vm','source annotation (OBF_ANNOTATE)'),('risky_vm()','light','automatic analysis (downgrade)'),('floored()','strong','automatic analysis (minimum security floor)'),('defaulted()','light','yaml default policy')]; sys.exit(0 if got==expected else 1)" %t.audit.json

@.obf.strong_vm = private unnamed_addr constant [14 x i8] c"obf:strong_vm\00", section "llvm.metadata"
@.obf.audit.file = private unnamed_addr constant [13 x i8] c"obf-audit.ll\00", section "llvm.metadata"
@llvm.global.annotations = appending global [1 x { ptr, ptr, ptr, i32, ptr }] [
  { ptr, ptr, ptr, i32, ptr } { ptr @annotated, ptr @.obf.strong_vm, ptr @.obf.audit.file, i32 1, ptr null }
], section "llvm.metadata"

declare void @declared_only()

define void @annotated() {
entry:
  ret void
}

define void @risky_vm() personality ptr null {
entry:
  invoke void @annotated() to label %done unwind label %landing

done:
  ret void

landing:
  %pad = landingpad { ptr, i32 }
      cleanup
  resume { ptr, i32 } %pad
}

define i32 @floored(i32 %x) {
entry:
  switch i32 %x, label %fallback [
    i32 0, label %zero
    i32 1, label %one
    i32 2, label %two
  ]

zero:
  br label %done

one:
  br label %done

two:
  br label %done

fallback:
  br label %done

done:
  %result = phi i32 [ 0, %zero ], [ 1, %one ], [ 2, %two ], [ 3, %fallback ]
  ret i32 %result
}

define i32 @defaulted(i32 %x) {
entry:
  %sum = add i32 %x, 1
  ret i32 %sum
}

; TABLE: [ llvm-obfus policy resolution ]
; TABLE-NEXT: function        | final level | source of truth
; TABLE-NEXT: ---------------------------------------------------------------------------
; TABLE-NEXT: declared_only() | none        | implicit (declaration forced none)
; TABLE-NEXT: annotated()     | strong_vm   | source annotation (OBF_ANNOTATE)
; TABLE-NEXT: risky_vm()      | light       | automatic analysis (downgrade)
; TABLE-NEXT: floored()       | strong      | automatic analysis (minimum security floor)
; TABLE-NEXT: defaulted()     | light       | yaml default policy
