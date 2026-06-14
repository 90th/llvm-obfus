; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/policy-floor.yaml -passes=obf-feature-report -disable-output %s | %FileCheck %s

@.str = private unnamed_addr constant [6 x i8] c"hello\00"

declare i32 @puts(ptr)

define i32 @forced_string() {
entry:
  %call = call i32 @puts(ptr @.str)
  ret i32 %call
}

define i32 @forced_control(i32 %x) {
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

define i32 @default_none(i32 %x) {
entry:
  ret i32 %x
}

; CHECK-DAG: "name":"forced_string","policy":{{.*}}"detail":"config match:forced_string; minimum security floor raised to light","level":"light","minimum_security_floor":"light","seed":"0x{{[0-9a-f]+}}","source":"config_rule"
; CHECK-DAG: "name":"forced_control","policy":{{.*}}"detail":"override:forced_control; minimum security floor raised to strong","level":"strong","minimum_security_floor":"strong","seed":"0x{{[0-9a-f]+}}","source":"explicit_override"
; CHECK-DAG: "name":"default_none","policy":{{.*}}"detail":"default","level":"none","seed":"0x{{[0-9a-f]+}}","source":"default"
