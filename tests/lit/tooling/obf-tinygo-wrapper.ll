; REQUIRES: has-tinygo-wrapper-host
;
; TinyGo parser and transaction coverage uses the table-driven fake tools in
; Inputs. The host gate matches the wrapper preflight. The real test is separate.
;
; RUN: rm -rf %t.* && mkdir -p %t.tmp
; RUN: not %obf_tinygo build -scheduler=none -gc=conservative -o %t.no-config %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=NO-CONFIG
; RUN: not %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml test -gc=conservative -o %t.command %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=COMMAND
; RUN: not %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml build -gc=leaking -o %t.gc %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=GC
; RUN: not %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml build -o %t.no-gc %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=GC-REQUIRED
; RUN: not %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml build -gc=conservative -o %t.no-scheduler %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=SCHEDULER-REQUIRED
; RUN: not %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml build -scheduler=tasks -gc=conservative -o %t.bad-scheduler %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=SCHEDULER
; RUN: not %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml build -scheduler=none -scheduler=none -gc=conservative -o %t.duplicate-scheduler %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=SCHEDULER-DUPLICATE
; RUN: not %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml build -gc=conservative %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=OUTPUT-REQUIRED
; RUN: not %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml build -gc=conservative -target=wasm -o %t.target %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=TARGET
; RUN: not %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml build -gc=conservative -buildmode=c-shared -o %t.mode %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=BUILDMODE
; RUN: not env GOARCH=arm64 %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml build -scheduler=none -gc=conservative -o %t.cross %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=CROSS
; RUN: not %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml build -scheduler=none -gc=conservative -o %t.two %S/../Inputs/obf-tinygo-numeric.go second 2>&1 | %FileCheck %s --check-prefix=PACKAGE
; RUN: rm -f %t.alias-output %t.alias-save && printf old > %t.alias-output && ln -s %t.alias-output %t.alias-save
; RUN: not %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml --obf-save-bc=%t.alias-save build -scheduler=none -gc=conservative -o %t.alias-output %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=ALIAS
; RUN: printf 'frontend: rust\ndefault_level: none\ntargets:\n  - match: protected_value\n    level: light\nstring_encoding:\n  max_strings_per_module: 0\n' > %t.bad-frontend.yaml
; RUN: not %obf_tinygo --obf-config=%t.bad-frontend.yaml build -scheduler=none -gc=conservative -o %t.bad-frontend %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=FRONTEND
; RUN: printf 'profile: standard\n---\nfrontend: tinygo\ndefault_level: none\ntargets:\n  - match: protected_value\n    level: light\nstring_encoding:\n  max_strings_per_module: 0\n' > %t.multiple-documents.yaml
; RUN: not %obf_tinygo --obf-config=%t.multiple-documents.yaml build -scheduler=none -gc=conservative -o %t.multiple-documents %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=DOCUMENTS
; RUN: printf 'profile: standard\n--- !!map\nfrontend: tinygo\ndefault_level: none\ntargets:\n  - match: protected_value\n    level: light\nstring_encoding:\n  max_strings_per_module: 0\n' > %t.tagged-documents.yaml
; RUN: not %obf_tinygo --obf-config=%t.tagged-documents.yaml build -scheduler=none -gc=conservative -o %t.tagged-documents %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=DOCUMENTS
; RUN: printf 'frontend: tinygo\ndefault_level: light\ntargets:\n  - match: protected_value\n    level: light\nstring_encoding:\n  max_strings_per_module: 0\n' > %t.bad-default.yaml
; RUN: not %obf_tinygo --obf-config=%t.bad-default.yaml build -scheduler=none -gc=conservative -o %t.bad-default %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=DEFAULT
; RUN: printf 'frontend: tinygo\ndefault_level: none\nstring_encoding:\n  max_strings_per_module: 0\n' > %t.no-target.yaml
; RUN: not %obf_tinygo --obf-config=%t.no-target.yaml build -scheduler=none -gc=conservative -o %t.no-target %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=TARGETS
; RUN: printf 'frontend: tinygo\ndefault_level: none\ntargets:\n  - match: protected_*\n    level: light\nstring_encoding:\n  max_strings_per_module: 0\n' > %t.bad-target.yaml
; RUN: not %obf_tinygo --obf-config=%t.bad-target.yaml build -scheduler=none -gc=conservative -o %t.bad-target %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=EXACT
; RUN: printf 'frontend: tinygo\ndefault_level: none\ntargets:\n  - match: protected_value\n    level: light\nstring_encoding:\n  max_strings_per_module: 1\n' > %t.bad-strings.yaml
; RUN: not %obf_tinygo --obf-config=%t.bad-strings.yaml build -scheduler=none -gc=conservative -o %t.bad-strings %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=STRINGS
; RUN: printf '"fr\\x6fntend": "tinyg\\x6f"\n"default_level": none\n"overrides":\n  - "name": protected_value\n    level: light\n"string_encoding":\n  "max_strings_per_module": 0\n' > %t.quoted-override.yaml
; RUN: not env TMPDIR=%t.tmp OBF_TINYGO_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_BC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_LLC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_TINYGO_FAKE_MODE=bad-tinygo-tuple %obf_tinygo --obf-config=%t.quoted-override.yaml build -scheduler=none -gc=conservative -o %t.quoted-override %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=TINYGO-TUPLE
; RUN: %python -c "from pathlib import Path; Path(r'%t.bom.yaml').write_text(Path(r'%S/../Inputs/obf-tinygo-config.yaml').read_text(encoding='utf-8'), encoding='utf-8-sig')"
; RUN: not env TMPDIR=%t.tmp OBF_TINYGO_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_BC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_LLC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_TINYGO_FAKE_MODE=bad-tinygo-tuple %obf_tinygo --obf-config=%t.bom.yaml build -scheduler=none -gc=conservative -o %t.bom %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=TINYGO-TUPLE
; RUN: printf 'frontend: tinygo\ndefault_level: none\noverrides:\n  - name: protected_*\n    level: light\nstring_encoding:\n  max_strings_per_module: 0\n' > %t.bad-override.yaml
; RUN: not %obf_tinygo --obf-config=%t.bad-override.yaml build -scheduler=none -gc=conservative -o %t.bad-override %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=EXACT-OVERRIDE
; RUN: printf 'package main\nimport "C"\nfunc main() {}\n' > %t.cgo.go
; RUN: not env TMPDIR=%t.tmp OBF_TINYGO_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_BC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_LLC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_TINYGO_FAKE_MODE=direct-cgo %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml build -scheduler=none -gc=conservative -o %t.cgo %t.cgo.go 2>&1 | %FileCheck %s --check-prefix=CGO
; RUN: not env TMPDIR=%t.tmp OBF_TINYGO_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_BC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_LLC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_TINYGO_FAKE_MODE=dependency-cgo %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml build -scheduler=none -gc=conservative -o %t.dependency-cgo %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=CGO-DEPENDENCY
;
; The TinyGo and llc tuple checks execute no build. The LLD check runs after
; closure capture and before transformation. No tuple failure touches the output.
; RUN: not env TMPDIR=%t.tmp OBF_TINYGO_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_BC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_LLC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_TINYGO_FAKE_MODE=bad-tinygo-tuple %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml build -scheduler=none -gc=conservative -o %t.bad-tinygo %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=TINYGO-TUPLE
; RUN: not env TMPDIR=%t.tmp OBF_TINYGO_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_BC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_LLC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_TINYGO_FAKE_MODE=bad-go-tuple %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml build -scheduler=none -gc=conservative -o %t.bad-go %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=TINYGO-TUPLE
; RUN: not env TMPDIR=%t.tmp OBF_TINYGO_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_BC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_LLC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_TINYGO_FAKE_MODE=bad-llc-tuple %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml build -scheduler=none -gc=conservative -o %t.bad-llc %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=LLC-TUPLE
; RUN: not env TMPDIR=%t.tmp OBF_TINYGO_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_BC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_LLC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_LLD_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_LLD_DRIVER=fake-lld OBF_TINYGO_FAKE_MODE=bad-lld-tuple %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml build -scheduler=none -gc=conservative -o %t.bad-lld %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=LLD-TUPLE
; RUN: not env TMPDIR=%t.tmp OBF_TINYGO_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_BC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_LLC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_TINYGO_FAKE_MODE=bad-captured-lld-tuple %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml build -scheduler=none -gc=conservative -o %t.bad-captured-lld %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=LLD-TUPLE
;
; The successful fake run records the exact protected BC -> llc object ->
; relink chain. It also proves a fresh saved BC follows the inherited umask.
; RUN: printf old > %t.ok.exe
; RUN: umask 0022 && env TMPDIR=%t.tmp OBF_TINYGO_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_BC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_LLC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_TINYGO_FAKE_MODE=ok OBF_TINYGO_FAKE_LOG=%t.ok.log %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml --obf-save-bc=%t.ok.bc build -scheduler=none -gc=none -o %t.ok.exe %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=PROVENANCE
; RUN: %python %S/../Inputs/obf-tinygo-assert.py provenance %t.ok.log %t.ok.bc %t.ok.exe %obf_runtime && %python %S/../Inputs/obf-tinygo-assert.py save-mode %t.ok.bc 0644
; RUN: %python %S/../Inputs/obf-tinygo-assert.py clean %t.ok.log %t.tmp
; RUN: env TMPDIR=%t.tmp OBF_TINYGO_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_BC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_LLC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_LLD_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_LLD_DRIVER=fake-lld OBF_TINYGO_FAKE_MODE=configured-lld OBF_TINYGO_FAKE_LOG=%t.configured-lld.log %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml build -scheduler=none -gc=none -o %t.configured-lld.exe %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=LLD-FALLBACK
; RUN: %python %S/../Inputs/obf-tinygo-assert.py elf %t.configured-lld.exe && %python %S/../Inputs/obf-tinygo-assert.py clean %t.configured-lld.log %t.tmp
; RUN: mkdir -p %t.linker-cwd && printf '#!/bin/sh\nexit 99\n' > %t.linker-cwd/ld.lld && chmod +x %t.linker-cwd/ld.lld
; RUN: cd %t.linker-cwd && env TMPDIR=%t.tmp OBF_TINYGO_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_BC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_LLC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_LLD_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_LLD_DRIVER=fake-lld OBF_TINYGO_FAKE_MODE=configured-lld OBF_TINYGO_FAKE_LOG=%t.bare-linker.log %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml build -scheduler=none -gc=none -o %t.bare-linker.exe %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=LLD-FALLBACK
; RUN: %python %S/../Inputs/obf-tinygo-assert.py elf %t.bare-linker.exe && %python %S/../Inputs/obf-tinygo-assert.py clean %t.bare-linker.log %t.tmp
; RUN: mkdir -p "%t.tmp/with space"
; RUN: env TMPDIR="%t.tmp/with space" OBF_TINYGO_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_BC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_LLC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_TINYGO_FAKE_MODE=ok OBF_TINYGO_FAKE_LOG=%t.space.log %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml build -scheduler=none -gc=none -o %t.space.exe %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=PROVENANCE
; RUN: %python %S/../Inputs/obf-tinygo-assert.py elf %t.space.exe && %python %S/../Inputs/obf-tinygo-assert.py clean %t.space.log "%t.tmp/with space"
; RUN: mkdir -p %t.python-temp
; RUN: env -u TMPDIR TEMP=%t.python-temp TMP=%t.python-temp OBF_TINYGO_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_BC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_LLC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_TINYGO_FAKE_MODE=ok OBF_TINYGO_FAKE_LOG=%t.unix-temp.log %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml build -scheduler=none -gc=none -o %t.unix-temp.exe %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=PROVENANCE
; RUN: %python %S/../Inputs/obf-tinygo-assert.py elf %t.unix-temp.exe && %python %S/../Inputs/obf-tinygo-assert.py clean %t.unix-temp.log %t.python-temp
;
; RUN: printf stale > %t.mode.bc && chmod 0640 %t.mode.bc
; RUN: umask 0077 && env TMPDIR=%t.tmp OBF_TINYGO_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_BC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_LLC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_TINYGO_FAKE_MODE=ok OBF_TINYGO_FAKE_LOG=%t.mode.log %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml --obf-save-bc=%t.mode.bc build -scheduler=none -gc=none -o %t.mode.exe %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=PROVENANCE
; RUN: %python %S/../Inputs/obf-tinygo-assert.py provenance %t.mode.log %t.mode.bc %t.mode.exe %obf_runtime && %python %S/../Inputs/obf-tinygo-assert.py save-mode %t.mode.bc 0640 && %python %S/../Inputs/obf-tinygo-assert.py clean %t.mode.log %t.tmp
;
; An explicit user -x/-work retains the wrapper scratch plus both TinyGo work
; trees. A requested -work response-shape failure below has the same retention.
; RUN: env TMPDIR=%t.tmp OBF_TINYGO_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_BC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_LLC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_TINYGO_FAKE_MODE=ok OBF_TINYGO_FAKE_LOG=%t.work.log %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml build -scheduler=none -x -work -gc=conservative -o %t.work.exe %S/../Inputs/obf-tinygo-numeric.go 2>&1 | tee %t.work.wrapper.log | %FileCheck %s --check-prefix=WORK
; RUN: %python %S/../Inputs/obf-tinygo-assert.py work %t.work.log %t.work.wrapper.log %t.tmp && %python %S/../Inputs/obf-tinygo-assert.py elf %t.work.exe
;
; Default closure failures retain neither TinyGo work nor wrapper scratch.
; RUN: for MODE in duplicate-work duplicate-link response group library-before-main duplicate-runtime duplicate-output duplicate-main duplicate-mcpu duplicate-mattr duplicate-lto bad-code-model target-closure non-elf-closure shared-output shared-alias-output shared-long-alias-output pic-output; do printf preserved > %t.$MODE.expected && cp %t.$MODE.expected %t.$MODE.exe && not env TMPDIR=%t.tmp OBF_TINYGO_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_BC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_LLC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_TINYGO_FAKE_MODE=$MODE OBF_TINYGO_FAKE_LOG=%t.$MODE.log %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml build -scheduler=none -gc=conservative -o %t.$MODE.exe %S/../Inputs/obf-tinygo-numeric.go && cmp %t.$MODE.expected %t.$MODE.exe && %python %S/../Inputs/obf-tinygo-assert.py clean %t.$MODE.log %t.tmp || exit 1; done
; RUN: for MODE in duplicate-work duplicate-link response group library-before-main duplicate-runtime duplicate-output duplicate-main duplicate-mcpu duplicate-mattr duplicate-lto bad-code-model target-closure non-elf-closure shared-output shared-alias-output shared-long-alias-output pic-output; do %python %S/../Inputs/obf-tinygo-assert.py clean %t.$MODE.log %t.tmp || exit 1; done
; RUN: for MODE in empty-mcpu empty-mattr; do printf preserved > %t.$MODE.expected && cp %t.$MODE.expected %t.$MODE.exe && not env TMPDIR=%t.tmp OBF_TINYGO_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_BC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_LLC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_TINYGO_FAKE_MODE=$MODE OBF_TINYGO_FAKE_LOG=%t.$MODE.log %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml build -scheduler=none -gc=conservative -o %t.$MODE.exe %S/../Inputs/obf-tinygo-numeric.go && cmp %t.$MODE.expected %t.$MODE.exe && %python %S/../Inputs/obf-tinygo-assert.py clean %t.$MODE.log %t.tmp || exit 1; done
; RUN: printf preserved > %t.response.expected && cp %t.response.expected %t.response.exe
; RUN: not env TMPDIR=%t.tmp OBF_TINYGO_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_BC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_LLC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_TINYGO_FAKE_MODE=response OBF_TINYGO_FAKE_LOG=%t.response.detail.log %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml build -scheduler=none -work -gc=conservative -o %t.response.exe %S/../Inputs/obf-tinygo-numeric.go 2>&1 | tee %t.response.wrapper.log | %FileCheck %s --check-prefix=RESPONSE
; RUN: cmp %t.response.expected %t.response.exe && %python %S/../Inputs/obf-tinygo-assert.py work %t.response.detail.log %t.response.wrapper.log %t.tmp
; RUN: not env TMPDIR=%t.tmp OBF_TINYGO_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_BC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_LLC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_TINYGO_FAKE_MODE=library-before-main %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml build -scheduler=none -gc=conservative -o %t.library %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=ARCHIVE
; RUN: not env TMPDIR=%t.tmp OBF_TINYGO_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_BC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_LLC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_TINYGO_FAKE_MODE=duplicate-mcpu %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml build -scheduler=none -gc=conservative -o %t.codegen %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=CODEGEN
; RUN: not env TMPDIR=%t.tmp OBF_TINYGO_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_BC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_LLC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_TINYGO_FAKE_MODE=target-closure %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml build -scheduler=none -gc=conservative -o %t.closure-target %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=CLOSURE-TARGET
; RUN: not env TMPDIR=%t.tmp OBF_TINYGO_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_BC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_LLC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_TINYGO_FAKE_MODE=non-elf-closure %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml build -scheduler=none -gc=conservative -o %t.non-elf %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=CLOSURE-ELF
; RUN: not env TMPDIR=%t.tmp OBF_TINYGO_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_BC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_LLC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_TINYGO_FAKE_MODE=shared-output %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml build -scheduler=none -gc=conservative -o %t.shared %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=CLOSURE-MODE
; RUN: not env TMPDIR=%t.tmp OBF_TINYGO_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_BC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_LLC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_TINYGO_FAKE_MODE=pie-output OBF_TINYGO_FAKE_LOG=%t.pie-output.log %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml build -scheduler=none -gc=conservative -o %t.pie %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=PIE-MODE
; RUN: %python %S/../Inputs/obf-tinygo-assert.py clean %t.pie-output.log %t.tmp
;
; Child failures and signals must leave the old executable intact and clean the
; retained work tree. All three mutable stages are exercised independently.
; RUN: %python %S/../Inputs/obf-tinygo-assert.py wrapper-signal %obf_tinygo %S/../Inputs/obf-tinygo-config.yaml %S/../Inputs/obf-tinygo-numeric.go %t.wrapper-signal.exe %t.wrapper-signal.log %t.wrapper-signal-tmp %S/../Inputs/obf-tinygo-fake-tools.py
; RUN: for MODE in transform-fail lower-fail relink-fail; do printf preserved > %t.$MODE.expected && cp %t.$MODE.expected %t.$MODE.exe && not env TMPDIR=%t.tmp OBF_TINYGO_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_BC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_LLC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_TINYGO_FAKE_MODE=$MODE OBF_TINYGO_FAKE_LOG=%t.$MODE.log %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml build -scheduler=none -gc=conservative -o %t.$MODE.exe %S/../Inputs/obf-tinygo-numeric.go && cmp %t.$MODE.expected %t.$MODE.exe && %python %S/../Inputs/obf-tinygo-assert.py clean %t.$MODE.log || exit 1; done
; RUN: for MODE in transform-signal lower-signal relink-signal; do printf preserved > %t.$MODE.expected && cp %t.$MODE.expected %t.$MODE.exe && not --crash env TMPDIR=%t.tmp OBF_TINYGO_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_BC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_LLC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_TINYGO_FAKE_MODE=$MODE OBF_TINYGO_FAKE_LOG=%t.$MODE.log %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml build -scheduler=none -gc=conservative -o %t.$MODE.exe %S/../Inputs/obf-tinygo-numeric.go && cmp %t.$MODE.expected %t.$MODE.exe && %python %S/../Inputs/obf-tinygo-assert.py clean %t.$MODE.log || exit 1; done
; RUN: for MODE in transform-fail lower-fail relink-fail transform-signal lower-signal relink-signal; do %python %S/../Inputs/obf-tinygo-assert.py clean %t.$MODE.log %t.tmp || exit 1; done
; RUN: for MODE in lower-non-elf relink-non-elf; do printf preserved > %t.$MODE.expected && cp %t.$MODE.expected %t.$MODE.exe && not env TMPDIR=%t.tmp OBF_TINYGO_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_BC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_LLC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_TINYGO_FAKE_MODE=$MODE OBF_TINYGO_FAKE_LOG=%t.$MODE.log %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml build -scheduler=none -gc=conservative -o %t.$MODE.exe %S/../Inputs/obf-tinygo-numeric.go && cmp %t.$MODE.expected %t.$MODE.exe && %python %S/../Inputs/obf-tinygo-assert.py clean %t.$MODE.log %t.tmp || exit 1; done
;
; Save failure is intentionally post-commit: the new executable survives, while
; the requested saved-BC destination is not replaced.
; RUN: rm -rf %t.save-dir && mkdir %t.save-dir && printf preserved > %t.partial.exe
; RUN: not env TMPDIR=%t.tmp OBF_TINYGO_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_BC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_LLC_BIN=%S/../Inputs/obf-tinygo-fake-tools.py OBF_TINYGO_FAKE_MODE=ok OBF_TINYGO_FAKE_LOG=%t.partial.log %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml --obf-save-bc=%t.save-dir build -scheduler=none -gc=conservative -o %t.partial.exe %S/../Inputs/obf-tinygo-numeric.go 2>&1 | %FileCheck %s --check-prefix=SAVE
; RUN: %python %S/../Inputs/obf-tinygo-assert.py elf %t.partial.exe && test -d %t.save-dir && %python %S/../Inputs/obf-tinygo-assert.py clean %t.partial.log
; RUN: %python %S/../Inputs/obf-tinygo-assert.py clean %t.partial.log %t.tmp
;
; NO-CONFIG: obf-tinygo: --obf-config requires a path
; COMMAND: obf-tinygo: only the TinyGo build subcommand is supported
; GC: obf-tinygo: only -gc=conservative and -gc=none are supported
; TARGET: obf-tinygo: -target is unsupported; only the native host default is supported
; GC-REQUIRED: obf-tinygo: an explicit -gc=conservative or -gc=none is required
; SCHEDULER-REQUIRED: obf-tinygo: an explicit -scheduler=none is required
; SCHEDULER: obf-tinygo: only -scheduler=none is supported
; SCHEDULER-DUPLICATE: obf-tinygo: -scheduler may be specified only once
; OUTPUT-REQUIRED: obf-tinygo: -o requires a path
; BUILDMODE: obf-tinygo: only the default TinyGo buildmode is supported
; CROSS: obf-tinygo: GOARCH target override is unsupported; only the native host default is supported
; PACKAGE: obf-tinygo: build requires exactly one package or .go file argument
; ALIAS: obf-tinygo: --obf-save-bc must be canonically distinct from -o
; DEFAULT: obf-tinygo: --obf-config line 2 requires default_level: none
; TARGETS: obf-tinygo: --obf-config requires at least one exact targets[].match or overrides[].name entry
; FRONTEND: obf-tinygo: --obf-config line 1 requires frontend: tinygo
; EXACT: obf-tinygo: --obf-config line 4 targets[].match must be exact, not a wildcard
; EXACT-OVERRIDE: obf-tinygo: --obf-config line 4 overrides[].name must be exact, not a wildcard
; STRINGS: obf-tinygo: --obf-config requires string_encoding.max_strings_per_module: 0
; DOCUMENTS: obf-tinygo: --obf-config must contain exactly one non-empty YAML document
; CGO: obf-tinygo: cgo is unsupported
; CGO-DEPENDENCY: obf-tinygo: cgo is unsupported (package example/dependency contains cgo sources)
; TINYGO-TUPLE: obf-tinygo: requires TinyGo 0.41.x with Go 1.23-1.26 and embedded LLVM 20.x
; LLC-TUPLE: obf-tinygo: requires configured LLVM 21 llc
; LLD-TUPLE: obf-tinygo: requires an LLVM 21 LLD linker
; LLD-FALLBACK: obf-tinygo: provenance {{.*"relink_argv": \[".*/obf-tinygo-fake-tools.py", "fake-lld", "--gc-sections".*}}
; WORK: OBF_WORK=
; PROVENANCE: obf-tinygo: provenance {{.*"llc_argv":.*"-mcpu=x86-64".*"relink_argv":.*"--gc-sections".*}}
; RESPONSE: obf-tinygo: retained ld.lld command uses unsupported response/group/shell syntax: @response.rsp
; RESPONSE: OBF_WORK=
; RESPONSE: TINYGO_WORK=
; ARCHIVE: obf-tinygo: retained ld.lld command places a library/archive before WORK/main.o
; CODEGEN: obf-tinygo: retained ld.lld command must contain exactly one non-empty -mllvm -mcpu= value (got 2)
; CLOSURE-TARGET: obf-tinygo: retained ld.lld command uses unsupported target selection: --target=x86_64-unknown-linux-gnu
; CLOSURE-ELF: obf-tinygo: expected native ELF artifact, got non-ELF file:
; CLOSURE-MODE: obf-tinygo: retained ld.lld command is not an executable closure: -shared
; PIE-MODE: obf-tinygo: retained ld.lld command is not an executable closure: -pie
; SAVE: obf-tinygo: executable was installed, but --obf-save-bc failed:
