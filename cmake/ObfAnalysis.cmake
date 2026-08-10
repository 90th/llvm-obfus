add_custom_target(obf-audit-benchmarks
  COMMAND "${Python3_EXECUTABLE}"
          "${CMAKE_CURRENT_SOURCE_DIR}/tools/obf-audit/audit_binary.py"
          "--benchmarks-dir" "${CMAKE_CURRENT_BINARY_DIR}/benchmarks"
          "--llvm-nm" "${OBF_NM}"
          "--llvm-objdump" "${OBF_OBJDUMP}"
          "--strings" "${OBF_STRINGS}"
          "--strict"
  DEPENDS obf-benchmarks
  VERBATIM)

set(OBF_RE_HARNESS_JSON
  "${CMAKE_CURRENT_BINARY_DIR}/re-harness/vm_recovery.json")
add_custom_target(obf-re-harness
  COMMAND "${CMAKE_COMMAND}" -E make_directory
          "${CMAKE_CURRENT_BINARY_DIR}/re-harness"
  COMMAND "${Python3_EXECUTABLE}"
          "${CMAKE_CURRENT_SOURCE_DIR}/tools/obf-re-harness/score_vm_resistance.py"
          "--benchmarks-dir" "${CMAKE_CURRENT_BINARY_DIR}/benchmarks"
          "--benchmarks" "license_demo,config_demo,vm_workflow_demo"
          "--json-out" "${OBF_RE_HARNESS_JSON}"
          "--strict"
  DEPENDS obf-benchmarks
  VERBATIM)

add_custom_target(obf-seed-diversity
  COMMAND "${Python3_EXECUTABLE}"
          "${CMAKE_CURRENT_SOURCE_DIR}/tools/obf-diversity/verify_seed_diversity.py"
          "--source-dir" "${CMAKE_CURRENT_SOURCE_DIR}"
          "--build-dir" "${CMAKE_CURRENT_BINARY_DIR}"
          "--plugin" "$<TARGET_FILE:obf_plugin>"
          "--opt" "${OBF_OPT}"
          "--clang" "${OBF_CLANG}"
          "--clangxx" "${OBF_CLANGXX}"
          "--llvm-link" "${OBF_LLVM_LINK}"
          "--seeds" "10101,20202,30303"
          "--benchmarks" "license_demo,config_demo,vm_workflow_demo"
          "--strict"
          "--require-pointer-materialization-diversity" "false"
          "--json-out" "${CMAKE_CURRENT_BINARY_DIR}/diversity/diversity.json"
  DEPENDS obf_plugin
  VERBATIM)
