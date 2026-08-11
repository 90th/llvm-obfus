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

set(OBF_RE_HARNESS_BENCHMARKS
  license_demo
  config_demo
  vm_workflow_demo)
string(JOIN "," OBF_RE_HARNESS_BENCHMARKS_CSV ${OBF_RE_HARNESS_BENCHMARKS})

set(OBF_RE_HARNESS_YAML_DEPENDENCIES)
set(OBF_RE_HARNESS_IR_DEPENDENCIES)
foreach(OBF_RE_HARNESS_BENCHMARK IN LISTS OBF_RE_HARNESS_BENCHMARKS)
  list(APPEND OBF_RE_HARNESS_YAML_DEPENDENCIES
    "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/config/${OBF_RE_HARNESS_BENCHMARK}.yaml")
  list(APPEND OBF_RE_HARNESS_IR_DEPENDENCIES
    "${CMAKE_CURRENT_BINARY_DIR}/benchmarks/${OBF_RE_HARNESS_BENCHMARK}/${OBF_RE_HARNESS_BENCHMARK}.obfuscated.ll")
endforeach()

set(OBF_RE_HARNESS_SCRIPT
  "${CMAKE_CURRENT_SOURCE_DIR}/tools/obf-re-harness/score_vm_resistance.py")
set(OBF_RE_HARNESS_JSON
  "${CMAKE_CURRENT_BINARY_DIR}/re-harness/vm_recovery.json")
add_custom_command(
  OUTPUT "${OBF_RE_HARNESS_JSON}"
  COMMAND "${CMAKE_COMMAND}" -E make_directory
          "${CMAKE_CURRENT_BINARY_DIR}/re-harness"
  COMMAND "${Python3_EXECUTABLE}"
          "${OBF_RE_HARNESS_SCRIPT}"
          "--benchmarks-dir" "${CMAKE_CURRENT_BINARY_DIR}/benchmarks"
          "--benchmarks" "${OBF_RE_HARNESS_BENCHMARKS_CSV}"
          "--json-out" "${OBF_RE_HARNESS_JSON}"
          "--strict"
  DEPENDS obf-benchmarks
          "${OBF_RE_HARNESS_SCRIPT}"
          ${OBF_RE_HARNESS_YAML_DEPENDENCIES}
          ${OBF_RE_HARNESS_IR_DEPENDENCIES}
  VERBATIM)
add_custom_target(obf-re-harness DEPENDS "${OBF_RE_HARNESS_JSON}")

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
