if(OBF_PLUGIN_IS_LOADABLE)
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

set(OBF_RE_HARNESS_IR_BENCHMARKS
  license_demo
  config_demo
  vm_workflow_demo)
string(JOIN "," OBF_RE_HARNESS_IR_BENCHMARKS_CSV ${OBF_RE_HARNESS_IR_BENCHMARKS})

set(OBF_RE_HARNESS_IR_YAML_DEPENDENCIES)
set(OBF_RE_HARNESS_IR_DEPENDENCIES)
foreach(OBF_RE_HARNESS_IR_BENCHMARK IN LISTS OBF_RE_HARNESS_IR_BENCHMARKS)
  list(APPEND OBF_RE_HARNESS_IR_YAML_DEPENDENCIES
    "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/config/${OBF_RE_HARNESS_IR_BENCHMARK}.yaml")
  list(APPEND OBF_RE_HARNESS_IR_DEPENDENCIES
    "${CMAKE_CURRENT_BINARY_DIR}/benchmarks/${OBF_RE_HARNESS_IR_BENCHMARK}/${OBF_RE_HARNESS_IR_BENCHMARK}.obfuscated.ll")
endforeach()

set(OBF_RE_HARNESS_IR_SCRIPT
  "${CMAKE_CURRENT_SOURCE_DIR}/tools/obf-re-harness/score_vm_resistance.py")
set(OBF_RE_HARNESS_IR_JSON
  "${CMAKE_CURRENT_BINARY_DIR}/re-harness/vm_recovery.json")
add_custom_command(
  OUTPUT "${OBF_RE_HARNESS_IR_JSON}"
  COMMAND "${CMAKE_COMMAND}" -E make_directory
          "${CMAKE_CURRENT_BINARY_DIR}/re-harness"
  COMMAND "${Python3_EXECUTABLE}"
          "${OBF_RE_HARNESS_IR_SCRIPT}"
          "--benchmarks-dir" "${CMAKE_CURRENT_BINARY_DIR}/benchmarks"
          "--benchmarks" "${OBF_RE_HARNESS_IR_BENCHMARKS_CSV}"
          "--json-out" "${OBF_RE_HARNESS_IR_JSON}"
          "--strict"
  DEPENDS obf-benchmarks
          "${OBF_RE_HARNESS_IR_SCRIPT}"
          ${OBF_RE_HARNESS_IR_YAML_DEPENDENCIES}
          ${OBF_RE_HARNESS_IR_DEPENDENCIES}
  VERBATIM)
add_custom_target(obf-re-harness DEPENDS "${OBF_RE_HARNESS_IR_JSON}")

set(OBF_RE_HARNESS_BINARY_BENCHMARKS
  license_demo
  config_demo
  vm_workflow_demo)
set(OBF_RE_HARNESS_BINARY_ARTIFACT_DEPENDENCIES)
set(OBF_RE_HARNESS_BINARY_CONTROL_ARGUMENTS)
foreach(OBF_RE_HARNESS_BINARY_BENCHMARK IN LISTS OBF_RE_HARNESS_BINARY_BENCHMARKS)
  set(OBF_RE_HARNESS_BINARY_BENCHMARK_DIR
    "${CMAKE_CURRENT_BINARY_DIR}/benchmarks/${OBF_RE_HARNESS_BINARY_BENCHMARK}")
  list(APPEND OBF_RE_HARNESS_BINARY_ARTIFACT_DEPENDENCIES
    "${OBF_RE_HARNESS_BINARY_BENCHMARK_DIR}/${OBF_RE_HARNESS_BINARY_BENCHMARK}.baseline"
    "${OBF_RE_HARNESS_BINARY_BENCHMARK_DIR}/${OBF_RE_HARNESS_BINARY_BENCHMARK}.obfuscated")
  list(APPEND OBF_RE_HARNESS_BINARY_CONTROL_ARGUMENTS
    "--positive"
    "${OBF_RE_HARNESS_BINARY_BENCHMARK}=${OBF_RE_HARNESS_BINARY_BENCHMARK_DIR}/${OBF_RE_HARNESS_BINARY_BENCHMARK}.obfuscated"
    "--baseline"
    "${OBF_RE_HARNESS_BINARY_BENCHMARK}=${OBF_RE_HARNESS_BINARY_BENCHMARK_DIR}/${OBF_RE_HARNESS_BINARY_BENCHMARK}.baseline")
endforeach()
list(APPEND OBF_RE_HARNESS_BINARY_CONTROL_ARGUMENTS
  "--positive-expectation"
  "license_demo=vm_candidate"
  "--positive-minimum"
  "config_demo=interpreter_like")

set(OBF_RE_HARNESS_BINARY_SCRIPT
  "${CMAKE_CURRENT_SOURCE_DIR}/tools/obf-re-harness/score_binary_recovery.py"
  CACHE FILEPATH "Binary recovery analyzer script")
set(OBF_RE_HARNESS_BINARY_CONTROLS_SCRIPT
  "${CMAKE_CURRENT_SOURCE_DIR}/tools/obf-re-harness/verify_binary_recovery_controls.py"
  CACHE FILEPATH "Binary recovery controller script")
set(OBF_RE_HARNESS_BINARY_REPORT
  "${CMAKE_CURRENT_BINARY_DIR}/re-harness/binary-recovery.json")
set(OBF_RE_HARNESS_BINARY_VERDICT
  "${CMAKE_CURRENT_BINARY_DIR}/re-harness/binary-recovery-controls.json")
add_custom_command(
  OUTPUT "${OBF_RE_HARNESS_BINARY_REPORT}" "${OBF_RE_HARNESS_BINARY_VERDICT}"
  COMMAND "${CMAKE_COMMAND}" -E make_directory
          "${CMAKE_CURRENT_BINARY_DIR}/re-harness"
  COMMAND "${Python3_EXECUTABLE}"
          "${OBF_RE_HARNESS_BINARY_CONTROLS_SCRIPT}"
          "--python" "${Python3_EXECUTABLE}"
          "--analyzer" "${OBF_RE_HARNESS_BINARY_SCRIPT}"
          "--llvm-objdump" "${OBF_OBJDUMP}"
          "--report-out" "${OBF_RE_HARNESS_BINARY_REPORT}"
          "--verdict-out" "${OBF_RE_HARNESS_BINARY_VERDICT}"
          ${OBF_RE_HARNESS_BINARY_CONTROL_ARGUMENTS}
          "--strict"
  DEPENDS obf-benchmarks-e2e
          "${OBF_RE_HARNESS_BINARY_SCRIPT}"
          "${OBF_RE_HARNESS_BINARY_CONTROLS_SCRIPT}"
          ${OBF_RE_HARNESS_BINARY_ARTIFACT_DEPENDENCIES}
  VERBATIM)
add_custom_target(obf-re-harness-binary
  DEPENDS "${OBF_RE_HARNESS_BINARY_REPORT}" "${OBF_RE_HARNESS_BINARY_VERDICT}")

set(OBF_RE_HARNESS_BINARY_MULTISEED_CONTROLLER
  "${CMAKE_CURRENT_SOURCE_DIR}/tools/obf-re-harness/verify_binary_recovery_multiseed.py")
set(OBF_RE_HARNESS_BINARY_MULTISEED_OUTPUT_ROOT
  "${CMAKE_CURRENT_BINARY_DIR}/re-harness/multiseed")
set(OBF_RE_HARNESS_BINARY_MULTISEED_REPORT
  "${CMAKE_CURRENT_BINARY_DIR}/re-harness/binary-multiseed-report.json")
add_custom_target(obf-re-harness-binary-seeds
  COMMAND "${CMAKE_COMMAND}" -E make_directory
          "${CMAKE_CURRENT_BINARY_DIR}/re-harness"
  COMMAND "${Python3_EXECUTABLE}"
          "${OBF_RE_HARNESS_BINARY_MULTISEED_CONTROLLER}"
          "--cmake" "${CMAKE_COMMAND}"
          "--source-dir" "${CMAKE_CURRENT_SOURCE_DIR}"
          "--llvm-dir" "${LLVM_DIR}"
          "--python" "${Python3_EXECUTABLE}"
          "--llvm-objdump" "${OBF_OBJDUMP}"
          "--analyzer" "${OBF_RE_HARNESS_BINARY_SCRIPT}"
          "--controller" "${OBF_RE_HARNESS_BINARY_CONTROLS_SCRIPT}"
          "--output-root" "${OBF_RE_HARNESS_BINARY_MULTISEED_OUTPUT_ROOT}"
          "--report-out" "${OBF_RE_HARNESS_BINARY_MULTISEED_REPORT}"
          "--seeds" "10101,20202,30303"
  DEPENDS "${OBF_RE_HARNESS_BINARY_SCRIPT}"
          "${OBF_RE_HARNESS_BINARY_CONTROLS_SCRIPT}"
          "${OBF_RE_HARNESS_BINARY_MULTISEED_CONTROLLER}"
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
endif()
