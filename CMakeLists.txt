cmake_minimum_required(VERSION 3.24)

project(llvm-obfus LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# -----------------------------------------------------------------------------
# Dynamic Seed Generation
# Injects entropy at compile time to mutate the structural generation per build
# -----------------------------------------------------------------------------
string(RANDOM LENGTH 16 ALPHABET "0123456789" BUILD_SEED)

find_package(Python3 REQUIRED COMPONENTS Interpreter)
find_program(OBF_LIT lit REQUIRED)

find_package(LLVM REQUIRED CONFIG)
find_program(OBF_OPT opt HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
find_program(OBF_CLANG clang HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
find_program(OBF_CLANGXX clang++ HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
find_program(OBF_LLVM_LINK llvm-link HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
find_program(OBF_LLC llc HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
find_program(OBF_STRIP llvm-strip HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)

option(OBF_BENCHMARK_CLEAN_IR
  "Generate cleaned benchmark IR for analysis builds"
  OFF)
set(OBF_BENCHMARK_CLEANUP_PASSES "dse" CACHE STRING
  "Cleanup passes used when OBF_BENCHMARK_CLEAN_IR is enabled")

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")

if(LLVM_PACKAGE_VERSION VERSION_LESS 21)
  message(FATAL_ERROR "llvm-obfus requires LLVM 21 or newer")
endif()

list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
include(AddLLVM)
include(HandleLLVMOptions)

separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND "${LLVM_DEFINITIONS}")

include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS_LIST})

llvm_map_components_to_libnames(OBF_LLVM_LIBS
  Analysis
  Core
  IRReader
  Passes
  Support
)

add_library(obf_core
  lib/frontend/annotations.cpp
  lib/frontend/config.cpp
  lib/analysis/function_features.cpp
  lib/policy/policy_engine.cpp
  lib/report/function_report.cpp
  lib/transforms/block_split.cpp
  lib/transforms/bogus_control_flow.cpp
  lib/transforms/constant_encoding.cpp
  lib/transforms/control_flattening.cpp
  lib/transforms/artifact_cleanup.cpp
  lib/transforms/entropy_initialization.cpp
  lib/transforms/function_outlining.cpp
  lib/transforms/instruction_substitution.cpp
  lib/transforms/mba.cpp
  lib/transforms/opaque_gep.cpp
  lib/transforms/opaque_predicates.cpp
  lib/transforms/string_encoding.cpp
  lib/vm/candidate_analysis.cpp
  lib/vm/bytecode_decode.cpp
  lib/vm/dispatch_emission.cpp
  lib/vm/handler_lowering_control.cpp
  lib/vm/handler_lowering_memory.cpp
  lib/vm/handler_lowering_scalar.cpp
  lib/vm/value_materialization.cpp
  lib/vm/virtualize.cpp
)
llvm_update_compile_flags(obf_core)
target_include_directories(obf_core PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(obf_core PRIVATE ${OBF_LLVM_LIBS})

add_llvm_pass_plugin(obf_plugin
  lib/plugin/plugin_vm.cpp
  lib/plugin/plugin_pipeline.cpp
  lib/plugin/plugin_reporting.cpp
  lib/plugin/plugin_policy.cpp
  lib/plugin/obfuscator_plugin.cpp
)
llvm_update_compile_flags(obf_plugin)
target_include_directories(obf_plugin PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(obf_plugin PRIVATE obf_core ${OBF_LLVM_LIBS})

add_executable(obf-driver
  tools/obf-driver/main.cpp
)
llvm_update_compile_flags(obf-driver)
target_include_directories(obf-driver PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(obf-driver PRIVATE obf_core ${OBF_LLVM_LIBS})

set(OBF_ENTROPY_ANCHOR_LL "${CMAKE_CURRENT_BINARY_DIR}/obf_entropy_anchor.ll")
set(OBF_ENTROPY_ANCHOR_RANDOMIZED_LL "${CMAKE_CURRENT_BINARY_DIR}/obf_entropy_anchor.randomized.ll")
set(OBF_ENTROPY_ANCHOR_OBJ "${CMAKE_CURRENT_BINARY_DIR}/obf_entropy_anchor.o")
add_custom_command(
  OUTPUT "${OBF_ENTROPY_ANCHOR_OBJ}"
  COMMAND "${OBF_CLANG}" -std=c17 -O0 -S -emit-llvm "${CMAKE_CURRENT_SOURCE_DIR}/runtime/entropy_anchor.c" -o "${OBF_ENTROPY_ANCHOR_LL}"
  COMMAND "${OBF_OPT}" -load-pass-plugin "$<TARGET_FILE:obf_plugin>" -passes=obf-entropy-init -S "${OBF_ENTROPY_ANCHOR_LL}" -o "${OBF_ENTROPY_ANCHOR_RANDOMIZED_LL}"
  COMMAND "${OBF_CLANG}" -c -fPIC "${OBF_ENTROPY_ANCHOR_RANDOMIZED_LL}" -o "${OBF_ENTROPY_ANCHOR_OBJ}"
  DEPENDS obf_plugin "${CMAKE_CURRENT_SOURCE_DIR}/runtime/entropy_anchor.c"
  VERBATIM)
add_custom_target(obf-entropy-anchor-runtime ALL DEPENDS "${OBF_ENTROPY_ANCHOR_OBJ}")

enable_testing()

file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/tests")
configure_file(tests/lit.cfg.py.in
  "${CMAKE_CURRENT_BINARY_DIR}/tests/lit.cfg.py"
  @ONLY)

add_test(
  NAME obf-lit
  COMMAND "${OBF_LIT}" -sv "${CMAKE_CURRENT_BINARY_DIR}/tests"
)

function(add_obf_benchmark target_name source_file config_file compiler std_flag)
  set(output_dir "${CMAKE_CURRENT_BINARY_DIR}/benchmarks/${target_name}")
  set(baseline_ll "${output_dir}/${target_name}.baseline.ll")
  set(obfuscated_ll "${output_dir}/${target_name}.obfuscated.ll")
  set(cleaned_ll "${output_dir}/${target_name}.obfuscated.cleaned.ll")
  set(final_obfuscated_ll "${obfuscated_ll}")
  set(baseline_bin "${output_dir}/${target_name}.baseline")
  set(obfuscated_bin "${output_dir}/${target_name}.obfuscated")

  add_custom_command(
    OUTPUT "${baseline_ll}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${output_dir}"
    COMMAND "${compiler}" "${std_flag}" -O1 -fno-inline -fno-inline-functions -S -emit-llvm "${source_file}" -o "${baseline_ll}"
    DEPENDS "${source_file}"
    VERBATIM)

  # Added dynamic --obf-seed insertion to the optimizer run
  add_custom_command(
    OUTPUT "${obfuscated_ll}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${output_dir}"
    COMMAND "${OBF_OPT}" -load-pass-plugin "$<TARGET_FILE:obf_plugin>" "--obf-config=${config_file}" "--obf-seed=${BUILD_SEED}" -passes=obf-safe-pipeline -S "${baseline_ll}" -o "${obfuscated_ll}"
    DEPENDS obf_plugin "${baseline_ll}" "${config_file}"
    VERBATIM)

  if(OBF_BENCHMARK_CLEAN_IR)
    add_custom_command(
      OUTPUT "${cleaned_ll}"
      COMMAND "${OBF_OPT}" "-passes=${OBF_BENCHMARK_CLEANUP_PASSES}" -S "${obfuscated_ll}" -o "${cleaned_ll}"
      DEPENDS "${obfuscated_ll}"
      VERBATIM)
    set(final_obfuscated_ll "${cleaned_ll}")
  endif()

  add_custom_command(
    OUTPUT "${baseline_bin}"
    COMMAND "${compiler}" "${baseline_ll}" -O0 -o "${baseline_bin}"
    COMMAND "${OBF_STRIP}" --strip-all "${baseline_bin}"
    DEPENDS "${baseline_ll}"
    VERBATIM)

  add_custom_command(
    OUTPUT "${obfuscated_bin}"
    COMMAND "${compiler}" "${final_obfuscated_ll}" "${OBF_ENTROPY_ANCHOR_OBJ}" -O0 -o "${obfuscated_bin}"
    COMMAND "${OBF_STRIP}" --strip-all "${obfuscated_bin}"
    DEPENDS "${final_obfuscated_ll}" "${OBF_ENTROPY_ANCHOR_OBJ}"
    VERBATIM)

  add_custom_target("${target_name}_bench" DEPENDS "${baseline_bin}" "${obfuscated_bin}")
  list(APPEND OBF_BENCHMARK_TARGETS "${target_name}_bench")
  set(OBF_BENCHMARK_TARGETS "${OBF_BENCHMARK_TARGETS}" PARENT_SCOPE)
endfunction()

function(add_obf_linked_benchmark target_name compiler std_flag config_file)
  set(output_dir "${CMAKE_CURRENT_BINARY_DIR}/benchmarks/${target_name}")
  set(linked_baseline_ll "${output_dir}/${target_name}.baseline.ll")
  set(linked_obfuscated_ll "${output_dir}/${target_name}.obfuscated.ll")
  set(linked_cleaned_ll "${output_dir}/${target_name}.obfuscated.cleaned.ll")
  set(linked_final_obfuscated_ll "${linked_obfuscated_ll}")
  set(baseline_bin "${output_dir}/${target_name}.baseline")
  set(obfuscated_bin "${output_dir}/${target_name}.obfuscated")

  set(source_lls)
  foreach(source_file IN LISTS ARGN)
    get_filename_component(source_name "${source_file}" NAME_WE)
    set(source_ll "${output_dir}/${source_name}.ll")
    add_custom_command(
      OUTPUT "${source_ll}"
      COMMAND "${CMAKE_COMMAND}" -E make_directory "${output_dir}"
      COMMAND "${compiler}" "${std_flag}" -O1 -fno-inline -fno-inline-functions -S -emit-llvm "${source_file}" -o "${source_ll}"
      DEPENDS "${source_file}"
      VERBATIM)
    list(APPEND source_lls "${source_ll}")
  endforeach()

  add_custom_command(
    OUTPUT "${linked_baseline_ll}"
    COMMAND "${OBF_LLVM_LINK}" ${source_lls} -S -o "${linked_baseline_ll}"
    DEPENDS ${source_lls}
    VERBATIM)

  # Added dynamic --obf-seed insertion to the optimizer run
  add_custom_command(
    OUTPUT "${linked_obfuscated_ll}"
    COMMAND "${OBF_OPT}" -load-pass-plugin "$<TARGET_FILE:obf_plugin>" "--obf-config=${config_file}" "--obf-seed=${BUILD_SEED}" -passes=obf-safe-pipeline -S "${linked_baseline_ll}" -o "${linked_obfuscated_ll}"
    DEPENDS obf_plugin "${linked_baseline_ll}" "${config_file}"
    VERBATIM)

  if(OBF_BENCHMARK_CLEAN_IR)
    add_custom_command(
      OUTPUT "${linked_cleaned_ll}"
      COMMAND "${OBF_OPT}" "-passes=${OBF_BENCHMARK_CLEANUP_PASSES}" -S "${linked_obfuscated_ll}" -o "${linked_cleaned_ll}"
      DEPENDS "${linked_obfuscated_ll}"
      VERBATIM)
    set(linked_final_obfuscated_ll "${linked_cleaned_ll}")
  endif()

  add_custom_command(
    OUTPUT "${baseline_bin}"
    COMMAND "${compiler}" "${linked_baseline_ll}" -O0 -o "${baseline_bin}"
    COMMAND "${OBF_STRIP}" --strip-all "${baseline_bin}"
    DEPENDS "${linked_baseline_ll}"
    VERBATIM)

  add_custom_command(
    OUTPUT "${obfuscated_bin}"
    COMMAND "${compiler}" "${linked_final_obfuscated_ll}" "${OBF_ENTROPY_ANCHOR_OBJ}" -O0 -o "${obfuscated_bin}"
    COMMAND "${OBF_STRIP}" --strip-all "${obfuscated_bin}"
    DEPENDS "${linked_final_obfuscated_ll}" "${OBF_ENTROPY_ANCHOR_OBJ}"
    VERBATIM)

  add_custom_target("${target_name}_bench" DEPENDS "${baseline_bin}" "${obfuscated_bin}")
  list(APPEND OBF_BENCHMARK_TARGETS "${target_name}_bench")
  set(OBF_BENCHMARK_TARGETS "${OBF_BENCHMARK_TARGETS}" PARENT_SCOPE)

  set(mir_baseline "${output_dir}/${target_name}.baseline.mir")
  set(mir_obfuscated "${output_dir}/${target_name}.obfuscated.mir")
  add_custom_command(
    OUTPUT "${mir_baseline}"
    COMMAND "${OBF_LLC}" -stop-after=finalize-isel "${linked_baseline_ll}" -o "${mir_baseline}"
    DEPENDS "${linked_baseline_ll}"
    VERBATIM)
  add_custom_command(
    OUTPUT "${mir_obfuscated}"
    COMMAND "${OBF_LLC}" -stop-after=finalize-isel "${linked_final_obfuscated_ll}" -o "${mir_obfuscated}"
    DEPENDS "${linked_final_obfuscated_ll}"
    VERBATIM)
  add_custom_target("${target_name}_mir" DEPENDS "${mir_baseline}" "${mir_obfuscated}")
  list(APPEND OBF_MIR_TARGETS "${target_name}_mir")
  set(OBF_MIR_TARGETS "${OBF_MIR_TARGETS}" PARENT_SCOPE)
endfunction()

add_obf_benchmark(
  license_demo
  "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/corpus/license_demo.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/config/license_demo.yaml"
  "${OBF_CLANGXX}"
  "-std=c++23")

add_obf_benchmark(
  config_demo
  "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/corpus/config_demo.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/config/config_demo.yaml"
  "${OBF_CLANG}"
  "-std=c17")

add_obf_benchmark(
  vm_workflow_demo
  "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/corpus/vm_workflow_demo.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/config/vm_workflow_demo.yaml"
  "${OBF_CLANG}"
  "-std=c17")

add_obf_linked_benchmark(
  wpo_demo
  "${OBF_CLANG}"
  "-std=c17"
  "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/config/wpo_demo.yaml"
  "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/corpus/wpo_demo_main.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/corpus/wpo_demo_core.c")

add_custom_target(obf-benchmarks DEPENDS ${OBF_BENCHMARK_TARGETS})
add_custom_target(obf-benchmarks-mir DEPENDS ${OBF_MIR_TARGETS})
