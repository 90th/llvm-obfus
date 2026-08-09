cmake_minimum_required(VERSION 3.24)

project(llvm-obfus LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(OBF_BENCHMARK_SEED "" CACHE STRING
  "Fixed benchmark obfuscation seed; empty uses a generated seed")

string(RANDOM LENGTH 1 ALPHABET "123456789" OBF_GENERATED_BENCHMARK_SEED_LEAD)
string(RANDOM LENGTH 15 ALPHABET "0123456789" OBF_GENERATED_BENCHMARK_SEED_TAIL)
set(OBF_GENERATED_BENCHMARK_SEED
  "${OBF_GENERATED_BENCHMARK_SEED_LEAD}${OBF_GENERATED_BENCHMARK_SEED_TAIL}")

if(NOT OBF_BENCHMARK_SEED STREQUAL "")
  if(NOT OBF_BENCHMARK_SEED MATCHES "^[1-9][0-9]*$")
    message(FATAL_ERROR
      "OBF_BENCHMARK_SEED must be a non-zero base-10 integer without leading zeroes")
  endif()
  set(OBF_EFFECTIVE_BENCHMARK_SEED "${OBF_BENCHMARK_SEED}")
  set(OBF_BENCHMARK_SEED_SOURCE "cache")
else()
  set(OBF_EFFECTIVE_BENCHMARK_SEED "${OBF_GENERATED_BENCHMARK_SEED}")
  set(OBF_BENCHMARK_SEED_SOURCE "generated")
endif()

set(OBF_BENCHMARK_SEED_STAMP
  "${CMAKE_CURRENT_BINARY_DIR}/obf_benchmark_seed.txt")
file(GENERATE OUTPUT "${OBF_BENCHMARK_SEED_STAMP}"
  CONTENT "${OBF_EFFECTIVE_BENCHMARK_SEED}\n")

find_package(Python3 REQUIRED COMPONENTS Interpreter)
find_program(OBF_LIT lit REQUIRED)

find_package(LLVM REQUIRED CONFIG)
find_program(OBF_OPT opt HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
find_program(OBF_CLANG clang HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
find_program(OBF_CLANGXX clang++ HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
find_program(OBF_LLVM_LINK llvm-link HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
find_program(OBF_LLC llc HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
find_program(OBF_LLI lli HINTS "${LLVM_TOOLS_BINARY_DIR}")
find_program(OBF_STRIP llvm-strip HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
find_program(OBF_NM llvm-nm HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
find_program(OBF_OBJDUMP llvm-objdump HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
find_program(OBF_STRINGS strings)
find_program(OBF_RUSTC rustc)
find_program(OBF_CARGO cargo)
find_program(OBF_ZIG zig)
find_program(OBF_TINYGO tinygo)
find_program(OBF_LLD NAMES ld.lld-21 ld.lld HINTS "${LLVM_TOOLS_BINARY_DIR}")

if(OBF_RUSTC)
  set(OBF_RUSTC_COMMAND "${OBF_RUSTC}")
else()
  set(OBF_RUSTC_COMMAND "rustc")
endif()

if(OBF_CARGO)
  set(OBF_CARGO_COMMAND "${OBF_CARGO}")
else()
  set(OBF_CARGO_COMMAND "cargo")
endif()

if(OBF_ZIG)
  set(OBF_ZIG_COMMAND "${OBF_ZIG}")
else()
  set(OBF_ZIG_COMMAND "zig")
endif()

set(OBF_LLD_IS_LLVM21 OFF)
if(OBF_LLD)
  execute_process(
    COMMAND "${OBF_LLD}" --version
    RESULT_VARIABLE OBF_LLD_VERSION_STATUS
    OUTPUT_VARIABLE OBF_LLD_VERSION_STDOUT
    ERROR_VARIABLE OBF_LLD_VERSION_STDERR
  )
  string(CONCAT OBF_LLD_VERSION_OUTPUT
    "${OBF_LLD_VERSION_STDOUT}" "\n" "${OBF_LLD_VERSION_STDERR}")
  if(OBF_LLD_VERSION_STATUS EQUAL 0
      AND OBF_LLD_VERSION_OUTPUT MATCHES "LLD[ \t]+21\\.")
    set(OBF_LLD_IS_LLVM21 ON)
  endif()
endif()

if(OBF_LLD_IS_LLVM21)
  set(OBF_LLD_COMMAND "${OBF_LLD}")
  set(OBF_LLD_DRIVER "")
elseif(OBF_ZIG)
  set(OBF_LLD_COMMAND "${OBF_ZIG}")
  set(OBF_LLD_DRIVER "ld.lld")
elseif(OBF_LLD)
  set(OBF_LLD_COMMAND "${OBF_LLD}")
  set(OBF_LLD_DRIVER "")
else()
  set(OBF_LLD_COMMAND "ld.lld")
  set(OBF_LLD_DRIVER "")
endif()


if(OBF_TINYGO)
  set(OBF_TINYGO_COMMAND "${OBF_TINYGO}")
else()
  set(OBF_TINYGO_COMMAND "tinygo")
endif()

set(OBF_HAS_RUST_BENCHMARK_TOOLCHAIN OFF)
set(OBF_HAS_ZIG_BENCHMARK_TOOLCHAIN OFF)
set(OBF_HAS_TINYGO_BENCHMARK_TOOLCHAIN OFF)

set(OBF_PROJECT_LLVM_MAJOR_MINOR "")
if(LLVM_PACKAGE_VERSION MATCHES "^([0-9]+)\\.([0-9]+)")
  set(OBF_PROJECT_LLVM_MAJOR_MINOR "${CMAKE_MATCH_1}.${CMAKE_MATCH_2}")
endif()

execute_process(
  COMMAND "${OBF_RUSTC_COMMAND}" -Vv
  RESULT_VARIABLE OBF_RUSTC_VERSION_STATUS
  OUTPUT_VARIABLE OBF_RUSTC_VERSION_STDOUT
  ERROR_VARIABLE OBF_RUSTC_VERSION_STDERR)
string(CONCAT OBF_RUSTC_VERSION_OUTPUT
  "${OBF_RUSTC_VERSION_STDOUT}" "\n" "${OBF_RUSTC_VERSION_STDERR}")
set(OBF_RUSTC_RELEASE "")
if(OBF_RUSTC_VERSION_OUTPUT MATCHES "release:[ \t]*([^ \t\r\n]+)")
  set(OBF_RUSTC_RELEASE "${CMAKE_MATCH_1}")
endif()
set(OBF_RUSTC_LLVM_MAJOR_MINOR "")
if(OBF_RUSTC_VERSION_OUTPUT MATCHES "LLVM version:[ \t]*([0-9]+)\.([0-9]+)")
  set(OBF_RUSTC_LLVM_MAJOR_MINOR "${CMAKE_MATCH_1}.${CMAKE_MATCH_2}")
endif()
if(OBF_RUSTC_VERSION_STATUS EQUAL 0
    AND OBF_CARGO
    AND NOT OBF_PROJECT_LLVM_MAJOR_MINOR STREQUAL ""
    AND OBF_RUSTC_RELEASE MATCHES "(^|[-.])(nightly|dev)([-.]|$)"
    AND OBF_RUSTC_LLVM_MAJOR_MINOR STREQUAL OBF_PROJECT_LLVM_MAJOR_MINOR)
  set(OBF_HAS_RUST_BENCHMARK_TOOLCHAIN ON)
endif()

execute_process(
  COMMAND "${OBF_ZIG_COMMAND}" version
  RESULT_VARIABLE OBF_ZIG_VERSION_STATUS
  OUTPUT_VARIABLE OBF_ZIG_VERSION_STDOUT
  ERROR_VARIABLE OBF_ZIG_VERSION_STDERR)
string(CONCAT OBF_ZIG_VERSION_OUTPUT
  "${OBF_ZIG_VERSION_STDOUT}" "\n" "${OBF_ZIG_VERSION_STDERR}")

string(TOLOWER "${CMAKE_HOST_SYSTEM_PROCESSOR}" OBF_HOST_SYSTEM_PROCESSOR_LOWER)
string(TOLOWER "${LLVM_HOST_TRIPLE}" OBF_LLVM_HOST_TRIPLE_LOWER)
string(REGEX MATCH "^[^-]+" OBF_LLVM_HOST_ARCH "${OBF_LLVM_HOST_TRIPLE_LOWER}")
if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux"
    AND OBF_LLVM_HOST_TRIPLE_LOWER MATCHES "linux"
    AND OBF_ZIG_VERSION_STATUS EQUAL 0
    AND OBF_ZIG_VERSION_OUTPUT MATCHES "(^|[\r\n])[ \\t]*0\\.16\\.[0-9]+([-+][^\\r\\n]*)?([\r\n]|$)")
  set(OBF_HAS_ZIG_BENCHMARK_TOOLCHAIN ON)
endif()

set(OBF_TINYGO_HOST_MATCH OFF)
set(OBF_TINYGO_ARM_HOST_ARCHES
  arm
  armv5
  armv5l
  armv5tel
  armv6
  armv6l
  armv7
  armv7l
  armv8
  armv8l)

if((OBF_HOST_SYSTEM_PROCESSOR_LOWER STREQUAL "x86_64"
      OR OBF_HOST_SYSTEM_PROCESSOR_LOWER STREQUAL "amd64")
    AND (OBF_LLVM_HOST_ARCH STREQUAL "x86_64"
      OR OBF_LLVM_HOST_ARCH STREQUAL "amd64"))
  set(OBF_TINYGO_HOST_MATCH ON)
elseif((OBF_HOST_SYSTEM_PROCESSOR_LOWER STREQUAL "aarch64"
         OR OBF_HOST_SYSTEM_PROCESSOR_LOWER STREQUAL "arm64")
       AND (OBF_LLVM_HOST_ARCH STREQUAL "aarch64"
         OR OBF_LLVM_HOST_ARCH STREQUAL "arm64"))
  set(OBF_TINYGO_HOST_MATCH ON)
elseif(OBF_HOST_SYSTEM_PROCESSOR_LOWER IN_LIST OBF_TINYGO_ARM_HOST_ARCHES
       AND OBF_LLVM_HOST_ARCH IN_LIST OBF_TINYGO_ARM_HOST_ARCHES)
  set(OBF_TINYGO_HOST_MATCH ON)
endif()

set(OBF_LLC_VERSION_COMMAND "${OBF_LLC}" "--version")
execute_process(
  COMMAND ${OBF_LLC_VERSION_COMMAND}
  RESULT_VARIABLE OBF_LLC_VERSION_STATUS
  OUTPUT_VARIABLE OBF_LLC_VERSION_STDOUT
  ERROR_VARIABLE OBF_LLC_VERSION_STDERR)
string(CONCAT OBF_LLC_VERSION_OUTPUT
  "${OBF_LLC_VERSION_STDOUT}" "\n" "${OBF_LLC_VERSION_STDERR}")

set(OBF_LLD_VERSION_COMMAND "${OBF_LLD_COMMAND}")
if(NOT OBF_LLD_DRIVER STREQUAL "")
  separate_arguments(OBF_LLD_DRIVER_ARGS NATIVE_COMMAND "${OBF_LLD_DRIVER}")
  list(APPEND OBF_LLD_VERSION_COMMAND ${OBF_LLD_DRIVER_ARGS})
endif()
list(APPEND OBF_LLD_VERSION_COMMAND "--version")
execute_process(
  COMMAND ${OBF_LLD_VERSION_COMMAND}
  RESULT_VARIABLE OBF_LLD_VERSION_STATUS
  OUTPUT_VARIABLE OBF_LLD_VERSION_STDOUT
  ERROR_VARIABLE OBF_LLD_VERSION_STDERR)
string(CONCAT OBF_LLD_VERSION_OUTPUT
  "${OBF_LLD_VERSION_STDOUT}" "\n" "${OBF_LLD_VERSION_STDERR}")

execute_process(
  COMMAND "${OBF_TINYGO_COMMAND}" version
  RESULT_VARIABLE OBF_TINYGO_VERSION_STATUS
  OUTPUT_VARIABLE OBF_TINYGO_VERSION_STDOUT
  ERROR_VARIABLE OBF_TINYGO_VERSION_STDERR)
string(CONCAT OBF_TINYGO_VERSION_OUTPUT
  "${OBF_TINYGO_VERSION_STDOUT}" "\n" "${OBF_TINYGO_VERSION_STDERR}")
if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux"
    AND OBF_LLVM_HOST_TRIPLE_LOWER MATCHES "linux"
    AND OBF_TINYGO_HOST_MATCH
    AND LLVM_PACKAGE_VERSION MATCHES "^21(\\.|$)"
    AND OBF_LLC_VERSION_STATUS EQUAL 0
    AND OBF_LLC_VERSION_OUTPUT MATCHES "LLVM.*version[ \\t:]*21(\\.|$)"
    AND OBF_TINYGO_VERSION_STATUS EQUAL 0
    AND OBF_LLD_VERSION_STATUS EQUAL 0
    AND OBF_TINYGO_VERSION_OUTPUT MATCHES "tinygo version 0\\.41\\.[0-9]+"
    AND OBF_TINYGO_VERSION_OUTPUT MATCHES "using go version go1\\.(23|24|25|26)"
    AND OBF_TINYGO_VERSION_OUTPUT MATCHES "LLVM version 20\\."
    AND OBF_LLD_VERSION_OUTPUT MATCHES "LLD[ \\t]+21(\\.|$)")
  set(OBF_HAS_TINYGO_BENCHMARK_TOOLCHAIN ON)
endif()

if(OBF_HAS_RUST_BENCHMARK_TOOLCHAIN)
  message(STATUS "Enabled Rust corpus benchmark")
else()
  message(STATUS "Rust corpus benchmark disabled: requires nightly or dev rustc with matching LLVM and Cargo")
endif()

if(OBF_HAS_ZIG_BENCHMARK_TOOLCHAIN)
  message(STATUS "Enabled Zig corpus benchmark")
else()
  message(STATUS "Zig corpus benchmark disabled: requires Zig 0.16.x on native Linux")
endif()

if(OBF_HAS_TINYGO_BENCHMARK_TOOLCHAIN)
  message(STATUS "Enabled TinyGo corpus benchmark")
else()
  message(STATUS "TinyGo corpus benchmark disabled: requires TinyGo 0.41.x, Go 1.23-1.26, configured LLVM 21 llc, native Linux, and LLD 21")
endif()


option(OBF_BENCHMARK_CLEAN_IR
  "Generate cleaned benchmark IR for analysis builds"
  OFF)
set(OBF_BENCHMARK_CLEANUP_PASSES "dse" CACHE STRING
  "Cleanup passes used when OBF_BENCHMARK_CLEAN_IR is enabled")

set(OBF_RUNTIME_ABI_PREFIX "rt_core_" CACHE STRING
  "Build-global runtime ABI prefix used for exported runtime symbols")

if(NOT OBF_RUNTIME_ABI_PREFIX MATCHES "^[A-Za-z_][A-Za-z0-9_]*_$")
  message(FATAL_ERROR
    "OBF_RUNTIME_ABI_PREFIX must be a valid C identifier prefix ending with '_'"
  )
endif()

string(TOLOWER "${OBF_RUNTIME_ABI_PREFIX}" OBF_RUNTIME_ABI_PREFIX_LOWER)
if(OBF_RUNTIME_ABI_PREFIX_LOWER MATCHES "obf")
  message(FATAL_ERROR
    "OBF_RUNTIME_ABI_PREFIX must not contain 'obf'"
  )
endif()

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS
  "Benchmark obfuscation seed (${OBF_BENCHMARK_SEED_SOURCE}): ${OBF_EFFECTIVE_BENCHMARK_SEED}")

if(LLVM_PACKAGE_VERSION VERSION_LESS 21)
  message(FATAL_ERROR "llvm-obfus requires LLVM 21 or newer")
endif()

list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
include(AddLLVM)
include(CheckCSourceCompiles)
include(HandleLLVMOptions)

if(NOT MSVC)
  set(_obf_saved_required_libraries "${CMAKE_REQUIRED_LIBRARIES}")
  set(CMAKE_REQUIRED_LIBRARIES "")
  check_c_source_compiles(
    "#include <stdint.h>
int main(void) {
  _Alignas(8) uint64_t value = 0;
  uint64_t expected = 0;
  (void)__atomic_compare_exchange_n(
      &value, &expected, 1ULL, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
  return 0;
}
"
    OBF_HAS_DIRECT_U64_ATOMICS)
  set(CMAKE_REQUIRED_LIBRARIES "${_obf_saved_required_libraries}")
  unset(_obf_saved_required_libraries)
  if(NOT OBF_HAS_DIRECT_U64_ATOMICS)
    message(FATAL_ERROR
      "Target toolchain must provide direct aligned uint64_t __atomic_compare_exchange_n support")
  endif()
endif()

separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND "${LLVM_DEFINITIONS}")

include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS_LIST})

file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/include/obf/support")
configure_file(
  include/obf/support/runtime_abi_generated.h.in
  "${CMAKE_CURRENT_BINARY_DIR}/include/obf/support/runtime_abi_generated.h"
  @ONLY)

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
  lib/transforms/indirect_dispatch.cpp
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
  lib/vm/virtualize_anchor_scattering.cpp
  lib/vm/virtualize_island_topology.cpp
  lib/vm/virtualize_dispatch_return.cpp
  lib/vm/virtualize_body_rewrite.cpp
  lib/vm/virtualize.cpp
  # Support
  lib/support/affine_helpers.cpp
  lib/support/constant_materialization.cpp
  lib/support/decoy_trap.cpp
  lib/support/flattening_metadata.cpp
  lib/support/mba_config_builder.cpp
  lib/support/value_utils.cpp
)
llvm_update_compile_flags(obf_core)
target_include_directories(obf_core PUBLIC ${PROJECT_SOURCE_DIR}/include
                                          ${CMAKE_CURRENT_BINARY_DIR}/include)
target_link_libraries(obf_core PRIVATE ${OBF_LLVM_LIBS})

add_llvm_pass_plugin(obf_plugin
  lib/plugin/plugin_vm_target_discovery.cpp
  lib/plugin/plugin_vm_binding_prep.cpp
  lib/plugin/plugin_vm_resolvers.cpp
  lib/plugin/plugin_vm_wrapper_emission.cpp
  lib/plugin/plugin_vm_callsite_rewriting.cpp
  lib/plugin/plugin_vm.cpp
  lib/plugin/plugin_pipeline.cpp
  lib/plugin/plugin_reporting.cpp
  lib/plugin/plugin_policy.cpp
  lib/plugin/obfuscator_plugin.cpp
)
llvm_update_compile_flags(obf_plugin)
target_include_directories(obf_plugin PRIVATE ${PROJECT_SOURCE_DIR}/include
                                              ${CMAKE_CURRENT_BINARY_DIR}/include)
target_link_libraries(obf_plugin PRIVATE obf_core ${OBF_LLVM_LIBS})

add_executable(obf-driver
  tools/obf-driver/main.cpp
)
llvm_update_compile_flags(obf-driver)
target_include_directories(obf-driver PRIVATE ${PROJECT_SOURCE_DIR}/include
                                              ${CMAKE_CURRENT_BINARY_DIR}/include)
target_link_libraries(obf-driver PRIVATE obf_core ${OBF_LLVM_LIBS})

add_executable(obf-unit-tests
  tests/unit/obf_unit_tests.cpp
)
llvm_update_compile_flags(obf-unit-tests)
target_include_directories(obf-unit-tests PRIVATE ${PROJECT_SOURCE_DIR}/include
                                                  ${CMAKE_CURRENT_BINARY_DIR}/include)
target_link_libraries(obf-unit-tests PRIVATE obf_core ${OBF_LLVM_LIBS})

add_executable(obf-runtime-atomic-tests
  tests/unit/runtime_atomic_tests.c
)
set_target_properties(obf-runtime-atomic-tests PROPERTIES
  C_STANDARD 17
  C_STANDARD_REQUIRED ON
)
target_include_directories(obf-runtime-atomic-tests PRIVATE ${PROJECT_SOURCE_DIR}/include
                                                            ${CMAKE_CURRENT_BINARY_DIR}/include)

set(OBF_ENTROPY_ANCHOR_LL "${CMAKE_CURRENT_BINARY_DIR}/obf_entropy_anchor.ll")
set(OBF_ENTROPY_ANCHOR_RANDOMIZED_LL "${CMAKE_CURRENT_BINARY_DIR}/obf_entropy_anchor.randomized.ll")
set(OBF_ENTROPY_ANCHOR_OBJ "${CMAKE_CURRENT_BINARY_DIR}/obf_entropy_anchor.o")
set(OBF_STRING_AUTH_RUNTIME_OBJ "${CMAKE_CURRENT_BINARY_DIR}/obf_string_auth_runtime.o")
add_custom_command(
  OUTPUT "${OBF_ENTROPY_ANCHOR_OBJ}"
  COMMAND "${OBF_CLANG}" -std=c17 -O0 -I${CMAKE_CURRENT_BINARY_DIR}/include -I${CMAKE_CURRENT_SOURCE_DIR}/include -S -emit-llvm "${CMAKE_CURRENT_SOURCE_DIR}/runtime/entropy_anchor.c" -o "${OBF_ENTROPY_ANCHOR_LL}"
  COMMAND "${OBF_OPT}" -load-pass-plugin "$<TARGET_FILE:obf_plugin>" "--obf-seed=${OBF_EFFECTIVE_BENCHMARK_SEED}" -passes=obf-entropy-init -S "${OBF_ENTROPY_ANCHOR_LL}" -o "${OBF_ENTROPY_ANCHOR_RANDOMIZED_LL}"
  COMMAND "${OBF_CLANG}" -c -fPIC "${OBF_ENTROPY_ANCHOR_RANDOMIZED_LL}" -o "${OBF_ENTROPY_ANCHOR_OBJ}"
  DEPENDS obf_plugin "${CMAKE_CURRENT_SOURCE_DIR}/runtime/entropy_anchor.c" "${CMAKE_CURRENT_SOURCE_DIR}/include/obf/support/blake2s_internal.h" "${CMAKE_CURRENT_BINARY_DIR}/include/obf/support/runtime_abi_generated.h" "${OBF_BENCHMARK_SEED_STAMP}"
  VERBATIM)
add_custom_command(
  OUTPUT "${OBF_STRING_AUTH_RUNTIME_OBJ}"
  COMMAND "${OBF_CLANG}" -std=c17 -O2 -I${CMAKE_CURRENT_BINARY_DIR}/include -I${CMAKE_CURRENT_SOURCE_DIR}/include -c -fPIC "${CMAKE_CURRENT_SOURCE_DIR}/runtime/string_auth_runtime.c" -o "${OBF_STRING_AUTH_RUNTIME_OBJ}"
  DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/runtime/string_auth_runtime.c" "${CMAKE_CURRENT_SOURCE_DIR}/include/obf/support/blake2s_internal.h" "${CMAKE_CURRENT_BINARY_DIR}/include/obf/support/runtime_abi_generated.h"
  VERBATIM)
add_custom_target(obf-entropy-anchor-runtime ALL DEPENDS "${OBF_ENTROPY_ANCHOR_OBJ}")
add_custom_target(obf-string-auth-runtime ALL DEPENDS "${OBF_STRING_AUTH_RUNTIME_OBJ}")
set(OBF_RUNTIME_ARCHIVE "${CMAKE_CURRENT_BINARY_DIR}/libobf_runtime.a")
add_custom_command(
  OUTPUT "${OBF_RUNTIME_ARCHIVE}"
  COMMAND "${CMAKE_COMMAND}" -E rm -f "${OBF_RUNTIME_ARCHIVE}"
  COMMAND "${CMAKE_AR}" qc "${OBF_RUNTIME_ARCHIVE}" "${OBF_ENTROPY_ANCHOR_OBJ}" "${OBF_STRING_AUTH_RUNTIME_OBJ}"
  COMMAND "${CMAKE_RANLIB}" "${OBF_RUNTIME_ARCHIVE}"
  DEPENDS "${OBF_ENTROPY_ANCHOR_OBJ}" "${OBF_STRING_AUTH_RUNTIME_OBJ}"
  VERBATIM)
add_custom_target(obf-runtime ALL DEPENDS "${OBF_RUNTIME_ARCHIVE}")
configure_file(
  tools/obf-clang/obf-clang.py.in
  "${CMAKE_CURRENT_BINARY_DIR}/obf-clang"
  @ONLY
  FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
configure_file(
  tools/obf-clang/obf-clang.py.in
  "${CMAKE_CURRENT_BINARY_DIR}/obf-clang++"
  @ONLY
  FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
add_custom_target(obf-clang-wrappers ALL
  DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/obf-clang" "${CMAKE_CURRENT_BINARY_DIR}/obf-clang++")
add_dependencies(obf-clang-wrappers obf_plugin obf-runtime)
configure_file(
  tools/obf-bc/obf-bc.py.in
  "${CMAKE_CURRENT_BINARY_DIR}/obf-bc"
  @ONLY
  FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
configure_file(
  tools/obf-rustc/obf-rustc.py.in
  "${CMAKE_CURRENT_BINARY_DIR}/obf-rustc"
  @ONLY
  FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
configure_file(
  tools/obf-tinygo/obf-tinygo.py.in
  "${CMAKE_CURRENT_BINARY_DIR}/obf-tinygo"
  @ONLY
  FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
add_custom_target(obf-language-tools ALL
  DEPENDS
    "${CMAKE_CURRENT_BINARY_DIR}/obf-bc"
    "${CMAKE_CURRENT_BINARY_DIR}/obf-rustc"
    "${CMAKE_CURRENT_BINARY_DIR}/obf-tinygo")
add_dependencies(obf-language-tools obf-driver obf_plugin obf-runtime)
enable_testing()

file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/tests")
configure_file(tests/lit.cfg.py.in
  "${CMAKE_CURRENT_BINARY_DIR}/tests/lit.cfg.py"
  @ONLY)

add_test(
  NAME obf-lit
  COMMAND "${OBF_LIT}" -j 1 -sv "${CMAKE_CURRENT_BINARY_DIR}/tests"
)

add_test(
  NAME obf-unit-tests
  COMMAND obf-unit-tests
)

add_test(
  NAME obf-runtime-atomic-tests
  COMMAND obf-runtime-atomic-tests
)

set(OBF_BENCHMARK_GENERATED_CONFIG_DIR
  "${CMAKE_CURRENT_BINARY_DIR}/benchmarks/config")
file(MAKE_DIRECTORY "${OBF_BENCHMARK_GENERATED_CONFIG_DIR}")
configure_file(
  benchmarks/config/rust_demo.yaml.in
  "${OBF_BENCHMARK_GENERATED_CONFIG_DIR}/rust_demo.yaml"
  @ONLY)
configure_file(
  benchmarks/config/zig_demo.yaml.in
  "${OBF_BENCHMARK_GENERATED_CONFIG_DIR}/zig_demo.yaml"
  @ONLY)
configure_file(
  benchmarks/config/tinygo_demo.yaml.in
  "${OBF_BENCHMARK_GENERATED_CONFIG_DIR}/tinygo_demo.yaml"
  @ONLY)

set(OBF_RUST_DEMO_BENCH_CONFIG
  "${OBF_BENCHMARK_GENERATED_CONFIG_DIR}/rust_demo.yaml")
set(OBF_ZIG_DEMO_BENCH_CONFIG
  "${OBF_BENCHMARK_GENERATED_CONFIG_DIR}/zig_demo.yaml")
set(OBF_TINYGO_DEMO_BENCH_CONFIG
  "${OBF_BENCHMARK_GENERATED_CONFIG_DIR}/tinygo_demo.yaml")

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

  add_custom_command(
    OUTPUT "${obfuscated_ll}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${output_dir}"
    COMMAND "${CMAKE_COMMAND}" -E rm -f "${obfuscated_ll}"
    COMMAND "${OBF_OPT}" -load-pass-plugin "$<TARGET_FILE:obf_plugin>" "--obf-config=${config_file}" "--obf-seed=${OBF_EFFECTIVE_BENCHMARK_SEED}" -passes=obf-safe-pipeline -S "${baseline_ll}" -o "${obfuscated_ll}"
    DEPENDS obf_plugin "${baseline_ll}" "${config_file}" "${OBF_BENCHMARK_SEED_STAMP}"
    VERBATIM)

  if(OBF_BENCHMARK_CLEAN_IR)
    add_custom_command(
      OUTPUT "${cleaned_ll}"
      COMMAND "${CMAKE_COMMAND}" -E rm -f "${cleaned_ll}"
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
    COMMAND "${compiler}" "${final_obfuscated_ll}" "${OBF_ENTROPY_ANCHOR_OBJ}" "${OBF_STRING_AUTH_RUNTIME_OBJ}" -O0 -o "${obfuscated_bin}"
    COMMAND "${OBF_STRIP}" --strip-all "${obfuscated_bin}"
    DEPENDS "${final_obfuscated_ll}" "${OBF_ENTROPY_ANCHOR_OBJ}" "${OBF_STRING_AUTH_RUNTIME_OBJ}"
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

  add_custom_command(
    OUTPUT "${linked_obfuscated_ll}"
    COMMAND "${CMAKE_COMMAND}" -E rm -f "${linked_obfuscated_ll}"
    COMMAND "${OBF_OPT}" -load-pass-plugin "$<TARGET_FILE:obf_plugin>" "--obf-config=${config_file}" "--obf-seed=${OBF_EFFECTIVE_BENCHMARK_SEED}" -passes=obf-safe-pipeline -S "${linked_baseline_ll}" -o "${linked_obfuscated_ll}"
    DEPENDS obf_plugin "${linked_baseline_ll}" "${config_file}" "${OBF_BENCHMARK_SEED_STAMP}"
    VERBATIM)

  if(OBF_BENCHMARK_CLEAN_IR)
    add_custom_command(
      OUTPUT "${linked_cleaned_ll}"
      COMMAND "${CMAKE_COMMAND}" -E rm -f "${linked_cleaned_ll}"
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
    COMMAND "${compiler}" "${linked_final_obfuscated_ll}" "${OBF_ENTROPY_ANCHOR_OBJ}" "${OBF_STRING_AUTH_RUNTIME_OBJ}" -O0 -o "${obfuscated_bin}"
    COMMAND "${OBF_STRIP}" --strip-all "${obfuscated_bin}"
    DEPENDS "${linked_final_obfuscated_ll}" "${OBF_ENTROPY_ANCHOR_OBJ}" "${OBF_STRING_AUTH_RUNTIME_OBJ}"
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

function(add_obf_rust_benchmark target_name source_file config_file)
  set(output_dir "${CMAKE_CURRENT_BINARY_DIR}/benchmarks/${target_name}")
  set(baseline_ll "${output_dir}/${target_name}.baseline.ll")
  set(obfuscated_ll "${output_dir}/${target_name}.obfuscated.ll")
  set(cleaned_ll "${output_dir}/${target_name}.obfuscated.cleaned.ll")
  set(extra_ir_outputs)
  set(baseline_bin "${output_dir}/${target_name}.baseline")
  set(obfuscated_bin "${output_dir}/${target_name}.obfuscated")

  add_custom_command(
    OUTPUT "${baseline_ll}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${output_dir}"
    COMMAND "${OBF_RUSTC_COMMAND}"
            --crate-name=${target_name}
            --crate-type=bin
            --edition=2021
            --emit=llvm-ir
            -Copt-level=1
            -Ccodegen-units=1
            "${source_file}"
            -o "${baseline_ll}"
    DEPENDS "${source_file}"
    VERBATIM)

  add_custom_command(
    OUTPUT "${obfuscated_ll}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${output_dir}"
    COMMAND "${CMAKE_COMMAND}" -E rm -f "${obfuscated_ll}"
    COMMAND "${CMAKE_CURRENT_BINARY_DIR}/obf-rustc"
            --obf-config=${config_file}
            --crate-name=${target_name}
            --crate-type=bin
            --edition=2021
            --emit=llvm-ir
            -Copt-level=1
            "${source_file}"
            -o "${obfuscated_ll}"
    DEPENDS obf-language-tools "${source_file}" "${config_file}"
    VERBATIM)

  if(OBF_BENCHMARK_CLEAN_IR)
    add_custom_command(
      OUTPUT "${cleaned_ll}"
      COMMAND "${CMAKE_COMMAND}" -E rm -f "${cleaned_ll}"
      COMMAND "${OBF_OPT}" "-passes=${OBF_BENCHMARK_CLEANUP_PASSES}" -S "${obfuscated_ll}" -o "${cleaned_ll}"
      DEPENDS "${obfuscated_ll}"
      VERBATIM)
    list(APPEND extra_ir_outputs "${cleaned_ll}")
  endif()

  add_custom_command(
    OUTPUT "${baseline_bin}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${output_dir}"
    COMMAND "${OBF_RUSTC_COMMAND}"
            --crate-name=${target_name}
            --crate-type=bin
            --edition=2021
            -Copt-level=1
            -Ccodegen-units=1
            "${source_file}"
            -o "${baseline_bin}"
    COMMAND "${OBF_STRIP}" --strip-all "${baseline_bin}"
    DEPENDS "${source_file}"
    VERBATIM)

  add_custom_command(
    OUTPUT "${obfuscated_bin}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${output_dir}"
    COMMAND "${CMAKE_CURRENT_BINARY_DIR}/obf-rustc"
            --obf-config=${config_file}
            --crate-name=${target_name}
            --crate-type=bin
            --edition=2021
            --emit=link
            -Copt-level=1
            "${source_file}"
            -o "${obfuscated_bin}"
    COMMAND "${OBF_STRIP}" --strip-all "${obfuscated_bin}"
    DEPENDS obf-language-tools "${source_file}" "${config_file}"
    VERBATIM)

  add_custom_target("${target_name}_bench"
    DEPENDS "${baseline_ll}" "${obfuscated_ll}" ${extra_ir_outputs} "${baseline_bin}" "${obfuscated_bin}")
  list(APPEND OBF_BENCHMARK_TARGETS "${target_name}_bench")
  set(OBF_BENCHMARK_TARGETS "${OBF_BENCHMARK_TARGETS}" PARENT_SCOPE)
endfunction()

function(add_obf_zig_benchmark target_name component_source main_source config_file)
  set(output_dir "${CMAKE_CURRENT_BINARY_DIR}/benchmarks/${target_name}")
  set(cache_dir "${output_dir}/zig-cache")
  set(global_cache_dir "${output_dir}/zig-global-cache")
  set(component_bc "${output_dir}/${target_name}.component.bc")
  set(protected_bc "${output_dir}/${target_name}.component.protected.bc")
  set(baseline_ll "${output_dir}/${target_name}.baseline.ll")
  set(obfuscated_ll "${output_dir}/${target_name}.obfuscated.ll")
  set(cleaned_ll "${output_dir}/${target_name}.obfuscated.cleaned.ll")
  set(extra_ir_outputs)
  set(baseline_bin "${output_dir}/${target_name}.baseline")
  set(obfuscated_bin "${output_dir}/${target_name}.obfuscated")

  add_custom_command(
    OUTPUT "${component_bc}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${output_dir}"
    COMMAND "${OBF_ZIG_COMMAND}" build-obj "${component_source}"
            -fllvm
            -O ReleaseFast
            --cache-dir "${cache_dir}"
            --global-cache-dir "${global_cache_dir}"
            -femit-llvm-bc=${component_bc}
            -fno-emit-bin
    DEPENDS "${component_source}"
    VERBATIM)

  add_custom_command(
    OUTPUT "${protected_bc}"
    COMMAND "${CMAKE_COMMAND}" -E rm -f "${protected_bc}"
    COMMAND "${CMAKE_CURRENT_BINARY_DIR}/obf-bc"
            --obf-config=${config_file}
            --obf-seed=${OBF_EFFECTIVE_BENCHMARK_SEED}
            "${component_bc}"
            -o "${protected_bc}"
    DEPENDS obf-language-tools "${component_bc}" "${config_file}"
    VERBATIM)

  add_custom_command(
    OUTPUT "${baseline_ll}"
    COMMAND "${OBF_OPT}" -S "${component_bc}" -o "${baseline_ll}"
    DEPENDS "${component_bc}"
    VERBATIM)

  add_custom_command(
    OUTPUT "${obfuscated_ll}"
    COMMAND "${OBF_OPT}" -S "${protected_bc}" -o "${obfuscated_ll}"
    DEPENDS "${protected_bc}"
    VERBATIM)

  if(OBF_BENCHMARK_CLEAN_IR)
    add_custom_command(
      OUTPUT "${cleaned_ll}"
      COMMAND "${CMAKE_COMMAND}" -E rm -f "${cleaned_ll}"
      COMMAND "${OBF_OPT}" "-passes=${OBF_BENCHMARK_CLEANUP_PASSES}" -S "${obfuscated_ll}" -o "${cleaned_ll}"
      DEPENDS "${obfuscated_ll}"
      VERBATIM)
    list(APPEND extra_ir_outputs "${cleaned_ll}")
  endif()

  add_custom_command(
    OUTPUT "${baseline_bin}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${output_dir}"
    COMMAND "${OBF_ZIG_COMMAND}" build-exe "${main_source}" "${component_bc}"
            -O ReleaseFast
            --cache-dir "${cache_dir}"
            --global-cache-dir "${global_cache_dir}"
            -femit-bin=${baseline_bin}
    COMMAND "${OBF_STRIP}" --strip-all "${baseline_bin}"
    DEPENDS "${main_source}" "${component_bc}"
    VERBATIM)

  add_custom_command(
    OUTPUT "${obfuscated_bin}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${output_dir}"
    COMMAND "${OBF_ZIG_COMMAND}" build-exe "${main_source}" "${protected_bc}" "${OBF_RUNTIME_ARCHIVE}"
            -O ReleaseFast
            --cache-dir "${cache_dir}"
            --global-cache-dir "${global_cache_dir}"
            -femit-bin=${obfuscated_bin}
    COMMAND "${OBF_STRIP}" --strip-all "${obfuscated_bin}"
    DEPENDS "${main_source}" "${protected_bc}" "${OBF_RUNTIME_ARCHIVE}"
    VERBATIM)

  add_custom_target("${target_name}_bench"
    DEPENDS "${baseline_ll}" "${obfuscated_ll}" ${extra_ir_outputs} "${baseline_bin}" "${obfuscated_bin}")
  list(APPEND OBF_BENCHMARK_TARGETS "${target_name}_bench")
  set(OBF_BENCHMARK_TARGETS "${OBF_BENCHMARK_TARGETS}" PARENT_SCOPE)
endfunction()

function(add_obf_tinygo_benchmark target_name source_file config_file)
  set(output_dir "${CMAKE_CURRENT_BINARY_DIR}/benchmarks/${target_name}")
  set(baseline_ll "${output_dir}/${target_name}.baseline.ll")
  set(obfuscated_ll "${output_dir}/${target_name}.obfuscated.ll")
  set(cleaned_ll "${output_dir}/${target_name}.obfuscated.cleaned.ll")
  set(extra_ir_outputs)
  set(baseline_bin "${output_dir}/${target_name}.baseline")
  set(obfuscated_bin "${output_dir}/${target_name}.obfuscated")

  add_custom_command(
    OUTPUT "${baseline_ll}" "${obfuscated_ll}" "${baseline_bin}" "${obfuscated_bin}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${output_dir}"
    COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/tools/obf-bench/build_tinygo_benchmark.py"
            --tinygo "${OBF_TINYGO_COMMAND}"
            --wrapper "${CMAKE_CURRENT_BINARY_DIR}/obf-tinygo"
            --opt "${OBF_OPT}"
            --strip "${OBF_STRIP}"
            --config "${config_file}"
            --source "${source_file}"
            --output-dir "${output_dir}"
            --name "${target_name}"
    DEPENDS obf-language-tools
            "${CMAKE_CURRENT_SOURCE_DIR}/tools/obf-bench/build_tinygo_benchmark.py"
            "${source_file}"
            "${config_file}"
    VERBATIM)

  if(OBF_BENCHMARK_CLEAN_IR)
    add_custom_command(
      OUTPUT "${cleaned_ll}"
      COMMAND "${CMAKE_COMMAND}" -E rm -f "${cleaned_ll}"
      COMMAND "${OBF_OPT}" "-passes=${OBF_BENCHMARK_CLEANUP_PASSES}" -S "${obfuscated_ll}" -o "${cleaned_ll}"
      DEPENDS "${obfuscated_ll}"
      VERBATIM)
    list(APPEND extra_ir_outputs "${cleaned_ll}")
  endif()

  add_custom_target("${target_name}_bench"
    DEPENDS "${baseline_ll}" "${obfuscated_ll}" ${extra_ir_outputs} "${baseline_bin}" "${obfuscated_bin}")
  list(APPEND OBF_BENCHMARK_TARGETS "${target_name}_bench")
  set(OBF_BENCHMARK_TARGETS "${OBF_BENCHMARK_TARGETS}" PARENT_SCOPE)
endfunction()

set(OBF_CORPUS_E2E_BENCHMARKS
  license_demo
  config_demo
  vm_workflow_demo
  wpo_demo)

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

if(OBF_HAS_RUST_BENCHMARK_TOOLCHAIN)
  add_obf_rust_benchmark(
    rust_demo
    "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/corpus/rust_demo.rs"
    "${OBF_RUST_DEMO_BENCH_CONFIG}")
  list(APPEND OBF_CORPUS_E2E_BENCHMARKS rust_demo)
endif()

if(OBF_HAS_ZIG_BENCHMARK_TOOLCHAIN)
  add_obf_zig_benchmark(
    zig_demo
    "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/corpus/zig_demo_component.zig"
    "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/corpus/zig_demo_main.zig"
    "${OBF_ZIG_DEMO_BENCH_CONFIG}")
  list(APPEND OBF_CORPUS_E2E_BENCHMARKS zig_demo)
endif()

if(OBF_HAS_TINYGO_BENCHMARK_TOOLCHAIN)
  add_obf_tinygo_benchmark(
    tinygo_demo
    "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/corpus/tinygo_demo.go"
    "${OBF_TINYGO_DEMO_BENCH_CONFIG}")
  list(APPEND OBF_CORPUS_E2E_BENCHMARKS tinygo_demo)
endif()

string(JOIN "," OBF_CORPUS_E2E_BENCHMARKS_CSV ${OBF_CORPUS_E2E_BENCHMARKS})

add_custom_target(obf-benchmarks DEPENDS ${OBF_BENCHMARK_TARGETS})
add_custom_target(obf-benchmarks-e2e
  COMMAND "${Python3_EXECUTABLE}"
          "${CMAKE_CURRENT_SOURCE_DIR}/tools/obf-bench/run_corpus_e2e.py"
          "--benchmarks-dir" "${CMAKE_CURRENT_BINARY_DIR}/benchmarks"
          "--runtime-prefix" "${OBF_RUNTIME_ABI_PREFIX}"
          "--benchmarks" "${OBF_CORPUS_E2E_BENCHMARKS_CSV}"
  DEPENDS obf-benchmarks
  VERBATIM)
add_custom_target(obf-benchmarks-mir DEPENDS ${OBF_MIR_TARGETS})
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
