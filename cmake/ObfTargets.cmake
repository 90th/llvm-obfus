function(obf_apply_llvm_target_settings target)
  target_include_directories(${target} SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS})
  target_compile_definitions(${target} PRIVATE ${OBF_LLVM_PLUGIN_DEFINITIONS_LIST})
endfunction()

function(obf_apply_static_llvm_target_settings target)
  target_include_directories(${target} SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS})
  target_compile_definitions(${target} PRIVATE ${OBF_LLVM_STATIC_DEFINITIONS_LIST})
endfunction()

function(obf_configure_plugin_object_target target)
  obf_apply_llvm_target_settings(${target})
  llvm_update_compile_flags(${target})
  target_include_directories(${target} PRIVATE ${PROJECT_SOURCE_DIR}/include
                                               ${CMAKE_CURRENT_BINARY_DIR}/include)
endfunction()

set(OBF_RUST_PLUGIN_FILENAME "")
set(OBF_RUST_PLUGIN_PATH "")
set(OBF_RUST_PLUGIN_IS_LOADABLE FALSE)

if(WIN32)
  function(obf_add_windows_plugin_executable_host target executable import_library)
    add_executable(${target} IMPORTED GLOBAL)
    set_target_properties(${target} PROPERTIES
      IMPORTED_LOCATION "${executable}"
      IMPORTED_IMPLIB "${import_library}"
      ENABLE_EXPORTS ON)
  endfunction()

  function(obf_add_windows_plugin_library_host target image import_library)
    add_library(${target} SHARED IMPORTED GLOBAL)
    set_target_properties(${target} PROPERTIES
      IMPORTED_LOCATION "${image}"
      IMPORTED_IMPLIB "${import_library}")
  endfunction()

  function(obf_add_windows_plugin_module target host_target)
    add_llvm_library(${target} MODULE NO_EXPORT PLUGIN_TOOL ${host_target}
      OBJLIBS
        $<TARGET_OBJECTS:obf_plugin_core_objects>
        $<TARGET_OBJECTS:obf_plugin_frontend_objects>)
    target_link_options(${target} PRIVATE "LINKER:/EXPORT:llvmGetPassPluginInfo")
  endfunction()
endif()

file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/include/obf/support")
configure_file(
  include/obf/support/runtime_abi_generated.h.in
  "${CMAKE_CURRENT_BINARY_DIR}/include/obf/support/runtime_abi_generated.h"
  @ONLY)

set(OBF_CORE_SOURCES
  lib/frontend/annotations.cpp
  lib/frontend/config.cpp
  lib/analysis/function_features.cpp
  lib/policy/policy_engine.cpp
  lib/report/function_report.cpp
  lib/report/coverage_report.cpp
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
  lib/transforms/self_checksum.cpp
  lib/transforms/string_encoding.cpp
  lib/transforms/zero_comparison.cpp
  lib/transforms/self_checksum.cpp
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
  lib/support/value_utils.cpp)

add_library(obf_core STATIC
  ${OBF_CORE_SOURCES})
obf_apply_static_llvm_target_settings(obf_core)
llvm_update_compile_flags(obf_core)
target_include_directories(obf_core PUBLIC ${PROJECT_SOURCE_DIR}/include
                                          ${CMAKE_CURRENT_BINARY_DIR}/include)
target_link_libraries(obf_core PRIVATE ${OBF_LLVM_LIBS})

set(OBF_PLUGIN_SOURCES
  lib/plugin/plugin_vm_target_discovery.cpp
  lib/plugin/plugin_vm_binding_prep.cpp
  lib/plugin/plugin_vm_resolvers.cpp
  lib/plugin/plugin_vm_wrapper_emission.cpp
  lib/plugin/plugin_vm_callsite_rewriting.cpp
  lib/plugin/plugin_vm.cpp
  lib/plugin/plugin_pipeline.cpp
  lib/plugin/plugin_reporting.cpp
  lib/plugin/plugin_policy.cpp
  lib/plugin/obfuscator_plugin.cpp)

if(WIN32)
  obf_add_windows_plugin_executable_host(obf_windows_opt_host "${OBF_OPT}" "${OBF_OPT_IMPORT_LIBRARY}")
  obf_add_windows_plugin_executable_host(obf_windows_clang_host "${OBF_CLANG}" "${OBF_CLANG_IMPORT_LIBRARY}")

  add_library(obf_plugin_core_objects OBJECT ${OBF_CORE_SOURCES})
  obf_configure_plugin_object_target(obf_plugin_core_objects)

  add_library(obf_plugin_frontend_objects OBJECT ${OBF_PLUGIN_SOURCES})
  obf_configure_plugin_object_target(obf_plugin_frontend_objects)

  obf_add_windows_plugin_module(obf_plugin obf_windows_opt_host)
  obf_add_windows_plugin_module(obf_clang_plugin obf_windows_clang_host)
  if(OBF_WINDOWS_RUST_LLVM_HOST_BOUND)
    obf_add_windows_plugin_library_host(
      obf_windows_rust_host
      "${OBF_WINDOWS_RUST_LLVM_HOST_IMAGE}"
      "${OBF_WINDOWS_RUST_LLVM_HOST_IMPORT_LIBRARY}")
    obf_add_windows_plugin_module(obf_rustc_plugin obf_windows_rust_host)
    set(OBF_RUST_PLUGIN_FILENAME "obf_rustc_plugin${LLVM_PLUGIN_EXT}")
    set(OBF_RUST_PLUGIN_PATH
      "${CMAKE_CURRENT_BINARY_DIR}/${OBF_RUST_PLUGIN_FILENAME}")
    set(OBF_RUST_PLUGIN_IS_LOADABLE TRUE)
  endif()

  set(OBF_PLUGIN_IS_LOADABLE TRUE)
  set(OBF_CLANG_PLUGIN_PATH
    "${CMAKE_CURRENT_BINARY_DIR}/obf_clang_plugin${LLVM_PLUGIN_EXT}")
else()
  add_llvm_pass_plugin(obf_plugin ${OBF_PLUGIN_SOURCES})

  get_target_property(OBF_PLUGIN_TARGET_TYPE obf_plugin TYPE)
  if(NOT OBF_PLUGIN_TARGET_TYPE STREQUAL "UTILITY")
    if(TARGET obj.obf_plugin)
      obf_apply_llvm_target_settings(obj.obf_plugin)
    endif()
    obf_apply_llvm_target_settings(obf_plugin)
    llvm_update_compile_flags(obf_plugin)
    target_include_directories(obf_plugin PRIVATE ${PROJECT_SOURCE_DIR}/include
                                                 ${CMAKE_CURRENT_BINARY_DIR}/include)
    target_link_libraries(obf_plugin PRIVATE obf_core ${OBF_LLVM_LIBS})

    set(OBF_PLUGIN_IS_LOADABLE TRUE)
  endif()
  set(OBF_RUST_PLUGIN_FILENAME "obf_plugin${LLVM_PLUGIN_EXT}")
  set(OBF_RUST_PLUGIN_PATH
    "${CMAKE_CURRENT_BINARY_DIR}/${OBF_RUST_PLUGIN_FILENAME}")
  if(OBF_PLUGIN_IS_LOADABLE)
    set(OBF_RUST_PLUGIN_IS_LOADABLE TRUE)
  endif()
  set(OBF_CLANG_PLUGIN_PATH
    "${CMAKE_CURRENT_BINARY_DIR}/obf_plugin${LLVM_PLUGIN_EXT}")
endif()

add_executable(obf-driver
  tools/obf-driver/main.cpp)
obf_apply_static_llvm_target_settings(obf-driver)
llvm_update_compile_flags(obf-driver)
target_include_directories(obf-driver PRIVATE ${PROJECT_SOURCE_DIR}/include
                                              ${CMAKE_CURRENT_BINARY_DIR}/include)
target_link_libraries(obf-driver PRIVATE obf_core ${OBF_LLVM_LIBS})

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" OR WIN32)
  if(WIN32)
    set(OBF_CHECKSUM_BIND_SOURCE tools/obf-checksum-bind/pe_main.cpp)
  else()
    set(OBF_CHECKSUM_BIND_SOURCE tools/obf-checksum-bind/main.cpp)
  endif()
  add_executable(obf-checksum-bind
    ${OBF_CHECKSUM_BIND_SOURCE}
  )
  target_include_directories(obf-checksum-bind PRIVATE ${PROJECT_SOURCE_DIR}/include)
  set(OBF_CHECKSUM_BIND "${CMAKE_CURRENT_BINARY_DIR}/obf-checksum-bind${CMAKE_EXECUTABLE_SUFFIX}")
else()
  set(OBF_CHECKSUM_BIND "")
endif()

add_executable(obf-unit-tests
  tests/unit/obf_unit_tests.cpp
)
obf_apply_static_llvm_target_settings(obf-unit-tests)
llvm_update_compile_flags(obf-unit-tests)
target_include_directories(obf-unit-tests PRIVATE ${PROJECT_SOURCE_DIR}/include
                                                  ${CMAKE_CURRENT_BINARY_DIR}/include)
target_link_libraries(obf-unit-tests PRIVATE obf_core ${OBF_LLVM_LIBS})

add_executable(obf-runtime-atomic-tests
  tests/unit/runtime_atomic_tests.c
)
obf_apply_static_llvm_target_settings(obf-runtime-atomic-tests)
set_target_properties(obf-runtime-atomic-tests PROPERTIES
  C_STANDARD 17
  C_STANDARD_REQUIRED ON
)
target_include_directories(obf-runtime-atomic-tests PRIVATE ${PROJECT_SOURCE_DIR}/include
                                                            ${CMAKE_CURRENT_BINARY_DIR}/include)

find_package(Threads REQUIRED)

add_executable(obf-runtime-decode-concurrency-tests
  tests/unit/runtime_decode_concurrency_tests.c
)
set_target_properties(obf-runtime-decode-concurrency-tests PROPERTIES
  C_STANDARD 17
  C_STANDARD_REQUIRED ON
)
target_include_directories(obf-runtime-decode-concurrency-tests PRIVATE
  ${PROJECT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_BINARY_DIR}/include)
target_link_libraries(obf-runtime-decode-concurrency-tests PRIVATE Threads::Threads)

add_executable(obf-mba-lifetime-tests
  tests/unit/mba_lifetime_tests.cpp
)
obf_apply_static_llvm_target_settings(obf-mba-lifetime-tests)
llvm_update_compile_flags(obf-mba-lifetime-tests)
target_link_libraries(obf-mba-lifetime-tests PRIVATE obf_core ${OBF_LLVM_LIBS} Threads::Threads)
