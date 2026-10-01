cmake_minimum_required(VERSION 3.24)
project(ObfWindowsLLVMHosts LANGUAGES C CXX)

if(NOT WIN32 OR NOT MSVC)
  message(FATAL_ERROR "Build Windows LLVM hosts with MSVC or clang-cl from a Visual Studio developer shell.")
endif()
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(OBF_LLVM_PROJECT_SOURCE_DIR "" CACHE PATH "Matching llvm-project source tree containing llvm and clang")
if(NOT EXISTS "${OBF_LLVM_PROJECT_SOURCE_DIR}/llvm/tools/opt/opt.cpp" OR
   NOT EXISTS "${OBF_LLVM_PROJECT_SOURCE_DIR}/clang/tools/driver/driver.cpp")
  message(FATAL_ERROR "Set OBF_LLVM_PROJECT_SOURCE_DIR to llvm-project sources matching the installed SDK.")
endif()

find_package(LLVM REQUIRED CONFIG)
find_package(Clang REQUIRED CONFIG)
if(LLVM_PACKAGE_VERSION VERSION_LESS 22)
  message(FATAL_ERROR "Windows host imports require LLVM 22 or newer export annotations.")
endif()
find_package(Python3 REQUIRED COMPONENTS Interpreter)
list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
include(AddLLVM)
include(HandleLLVMOptions)

if(TARGET LLVMDebugInfoPDB)
  get_target_property(_pdb_libs LLVMDebugInfoPDB INTERFACE_LINK_LIBRARIES)
  set(_updated_pdb_libs "")
  foreach(_lib IN LISTS _pdb_libs)
    if(_lib MATCHES "diaguids\\.lib" AND NOT EXISTS "${_lib}")
      find_file(OBF_DIAGUIDS_LIB diaguids.lib HINTS
        "$ENV{VSINSTALLDIR}/DIA SDK/lib/amd64"
        "C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/DIA SDK/lib/amd64"
        REQUIRED)
      list(APPEND _updated_pdb_libs "${OBF_DIAGUIDS_LIB}")
    else()
      list(APPEND _updated_pdb_libs "${_lib}")
    endif()
  endforeach()
  set_target_properties(LLVMDebugInfoPDB PROPERTIES INTERFACE_LINK_LIBRARIES "${_updated_pdb_libs}")
endif()

set(LLVM_EXPORT_SYMBOLS_FOR_PLUGINS ON)
set(LLVM_MAIN_SRC_DIR "${OBF_LLVM_PROJECT_SOURCE_DIR}/llvm")
set(LLVM_LIBRARY_OUTPUT_INTDIR "${LLVM_LIBRARY_DIRS}")
set(LLVM_RUNTIME_OUTPUT_INTDIR "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
include_directories(SYSTEM ${LLVM_INCLUDE_DIRS} ${CLANG_INCLUDE_DIRS})
separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND "${LLVM_DEFINITIONS}")
add_compile_definitions(${LLVM_DEFINITIONS_LIST})

llvm_map_components_to_libnames(HOST_TARGET_LIBS
  AllTargetsCodeGens AllTargetsAsmParsers AllTargetsDescs AllTargetsInfos)
llvm_map_components_to_libnames(PASS_HOST_LIBS Analysis BitReader Core IRReader Object Passes Support)
add_library(llvm_api_exports OBJECT llvm-api-exports.cpp)
target_compile_definitions(llvm_api_exports PRIVATE LLVM_ENABLE_LLVM_EXPORT_ANNOTATIONS LLVM_EXPORTS)
llvm_update_compile_flags(llvm_api_exports)

add_llvm_executable(obf_export_opt
  "${LLVM_MAIN_SRC_DIR}/tools/opt/opt.cpp"
  $<TARGET_OBJECTS:llvm_api_exports>
  PARTIAL_SOURCES_INTENDED)
set_target_properties(obf_export_opt PROPERTIES
  OUTPUT_NAME opt ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
target_link_libraries(obf_export_opt PRIVATE LLVMOptDriver ${HOST_TARGET_LIBS})
export_executable_symbols(obf_export_opt)

set(TOOL_NAME clang)
configure_file("${LLVM_CMAKE_DIR}/llvm-driver-template.cpp.in"
  "${CMAKE_BINARY_DIR}/clang-driver.cpp" @ONLY)
add_llvm_executable(obf_export_clang
  "${OBF_LLVM_PROJECT_SOURCE_DIR}/clang/tools/driver/driver.cpp"
  "${OBF_LLVM_PROJECT_SOURCE_DIR}/clang/tools/driver/cc1_main.cpp"
  "${OBF_LLVM_PROJECT_SOURCE_DIR}/clang/tools/driver/cc1as_main.cpp"
  "${OBF_LLVM_PROJECT_SOURCE_DIR}/clang/tools/driver/cc1gen_reproducer_main.cpp"
  "${CMAKE_BINARY_DIR}/clang-driver.cpp"
  $<TARGET_OBJECTS:llvm_api_exports>
  PARTIAL_SOURCES_INTENDED)
set_target_properties(obf_export_clang PROPERTIES
  OUTPUT_NAME clang ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
target_link_libraries(obf_export_clang PRIVATE ${PASS_HOST_LIBS} ${HOST_TARGET_LIBS})
# Export LLVM's API, not Clang's AST API, to stay below PE's export-count limit.
export_executable_symbols(obf_export_clang)
target_link_libraries(obf_export_clang PRIVATE
  clangBasic clangCodeGen clangDriver clangFrontend clangFrontendTool clangOptions clangSerialization)

get_filename_component(_llvm_sdk_lib_dir "${LLVM_DIR}/../.." ABSOLUTE)
if(NOT EXISTS "${_llvm_sdk_lib_dir}/clang")
  message(FATAL_ERROR "The installed LLVM SDK must include its lib/clang resource directory.")
endif()
add_custom_command(TARGET obf_export_clang POST_BUILD
  COMMAND "${CMAKE_COMMAND}" -E copy_directory
    "${_llvm_sdk_lib_dir}/clang" "${CMAKE_BINARY_DIR}/lib/clang"
  VERBATIM)

add_llvm_executable(obf_llvm_filecheck
  "${LLVM_MAIN_SRC_DIR}/utils/FileCheck/FileCheck.cpp" PARTIAL_SOURCES_INTENDED)
set_target_properties(obf_llvm_filecheck PROPERTIES OUTPUT_NAME FileCheck)
target_link_libraries(obf_llvm_filecheck PRIVATE LLVMFileCheck LLVMSupport)

add_llvm_executable(obf_llvm_not
  "${LLVM_MAIN_SRC_DIR}/utils/not/not.cpp" PARTIAL_SOURCES_INTENDED)
set_target_properties(obf_llvm_not PROPERTIES OUTPUT_NAME not)
target_link_libraries(obf_llvm_not PRIVATE LLVMSupport)
