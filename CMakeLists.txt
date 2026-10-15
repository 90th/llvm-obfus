cmake_minimum_required(VERSION 3.24)

project(llvm-obfus LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
if(MSVC)
  add_compile_options(/EHsc /Zc:__cplusplus)
endif()

# Set this before LLVM imports GNUInstallDirs and selects a host-specific default.
if(NOT DEFINED CMAKE_INSTALL_LIBDIR)
  set(CMAKE_INSTALL_LIBDIR "lib" CACHE PATH "Object code libraries")
endif()

include(cmake/ObfToolchain.cmake)

# Installed artifacts must not retain paths into the project checkout.
set(OBF_CLANG_RELOCATABLE_COMPILE_OPTIONS
  "-ffile-prefix-map=${PROJECT_SOURCE_DIR}=."
  "-ffile-prefix-map=${PROJECT_BINARY_DIR}=.")
if(MSVC)
  if(CMAKE_C_COMPILER_ID MATCHES "Clang" AND CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    set(OBF_RELOCATABLE_COMPILE_OPTIONS
      "/clang:-ffile-prefix-map=${PROJECT_SOURCE_DIR}=."
      "/clang:-ffile-prefix-map=${PROJECT_BINARY_DIR}=.")
  else()
    set(OBF_RELOCATABLE_COMPILE_OPTIONS
      "/pathmap:${PROJECT_SOURCE_DIR}=."
      "/pathmap:${PROJECT_BINARY_DIR}=.")
  endif()
  add_link_options("/PDBALTPATH:%_PDB%")
elseif(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang"
    AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  set(OBF_RELOCATABLE_COMPILE_OPTIONS ${OBF_CLANG_RELOCATABLE_COMPILE_OPTIONS})
endif()
add_compile_options(${OBF_RELOCATABLE_COMPILE_OPTIONS})
include(cmake/ObfTargets.cmake)
include(cmake/ObfRuntime.cmake)
include(cmake/ObfInstall.cmake)
include(cmake/ObfTesting.cmake)
include(cmake/ObfBenchmarks.cmake)
include(cmake/ObfAnalysis.cmake)
