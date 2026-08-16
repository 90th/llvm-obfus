set(OBF_BENCHMARK_SEED "" CACHE STRING
  "Fixed benchmark obfuscation seed; empty uses a generated seed")

if(OBF_BENCHMARK_SEED STREQUAL "")
  if(NOT DEFINED CACHE{OBF_BENCHMARK_GENERATED_SEED})
    string(RANDOM LENGTH 1 ALPHABET "123456789" OBF_GENERATED_BENCHMARK_SEED_LEAD)
    string(RANDOM LENGTH 15 ALPHABET "0123456789" OBF_GENERATED_BENCHMARK_SEED_TAIL)
    set(OBF_BENCHMARK_GENERATED_SEED
      "${OBF_GENERATED_BENCHMARK_SEED_LEAD}${OBF_GENERATED_BENCHMARK_SEED_TAIL}"
      CACHE INTERNAL "Generated benchmark obfuscation seed")
  endif()
  set(OBF_EFFECTIVE_BENCHMARK_SEED "$CACHE{OBF_BENCHMARK_GENERATED_SEED}")
  set(OBF_BENCHMARK_SEED_SOURCE "generated")
else()
  if(NOT OBF_BENCHMARK_SEED MATCHES "^[1-9][0-9]*$")
    message(FATAL_ERROR
      "OBF_BENCHMARK_SEED must be a non-zero base-10 integer without leading zeroes")
  endif()
  set(OBF_EFFECTIVE_BENCHMARK_SEED "${OBF_BENCHMARK_SEED}")
  set(OBF_BENCHMARK_SEED_SOURCE "cache")
endif()

set(OBF_BENCHMARK_SEED_STAMP
  "${CMAKE_CURRENT_BINARY_DIR}/obf_benchmark_seed.txt")
file(GENERATE OUTPUT "${OBF_BENCHMARK_SEED_STAMP}"
  CONTENT "${OBF_EFFECTIVE_BENCHMARK_SEED}\n")

find_package(Python3 REQUIRED COMPONENTS Interpreter)
find_program(OBF_LIT lit REQUIRED)

if(WIN32)
  set(LLVM_ENABLE_PLUGINS ON CACHE BOOL "Enable LLVM pass plugins" FORCE)
  set(LLVM_ENABLE_PLUGINS ON)
endif()
find_package(LLVM REQUIRED CONFIG)
if(WIN32)
  set(LLVM_ENABLE_PLUGINS ON CACHE BOOL "Enable LLVM pass plugins" FORCE)
  set(LLVM_ENABLE_PLUGINS ON)
endif()
find_program(OBF_LLVM_AR NAMES llvm-ar ar HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
if(WIN32 AND TARGET LLVMDebugInfoPDB)
  get_target_property(_pdb_libs LLVMDebugInfoPDB INTERFACE_LINK_LIBRARIES)
  if(_pdb_libs)
    set(_updated_pdb_libs "")
    foreach(_lib IN LISTS _pdb_libs)
      if(_lib MATCHES "diaguids\\.lib" AND NOT EXISTS "${_lib}")
        find_file(OBF_DIAGUIDS_LIB NAMES diaguids.lib
          HINTS
            "$ENV{VSINSTALLDIR}/DIA SDK/lib/amd64"
            "C:/Program Files/Microsoft Visual Studio/2022/Community/DIA SDK/lib/amd64"
            "C:/Program Files/Microsoft Visual Studio/2022/Professional/DIA SDK/lib/amd64"
            "C:/Program Files/Microsoft Visual Studio/2022/BuildTools/DIA SDK/lib/amd64"
            "C:/Program Files/Microsoft Visual Studio/2022/Enterprise/DIA SDK/lib/amd64"
            "C:/Program Files (x86)/Microsoft Visual Studio/2019/Community/DIA SDK/lib/amd64"
            "C:/Program Files (x86)/Microsoft Visual Studio/2019/Professional/DIA SDK/lib/amd64"
            "C:/Program Files (x86)/Microsoft Visual Studio/2019/Enterprise/DIA SDK/lib/amd64"
            "C:/Program Files (x86)/Microsoft Visual Studio/2019/BuildTools/DIA SDK/lib/amd64"
        )
        if(OBF_DIAGUIDS_LIB)
          list(APPEND _updated_pdb_libs "${OBF_DIAGUIDS_LIB}")
        endif()
      else()
        list(APPEND _updated_pdb_libs "${_lib}")
      endif()
    endforeach()
    set_target_properties(LLVMDebugInfoPDB PROPERTIES
      INTERFACE_LINK_LIBRARIES "${_updated_pdb_libs}")
  endif()
endif()
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

llvm_map_components_to_libnames(OBF_LLVM_LIBS
  Analysis
  Core
  IRReader
  Passes
  Support
)
