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

find_package(LLVM REQUIRED CONFIG)
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
set(OBF_WINDOWS_RUST_LLVM_HOST_BOUND FALSE)
if(NOT WIN32)
  set(OBF_WINDOWS_RUST_LLVM_HOST_IMAGE "")
  set(OBF_WINDOWS_RUST_LLVM_HOST_IMPORT_LIBRARY "")
  set(OBF_WINDOWS_RUST_LLVM_HOST_RUSTC "")
endif()
set(OBF_WINDOWS_RUST_LLVM_HOST_IMAGE_SHA256 "")
set(OBF_WINDOWS_RUST_LLVM_HOST_IMPORT_LIBRARY_SHA256 "")
set(OBF_WINDOWS_RUST_LLVM_HOST_RUSTC_SHA256 "")
set(OBF_WINDOWS_RUST_LLVM_HOST_RUSTC_RELEASE "")
set(OBF_WINDOWS_RUST_LLVM_HOST_RUSTC_HOST "")
set(OBF_WINDOWS_RUST_LLVM_HOST_RUSTC_COMMIT_HASH "")
set(OBF_WINDOWS_RUST_LLVM_HOST_RUSTC_COMMIT_DATE "")
set(OBF_WINDOWS_RUST_LLVM_HOST_RUSTC_LLVM_VERSION "")

if(WIN32)
  set(OBF_WINDOWS_PLUGIN_HOST_ROOT "" CACHE PATH
    "Root directory containing exported opt.exe/clang.exe pass-plugin hosts and import libraries")
  set(OBF_WINDOWS_PLUGIN_HOST_CONFIGURATION_HINT
    "Set -DOBF_WINDOWS_PLUGIN_HOST_ROOT=<host-build-root> or provide explicit host paths:\n  -DOBF_OPT=.../opt.exe\n  -DOBF_OPT_IMPORT_LIBRARY=.../opt.lib\n  -DOBF_CLANG=.../clang.exe\n  -DOBF_CLANG_IMPORT_LIBRARY=.../clang.lib")
  set(OBF_WINDOWS_RUST_LLVM_HOST_IMAGE "" CACHE FILEPATH
    "Absolute path to the Windows rustc_driver DLL that owns LLVM exports for rustc -Zllvm-plugins")
  set(OBF_WINDOWS_RUST_LLVM_HOST_IMPORT_LIBRARY "" CACHE FILEPATH
    "Absolute path to the import library matching OBF_WINDOWS_RUST_LLVM_HOST_IMAGE")
  set(OBF_WINDOWS_RUST_LLVM_HOST_RUSTC "" CACHE FILEPATH
    "Absolute path to the rustc executable bound to OBF_WINDOWS_RUST_LLVM_HOST_IMAGE")
  set(OBF_WINDOWS_RUST_LLVM_HOST_CONFIGURATION_HINT
    "To enable active Rust support on Windows, provide canonical absolute paths for:\n  -DOBF_WINDOWS_RUST_LLVM_HOST_IMAGE=.../rustc_driver-*.dll\n  -DOBF_WINDOWS_RUST_LLVM_HOST_IMPORT_LIBRARY=.../*.lib\n  -DOBF_WINDOWS_RUST_LLVM_HOST_RUSTC=.../rustc.exe")
  set(_obf_windows_plugin_host_bin_hints "")
  set(_obf_windows_plugin_host_lib_hints "")
  if(OBF_WINDOWS_PLUGIN_HOST_ROOT)
    list(APPEND _obf_windows_plugin_host_bin_hints
      "${OBF_WINDOWS_PLUGIN_HOST_ROOT}/bin")
    list(APPEND _obf_windows_plugin_host_lib_hints
      "${OBF_WINDOWS_PLUGIN_HOST_ROOT}/lib"
      "${OBF_WINDOWS_PLUGIN_HOST_ROOT}/lib64"
      "${OBF_WINDOWS_PLUGIN_HOST_ROOT}/bin")
  endif()
  foreach(_obf_windows_plugin_host_var IN ITEMS OBF_OPT OBF_CLANG)
    if(DEFINED ${_obf_windows_plugin_host_var}
        AND NOT "${${_obf_windows_plugin_host_var}}" STREQUAL "")
      get_filename_component(_obf_windows_plugin_host_bin_dir
        "${${_obf_windows_plugin_host_var}}" DIRECTORY)
      if(EXISTS "${_obf_windows_plugin_host_bin_dir}")
        list(APPEND _obf_windows_plugin_host_bin_hints
          "${_obf_windows_plugin_host_bin_dir}")
        get_filename_component(_obf_windows_plugin_host_root_dir
          "${_obf_windows_plugin_host_bin_dir}" DIRECTORY)
        list(APPEND _obf_windows_plugin_host_lib_hints
          "${_obf_windows_plugin_host_root_dir}/lib"
          "${_obf_windows_plugin_host_root_dir}/lib64"
          "${_obf_windows_plugin_host_bin_dir}")
      endif()
    endif()
  endforeach()
  list(REMOVE_DUPLICATES _obf_windows_plugin_host_bin_hints)
  list(REMOVE_DUPLICATES _obf_windows_plugin_host_lib_hints)

  function(obf_require_windows_plugin_host executable_var expected_executable
      import_library_var expected_import_library)
    if(NOT DEFINED ${executable_var}
        OR "${${executable_var}}" STREQUAL ""
        OR NOT EXISTS "${${executable_var}}")
      message(FATAL_ERROR
        "Windows pass-plugin builds require ${executable_var} to point to ${expected_executable}.\n${OBF_WINDOWS_PLUGIN_HOST_CONFIGURATION_HINT}")
    endif()

    get_filename_component(_obf_host_executable_name "${${executable_var}}" NAME)
    string(TOLOWER "${_obf_host_executable_name}" _obf_host_executable_name_lower)
    string(TOLOWER "${expected_executable}" _obf_expected_executable_name_lower)
    if(NOT _obf_host_executable_name_lower STREQUAL _obf_expected_executable_name_lower)
      message(FATAL_ERROR
        "${executable_var} must point to the canonical ${expected_executable} pass-plugin host, not ${_obf_host_executable_name}.\n${OBF_WINDOWS_PLUGIN_HOST_CONFIGURATION_HINT}")
    endif()

    if(NOT DEFINED ${import_library_var}
        OR "${${import_library_var}}" STREQUAL ""
        OR NOT EXISTS "${${import_library_var}}")
      message(FATAL_ERROR
        "Windows pass-plugin builds require ${import_library_var} to point to ${expected_import_library} matching ${${executable_var}}.\n${OBF_WINDOWS_PLUGIN_HOST_CONFIGURATION_HINT}")
    endif()

    get_filename_component(_obf_host_import_library_name "${${import_library_var}}" NAME)
    string(TOLOWER "${_obf_host_import_library_name}" _obf_host_import_library_name_lower)
    string(TOLOWER "${expected_import_library}" _obf_expected_import_library_name_lower)
    if(NOT _obf_host_import_library_name_lower STREQUAL _obf_expected_import_library_name_lower)
      message(FATAL_ERROR
        "${import_library_var} must point to ${expected_import_library}, not ${_obf_host_import_library_name}.\n${OBF_WINDOWS_PLUGIN_HOST_CONFIGURATION_HINT}")
    endif()
  endfunction()
  function(obf_require_windows_rust_host_file input_var description output_var)
    set(_obf_windows_rust_host_value "${${input_var}}")
    if(_obf_windows_rust_host_value STREQUAL "")
      message(FATAL_ERROR
        "Windows Rust active support requires ${input_var} to point to ${description}.\n${OBF_WINDOWS_RUST_LLVM_HOST_CONFIGURATION_HINT}")
    endif()
    if(NOT IS_ABSOLUTE "${_obf_windows_rust_host_value}")
      message(FATAL_ERROR
        "${input_var} must be a canonical absolute path to ${description}, not ${_obf_windows_rust_host_value}.\n${OBF_WINDOWS_RUST_LLVM_HOST_CONFIGURATION_HINT}")
    endif()
    if(NOT EXISTS "${_obf_windows_rust_host_value}")
      message(FATAL_ERROR
        "${input_var} must point to an existing ${description}, not ${_obf_windows_rust_host_value}.\n${OBF_WINDOWS_RUST_LLVM_HOST_CONFIGURATION_HINT}")
    endif()
    file(REAL_PATH "${_obf_windows_rust_host_value}" _obf_windows_rust_host_file)
    set(${output_var} "${_obf_windows_rust_host_file}" PARENT_SCOPE)
  endfunction()

  find_program(OBF_OPT NAMES opt.exe opt
    HINTS ${_obf_windows_plugin_host_bin_hints} "${LLVM_TOOLS_BINARY_DIR}"
    NO_DEFAULT_PATH
    REQUIRED)
  find_program(OBF_CLANG NAMES clang.exe clang
    HINTS ${_obf_windows_plugin_host_bin_hints} "${LLVM_TOOLS_BINARY_DIR}"
    NO_DEFAULT_PATH
    REQUIRED)
  find_program(OBF_CLANGXX NAMES clang++.exe clang++
    HINTS "${LLVM_TOOLS_BINARY_DIR}"
    NO_DEFAULT_PATH
    REQUIRED)
  foreach(_obf_windows_plugin_host_executable IN ITEMS "${OBF_OPT}" "${OBF_CLANG}")
    get_filename_component(_obf_windows_plugin_host_bin_dir
      "${_obf_windows_plugin_host_executable}" DIRECTORY)
    get_filename_component(_obf_windows_plugin_host_root_dir
      "${_obf_windows_plugin_host_bin_dir}" DIRECTORY)
    list(APPEND _obf_windows_plugin_host_lib_hints
      "${_obf_windows_plugin_host_root_dir}/lib"
      "${_obf_windows_plugin_host_root_dir}/lib64"
      "${_obf_windows_plugin_host_bin_dir}")
  endforeach()
  list(REMOVE_DUPLICATES _obf_windows_plugin_host_lib_hints)
  find_file(OBF_OPT_IMPORT_LIBRARY
    NAMES opt.lib
    HINTS ${_obf_windows_plugin_host_lib_hints}
    NO_DEFAULT_PATH
    DOC "Import library paired with OBF_OPT for Windows pass-plugin hosts")
  find_file(OBF_CLANG_IMPORT_LIBRARY
    NAMES clang.lib
    HINTS ${_obf_windows_plugin_host_lib_hints}
    NO_DEFAULT_PATH
    DOC "Import library paired with OBF_CLANG for Windows pass-plugin hosts")
  obf_require_windows_plugin_host(OBF_OPT "opt.exe" OBF_OPT_IMPORT_LIBRARY "opt.lib")
  obf_require_windows_plugin_host(OBF_CLANG "clang.exe" OBF_CLANG_IMPORT_LIBRARY "clang.lib")
else()
  find_program(OBF_OPT opt HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
  find_program(OBF_CLANG clang HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
  find_program(OBF_CLANGXX clang++ HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
endif()
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
set(OBF_WINDOWS_RUST_LLVM_HOST_BOUND FALSE)
if(WIN32)
  set(_obf_windows_rust_host_any OFF)
  set(_obf_windows_rust_host_all ON)
  foreach(_obf_windows_rust_host_var IN ITEMS
      OBF_WINDOWS_RUST_LLVM_HOST_IMAGE
      OBF_WINDOWS_RUST_LLVM_HOST_IMPORT_LIBRARY
      OBF_WINDOWS_RUST_LLVM_HOST_RUSTC)
    if("${${_obf_windows_rust_host_var}}" STREQUAL "")
      set(_obf_windows_rust_host_all OFF)
    else()
      set(_obf_windows_rust_host_any ON)
    endif()
  endforeach()

  if(_obf_windows_rust_host_any AND NOT _obf_windows_rust_host_all)
    message(FATAL_ERROR
      "Windows Rust active support requires all of OBF_WINDOWS_RUST_LLVM_HOST_IMAGE, OBF_WINDOWS_RUST_LLVM_HOST_IMPORT_LIBRARY, and OBF_WINDOWS_RUST_LLVM_HOST_RUSTC together, or none of them.\n${OBF_WINDOWS_RUST_LLVM_HOST_CONFIGURATION_HINT}")
  endif()

  if(_obf_windows_rust_host_all)
    obf_require_windows_rust_host_file(
      OBF_WINDOWS_RUST_LLVM_HOST_IMAGE
      "the Rust LLVM owner DLL"
      _obf_windows_rust_host_image)
    obf_require_windows_rust_host_file(
      OBF_WINDOWS_RUST_LLVM_HOST_IMPORT_LIBRARY
      "the Rust LLVM owner import library"
      _obf_windows_rust_host_import_library)
    obf_require_windows_rust_host_file(
      OBF_WINDOWS_RUST_LLVM_HOST_RUSTC
      "the bound rustc.exe compiler"
      _obf_windows_rust_host_rustc)
    execute_process(
      COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tools/obf-windows-hosts/verify_rust_host.py"
        --rustc "${_obf_windows_rust_host_rustc}"
        --image "${_obf_windows_rust_host_image}"
        --import-library "${_obf_windows_rust_host_import_library}"
        --llvm-version "${LLVM_PACKAGE_VERSION}"
      RESULT_VARIABLE _obf_rust_verify_status
      OUTPUT_VARIABLE _obf_rust_verify_stdout
      ERROR_VARIABLE _obf_rust_verify_stderr
    )
    if(NOT _obf_rust_verify_status EQUAL 0)
      string(STRIP "${_obf_rust_verify_stderr}" _obf_rust_verify_err)
      string(STRIP "${_obf_rust_verify_stdout}" _obf_rust_verify_out)
      message(FATAL_ERROR
        "Windows Rust LLVM host verification failed:\n${_obf_rust_verify_err}\n${_obf_rust_verify_out}\n${OBF_WINDOWS_RUST_LLVM_HOST_CONFIGURATION_HINT}")
    endif()

    string(JSON OBF_WINDOWS_RUST_LLVM_HOST_IMAGE_SHA256 GET "${_obf_rust_verify_stdout}" "image_sha256")
    string(JSON OBF_WINDOWS_RUST_LLVM_HOST_IMPORT_LIBRARY_SHA256 GET "${_obf_rust_verify_stdout}" "import_library_sha256")
    string(JSON OBF_WINDOWS_RUST_LLVM_HOST_RUSTC_SHA256 GET "${_obf_rust_verify_stdout}" "rustc_sha256")
    string(JSON OBF_WINDOWS_RUST_LLVM_HOST_RUSTC_RELEASE GET "${_obf_rust_verify_stdout}" "version" "release")
    string(JSON OBF_WINDOWS_RUST_LLVM_HOST_RUSTC_HOST GET "${_obf_rust_verify_stdout}" "version" "host")
    string(JSON OBF_WINDOWS_RUST_LLVM_HOST_RUSTC_COMMIT_HASH GET "${_obf_rust_verify_stdout}" "version" "commit-hash")
    string(JSON OBF_WINDOWS_RUST_LLVM_HOST_RUSTC_COMMIT_DATE GET "${_obf_rust_verify_stdout}" "version" "commit-date")
    string(JSON OBF_WINDOWS_RUST_LLVM_HOST_RUSTC_LLVM_VERSION GET "${_obf_rust_verify_stdout}" "version" "LLVM version")
    set(OBF_WINDOWS_RUST_LLVM_HOST_IMAGE "${_obf_windows_rust_host_image}" CACHE FILEPATH
      "Absolute path to the Windows rustc_driver DLL that owns LLVM exports for rustc -Zllvm-plugins" FORCE)
    set(OBF_WINDOWS_RUST_LLVM_HOST_IMPORT_LIBRARY "${_obf_windows_rust_host_import_library}" CACHE FILEPATH
      "Absolute path to the import library matching OBF_WINDOWS_RUST_LLVM_HOST_IMAGE" FORCE)
    set(OBF_WINDOWS_RUST_LLVM_HOST_RUSTC "${_obf_windows_rust_host_rustc}" CACHE FILEPATH
      "Absolute path to the rustc executable bound to OBF_WINDOWS_RUST_LLVM_HOST_IMAGE" FORCE)
    set(OBF_RUSTC_COMMAND "${OBF_WINDOWS_RUST_LLVM_HOST_RUSTC}")
    set(OBF_WINDOWS_RUST_LLVM_HOST_BOUND TRUE)
  endif()
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
set(OBF_RUSTC_HOST "")
if(OBF_RUSTC_VERSION_OUTPUT MATCHES "host:[ \t]*([^ \t\r\n]+)")
  set(OBF_RUSTC_HOST "${CMAKE_MATCH_1}")
endif()
set(OBF_RUSTC_COMMIT_HASH "")
if(OBF_RUSTC_VERSION_OUTPUT MATCHES "commit-hash:[ \t]*([^ \t\r\n]+)")
  set(OBF_RUSTC_COMMIT_HASH "${CMAKE_MATCH_1}")
endif()
set(OBF_RUSTC_COMMIT_DATE "")
if(OBF_RUSTC_VERSION_OUTPUT MATCHES "commit-date:[ \t]*([^ \t\r\n]+)")
  set(OBF_RUSTC_COMMIT_DATE "${CMAKE_MATCH_1}")
endif()
set(OBF_RUSTC_LLVM_VERSION "")
if(OBF_RUSTC_VERSION_OUTPUT MATCHES "LLVM version:[ \t]*([^ \t\r\n]+)")
  set(OBF_RUSTC_LLVM_VERSION "${CMAKE_MATCH_1}")
endif()

if(WIN32 AND OBF_WINDOWS_RUST_LLVM_HOST_BOUND)
  if(NOT OBF_RUSTC_VERSION_STATUS EQUAL 0)
    message(FATAL_ERROR
      "Windows Rust active support requires querying OBF_WINDOWS_RUST_LLVM_HOST_RUSTC with -Vv.\n${OBF_WINDOWS_RUST_LLVM_HOST_CONFIGURATION_HINT}")
  endif()
  foreach(_obf_windows_rust_required_var IN ITEMS
      OBF_RUSTC_RELEASE
      OBF_RUSTC_HOST
      OBF_RUSTC_COMMIT_HASH
      OBF_RUSTC_LLVM_VERSION)
    if("${${_obf_windows_rust_required_var}}" STREQUAL "")
      message(FATAL_ERROR
        "Windows Rust active support requires ${_obf_windows_rust_required_var} in rustc -Vv output for ${OBF_WINDOWS_RUST_LLVM_HOST_RUSTC}.")
    endif()
  endforeach()
  if(NOT OBF_RUSTC_RELEASE MATCHES "(^|[-.])(nightly|dev)([-.]|$)")
    message(FATAL_ERROR
      "Windows Rust active support requires a nightly or dev OBF_WINDOWS_RUST_LLVM_HOST_RUSTC, not ${OBF_RUSTC_RELEASE}.")
  endif()
  set(OBF_WINDOWS_RUST_LLVM_HOST_RUSTC_RELEASE "${OBF_RUSTC_RELEASE}")
  set(OBF_WINDOWS_RUST_LLVM_HOST_RUSTC_HOST "${OBF_RUSTC_HOST}")
  set(OBF_WINDOWS_RUST_LLVM_HOST_RUSTC_COMMIT_HASH "${OBF_RUSTC_COMMIT_HASH}")
  set(OBF_WINDOWS_RUST_LLVM_HOST_RUSTC_COMMIT_DATE "${OBF_RUSTC_COMMIT_DATE}")
  set(OBF_WINDOWS_RUST_LLVM_HOST_RUSTC_LLVM_VERSION "${OBF_RUSTC_LLVM_VERSION}")
endif()

if(OBF_RUSTC_VERSION_STATUS EQUAL 0
    AND OBF_CARGO
    AND NOT OBF_PROJECT_LLVM_MAJOR_MINOR STREQUAL ""
    AND OBF_RUSTC_LLVM_MAJOR_MINOR STREQUAL OBF_PROJECT_LLVM_MAJOR_MINOR
    AND OBF_RUSTC_RELEASE MATCHES "(^|[-.])(nightly|dev)([-.]|$)"
    AND (NOT WIN32 OR OBF_WINDOWS_RUST_LLVM_HOST_BOUND))
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
if((CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux"
      AND OBF_LLVM_HOST_TRIPLE_LOWER MATCHES "linux")
    OR (WIN32
      AND OBF_LLVM_HOST_TRIPLE_LOWER MATCHES "windows"))
  if(OBF_ZIG_VERSION_STATUS EQUAL 0
      AND OBF_ZIG_VERSION_OUTPUT MATCHES "(^|[\r\n])[ \t]*0\.16\.[0-9]+([-+][^\r\n]*)?([\r\n]|$)")
    set(OBF_HAS_ZIG_BENCHMARK_TOOLCHAIN ON)
  endif()
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
  message(STATUS "Rust corpus benchmark disabled: requires Cargo plus a nightly or dev rustc with matching LLVM")
endif()

if(OBF_HAS_ZIG_BENCHMARK_TOOLCHAIN)
  message(STATUS "Enabled Zig corpus benchmark")
else()
  message(STATUS "Zig corpus benchmark disabled: requires Zig 0.16.x on native Linux or Windows")
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
set(OBF_LLVM_PLUGIN_DEFINITIONS_LIST ${LLVM_DEFINITIONS_LIST})
set(OBF_LLVM_STATIC_DEFINITIONS_LIST ${LLVM_DEFINITIONS_LIST})
if(WIN32)
  list(FILTER OBF_LLVM_PLUGIN_DEFINITIONS_LIST EXCLUDE REGEX "^([/-]D)?LLVM_BUILD_STATIC($|=.*)")
  list(FILTER OBF_LLVM_STATIC_DEFINITIONS_LIST EXCLUDE REGEX "^([/-]D)?LLVM_BUILD_STATIC($|=.*)")
  list(APPEND OBF_LLVM_STATIC_DEFINITIONS_LIST LLVM_BUILD_STATIC)

  set(OBF_LLVM_HAS_EXPORT_ANNOTATIONS OFF)
  foreach(_obf_llvm_include_dir IN LISTS LLVM_INCLUDE_DIRS)
    if(EXISTS "${_obf_llvm_include_dir}/llvm/Support/Compiler.h")
      file(STRINGS "${_obf_llvm_include_dir}/llvm/Support/Compiler.h"
        _obf_llvm_export_annotation_lines
        REGEX "defined\\(LLVM_ENABLE_LLVM_EXPORT_ANNOTATIONS\\)")
      if(_obf_llvm_export_annotation_lines)
        set(OBF_LLVM_HAS_EXPORT_ANNOTATIONS ON)
      endif()
    endif()
    if(OBF_LLVM_HAS_EXPORT_ANNOTATIONS)
      break()
    endif()
  endforeach()
  if(NOT OBF_LLVM_HAS_EXPORT_ANNOTATIONS)
    message(FATAL_ERROR
      "Windows pass-plugin builds require LLVM headers with LLVM_ENABLE_LLVM_EXPORT_ANNOTATIONS support to import LLVM data from the host executable. Update the Windows LLVM SDK.")
  endif()
  list(APPEND OBF_LLVM_PLUGIN_DEFINITIONS_LIST LLVM_ENABLE_LLVM_EXPORT_ANNOTATIONS)

  # The imported LLVM package may report LLVM_ENABLE_PLUGINS=OFF even though an
  # external opt.exe/clang.exe pair exports the required symbols through the
  # validated import libraries above.  Use LLVM's PLUGIN_TOOL path instead of
  # forcing LLVM_ENABLE_PLUGINS.
  set(LLVM_EXPORT_SYMBOLS_FOR_PLUGINS ON)
endif()

llvm_map_components_to_libnames(OBF_LLVM_LIBS
  Analysis
  BitReader
  Core
  IRReader
  Object
  Passes
  Support
)
