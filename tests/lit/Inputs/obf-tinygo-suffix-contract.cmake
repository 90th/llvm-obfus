cmake_minimum_required(VERSION 3.24)

foreach(_required IN ITEMS
    TEST_ROOT
    WRAPPER_TEMPLATE
    FAKE_TOOL
    PYTHON_EXECUTABLE
    TINYGO_CONFIG
    GO_SOURCE
    SIMULATED_EXECUTABLE_SUFFIX
    LLVM_HOST_TRIPLE)
  if(NOT DEFINED ${_required} OR "${${_required}}" STREQUAL "")
    message(FATAL_ERROR
      "obf-tinygo suffix contract: -D${_required}=... is required")
  endif()
endforeach()

foreach(_input IN ITEMS WRAPPER_TEMPLATE FAKE_TOOL PYTHON_EXECUTABLE TINYGO_CONFIG GO_SOURCE)
  if(NOT EXISTS "${${_input}}" OR IS_DIRECTORY "${${_input}}")
    message(FATAL_ERROR
      "obf-tinygo suffix contract: -D${_input} is not a file: ${${_input}}")
  endif()
endforeach()

file(REMOVE_RECURSE "${TEST_ROOT}")
file(MAKE_DIRECTORY "${TEST_ROOT}")
if(NOT IS_DIRECTORY "${TEST_ROOT}")
  message(FATAL_ERROR
    "obf-tinygo suffix contract: cannot create isolated test directory: ${TEST_ROOT}")
endif()

set(_configured_dir "${TEST_ROOT}/configured")
set(_scratch_dir "${TEST_ROOT}/scratch")
set(_wrapper "${_configured_dir}/obf-tinygo")
set(_obf_bc "${_configured_dir}/obf-bc")
set(_runtime_archive "${_configured_dir}/libobf_runtime.a")
set(_output "${TEST_ROOT}/program")
set(_fake_log "${TEST_ROOT}/fake-tools.log")
file(MAKE_DIRECTORY "${_configured_dir}" "${_scratch_dir}")

# This is a native-Linux wrapper contract. The synthetic suffix verifies only
# that configure_file does not append it to the obf-bc default.
set(Python3_EXECUTABLE "${PYTHON_EXECUTABLE}")
set(OBF_TINYGO_COMMAND "${FAKE_TOOL}")
set(OBF_LLC "${FAKE_TOOL}")
set(OBF_LLD_COMMAND "${FAKE_TOOL}")
set(OBF_LLD_DRIVER "fake-lld")
set(OBF_RUNTIME_ARCHIVE "${_runtime_archive}")
set(LLVM_PACKAGE_VERSION "21.1.8")
set(CMAKE_EXECUTABLE_SUFFIX "${SIMULATED_EXECUTABLE_SUFFIX}")
set(_original_current_binary_dir "${CMAKE_CURRENT_BINARY_DIR}")
set(CMAKE_CURRENT_BINARY_DIR "${_configured_dir}")
configure_file("${WRAPPER_TEMPLATE}" "${_wrapper}" @ONLY)
set(CMAKE_CURRENT_BINARY_DIR "${_original_current_binary_dir}")

if(NOT EXISTS "${_wrapper}")
  message(FATAL_ERROR
    "obf-tinygo suffix contract: configuring the wrapper did not produce ${_wrapper}")
endif()

file(WRITE "${_runtime_archive}" "fake runtime archive\n")
file(COPY_FILE "${FAKE_TOOL}" "${_obf_bc}")
file(CHMOD "${_obf_bc}"
  PERMISSIONS
    OWNER_READ OWNER_WRITE OWNER_EXECUTE
    GROUP_READ GROUP_EXECUTE
    WORLD_READ WORLD_EXECUTE)
if(NOT EXISTS "${_obf_bc}")
  message(FATAL_ERROR
    "obf-tinygo suffix contract: failed to install fake obf-bc at ${_obf_bc}")
endif()

set(ENV{TMPDIR} "${_scratch_dir}")
set(ENV{OBF_TINYGO_BIN} "${FAKE_TOOL}")
set(ENV{OBF_LLC_BIN} "${FAKE_TOOL}")
set(ENV{OBF_LLD_BIN} "${FAKE_TOOL}")
set(ENV{OBF_LLD_DRIVER} "fake-lld")
set(ENV{OBF_TINYGO_FAKE_MODE} "configured-lld")
set(ENV{OBF_TINYGO_FAKE_LOG} "${_fake_log}")
unset(ENV{OBF_BC_BIN})
unset(ENV{GOARCH})
unset(ENV{GOOS})

execute_process(
  COMMAND "${PYTHON_EXECUTABLE}" "${_wrapper}"
    "--obf-config=${TINYGO_CONFIG}"
    build
    -scheduler=none
    -gc=none
    -o "${_output}"
    "${GO_SOURCE}"
  RESULT_VARIABLE _wrapper_result
  OUTPUT_VARIABLE _wrapper_stdout
  ERROR_VARIABLE _wrapper_stderr)
if(NOT "${_wrapper_result}" STREQUAL "0")
  message(FATAL_ERROR
    "obf-tinygo suffix contract: configured wrapper failed with exit ${_wrapper_result}\n"
    "stdout:\n${_wrapper_stdout}\n"
    "stderr:\n${_wrapper_stderr}")
endif()

if(NOT EXISTS "${_output}" OR IS_DIRECTORY "${_output}")
  message(FATAL_ERROR
    "obf-tinygo suffix contract: wrapper succeeded without producing ${_output}")
endif()
file(SIZE "${_output}" _output_size)
if(_output_size EQUAL 0)
  message(FATAL_ERROR
    "obf-tinygo suffix contract: wrapper produced an empty output: ${_output}")
endif()

if(NOT EXISTS "${_fake_log}" OR IS_DIRECTORY "${_fake_log}")
  message(FATAL_ERROR
    "obf-tinygo suffix contract: fake tools did not produce a transform log: ${_fake_log}")
endif()
file(READ "${_fake_log}" _fake_log_contents)
string(FIND "${_fake_log_contents}" "\"role\": \"transform\"" _transform_index)
if(_transform_index EQUAL -1)
  message(FATAL_ERROR
    "obf-tinygo suffix contract: fake tools never ran obf-bc transform\n"
    "log:\n${_fake_log_contents}")
endif()
