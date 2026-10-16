include(GNUInstallDirs)

foreach(_obf_install_dir IN ITEMS CMAKE_INSTALL_BINDIR CMAKE_INSTALL_LIBDIR
    CMAKE_INSTALL_INCLUDEDIR CMAKE_INSTALL_LIBEXECDIR CMAKE_INSTALL_DATADIR)
  set(_obf_dir "${${_obf_install_dir}}")
  cmake_path(IS_ABSOLUTE _obf_dir _obf_absolute)
  cmake_path(NORMAL_PATH _obf_dir OUTPUT_VARIABLE _obf_normal_dir)
  if(_obf_absolute OR _obf_dir MATCHES "^[A-Za-z]:"
      OR _obf_normal_dir STREQUAL ""
      OR _obf_normal_dir MATCHES "^\\.\\.(/|$)"
      OR _obf_dir MATCHES "[\\\\;\n\r]")
    message(FATAL_ERROR
      "${_obf_install_dir} must be a nonempty relative path inside the installation prefix: ${_obf_dir}")
  endif()
  set(${_obf_install_dir} "${_obf_normal_dir}")
endforeach()

# The standalone package needs a loadable host plugin and native loader support.
if(NOT OBF_PLUGIN_IS_LOADABLE)
  return()
endif()
if(NOT WIN32 AND NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(STATUS "Standalone toolchain installation is available on Linux and Windows")
  return()
endif()

set(_obf_relative_root "${PROJECT_BINARY_DIR}/obf-install-prefix")
file(RELATIVE_PATH _obf_bin_to_lib
  "${_obf_relative_root}/${CMAKE_INSTALL_BINDIR}" "${_obf_relative_root}/${CMAKE_INSTALL_LIBDIR}")
file(RELATIVE_PATH _obf_bin_to_include
  "${_obf_relative_root}/${CMAKE_INSTALL_BINDIR}" "${_obf_relative_root}/${CMAKE_INSTALL_INCLUDEDIR}")

set(_obf_install_helpers obf-driver obf-native-link)
if(TARGET obf-checksum-bind)
  list(APPEND _obf_install_helpers obf-checksum-bind)
endif()
set(_obf_install_plugins obf_plugin)
if(TARGET obf_clang_plugin)
  list(APPEND _obf_install_plugins obf_clang_plugin)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  foreach(_obf_target IN LISTS _obf_install_helpers)
    set_target_properties(${_obf_target} PROPERTIES
      INSTALL_RPATH "$ORIGIN/${_obf_bin_to_lib}"
      INSTALL_RPATH_USE_LINK_PATH FALSE
      INSTALL_REMOVE_ENVIRONMENT_RPATH TRUE)
  endforeach()
  foreach(_obf_target IN LISTS _obf_install_plugins)
    set_target_properties(${_obf_target} PROPERTIES
      INSTALL_RPATH "$ORIGIN"
      INSTALL_RPATH_USE_LINK_PATH FALSE
      INSTALL_REMOVE_ENVIRONMENT_RPATH TRUE)
  endforeach()
endif()

install(TARGETS ${_obf_install_helpers}
  RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(TARGETS ${_obf_install_plugins}
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  RUNTIME DESTINATION "${CMAKE_INSTALL_LIBDIR}")

if(WIN32)
  set(OBF_INSTALLED_RUNTIME_NAME "obf_runtime.lib")
  set(OBF_INSTALLED_CLANG_PLUGIN_NAME "obf_clang_plugin${LLVM_PLUGIN_EXT}")
else()
  set(OBF_INSTALLED_RUNTIME_NAME "libobf_runtime.a")
  set(OBF_INSTALLED_CLANG_PLUGIN_NAME "obf_plugin${LLVM_PLUGIN_EXT}")
endif()
install(FILES "${OBF_RUNTIME_ARCHIVE}"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}" RENAME "${OBF_INSTALLED_RUNTIME_NAME}")
install(DIRECTORY "${PROJECT_SOURCE_DIR}/include/"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
  FILES_MATCHING PATTERN "*.h")
install(DIRECTORY "${PROJECT_BINARY_DIR}/include/"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
  FILES_MATCHING PATTERN "*.h")
install(FILES "${PROJECT_SOURCE_DIR}/LICENSE"
  DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/llvm-obfus")

execute_process(COMMAND "${OBF_CLANG}" --print-resource-dir
  OUTPUT_VARIABLE OBF_CLANG_RESOURCE_DIR
  ERROR_VARIABLE _obf_resource_error
  RESULT_VARIABLE _obf_resource_result
  OUTPUT_STRIP_TRAILING_WHITESPACE)
file(TO_CMAKE_PATH "${OBF_CLANG_RESOURCE_DIR}" OBF_CLANG_RESOURCE_DIR)
if(NOT _obf_resource_result EQUAL 0 OR NOT IS_DIRECTORY "${OBF_CLANG_RESOURCE_DIR}")
  message(FATAL_ERROR
    "Cannot locate resources for configured Clang ${OBF_CLANG}: ${_obf_resource_error}")
endif()
cmake_path(GET OBF_CLANG_RESOURCE_DIR FILENAME _obf_resource_version)
set(OBF_INSTALL_CLANG_RESOURCE_DIR "${CMAKE_INSTALL_LIBDIR}/clang/${_obf_resource_version}")
install(DIRECTORY "${OBF_CLANG_RESOURCE_DIR}/"
  DESTINATION "${OBF_INSTALL_CLANG_RESOURCE_DIR}")

function(obf_install_llvm_host source name output)
  if(WIN32)
    install(PROGRAMS "${source}" DESTINATION "${CMAKE_INSTALL_BINDIR}"
      RENAME "${name}${CMAKE_EXECUTABLE_SUFFIX}")
    set(${output} "${name}${CMAKE_EXECUTABLE_SUFFIX}" PARENT_SCOPE)
  else()
    set(_obf_host_directory "${CMAKE_INSTALL_LIBEXECDIR}/llvm-obfus/${name}")
    install(PROGRAMS "${source}" DESTINATION "${_obf_host_directory}" RENAME "${name}")
    file(RELATIVE_PATH _obf_host_relative
      "${_obf_relative_root}/${CMAKE_INSTALL_BINDIR}"
      "${_obf_relative_root}/${_obf_host_directory}/${name}")
    obf_python_string(OBF_HOST_EXECUTABLE_RELATIVE "${_obf_host_relative}")
    obf_python_string(OBF_HOST_LIBRARY_RELATIVE "${_obf_bin_to_lib}")
    set(OBF_HOST_ARGUMENTS "[]")
    if(name STREQUAL "clang" OR name STREQUAL "clang++")
      file(RELATIVE_PATH _obf_host_resource
        "${_obf_relative_root}/${CMAKE_INSTALL_BINDIR}"
        "${_obf_relative_root}/${OBF_INSTALL_CLANG_RESOURCE_DIR}")
      obf_python_string(_obf_host_resource_literal "${_obf_host_resource}")
      set(OBF_HOST_ARGUMENTS
        "[\"-resource-dir\", str((bindir / ${_obf_host_resource_literal}).resolve())]")
    endif()
    configure_file("${CMAKE_CURRENT_FUNCTION_LIST_DIR}/ObfInstalledHost.py.in"
      "${PROJECT_BINARY_DIR}/install-hosts/${name}" @ONLY)
    install(PROGRAMS "${PROJECT_BINARY_DIR}/install-hosts/${name}"
      DESTINATION "${CMAKE_INSTALL_BINDIR}")
    set(${output} "${_obf_host_relative}" PARENT_SCOPE)
  endif()
endfunction()

# Resolve symlinks before copying, so packaged tools never point at their source.
file(REAL_PATH "${OBF_CLANG}" OBF_INSTALL_CLANG_SOURCE)
file(REAL_PATH "${OBF_OPT}" OBF_INSTALL_OPT_SOURCE)
set(OBF_INSTALL_HOST_SOURCES "${OBF_INSTALL_CLANG_SOURCE}" "${OBF_INSTALL_OPT_SOURCE}")
obf_install_llvm_host("${OBF_INSTALL_CLANG_SOURCE}" clang _obf_installed_clang)
obf_install_llvm_host("${OBF_INSTALL_OPT_SOURCE}" opt _obf_installed_opt)
if(WIN32)
  set(_obf_installed_clangxx "${_obf_installed_clang}")
else()
  file(REAL_PATH "${OBF_CLANGXX}" OBF_INSTALL_CLANGXX_SOURCE)
  list(APPEND OBF_INSTALL_HOST_SOURCES "${OBF_INSTALL_CLANGXX_SOURCE}")
  obf_install_llvm_host("${OBF_INSTALL_CLANGXX_SOURCE}" clang++ _obf_installed_clangxx)
endif()
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" OR WIN32)
  if(WIN32)
    set(_obf_linker_name "lld-link")
  else()
    set(_obf_linker_name "ld.lld")
  endif()
  # Match the wrapper's Clang-selected linker, not the optional OBF_LLD cache.
  execute_process(COMMAND "${OBF_CLANG}" "-print-prog-name=${_obf_linker_name}"
    WORKING_DIRECTORY "${PROJECT_BINARY_DIR}"
    OUTPUT_VARIABLE _obf_lld_report
    RESULT_VARIABLE _obf_lld_query_result
    ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)
  string(REGEX MATCH "[^\r\n]+$" _obf_lld_report "${_obf_lld_report}")
  file(TO_CMAKE_PATH "${_obf_lld_report}" _obf_lld_report)
  set(_obf_lld_candidate "")
  if(_obf_lld_query_result EQUAL 0 AND NOT _obf_lld_report STREQUAL "")
    if(IS_ABSOLUTE "${_obf_lld_report}")
      set(_obf_lld_candidate "${_obf_lld_report}")
    elseif(_obf_lld_report MATCHES "/")
      cmake_path(ABSOLUTE_PATH _obf_lld_report
        BASE_DIRECTORY "${PROJECT_BINARY_DIR}" OUTPUT_VARIABLE _obf_lld_candidate)
    else()
      find_program(_obf_lld_found NAMES "${_obf_lld_report}"
        PATHS ENV PATH NO_DEFAULT_PATH NO_CMAKE_FIND_ROOT_PATH NO_CACHE)
      if(_obf_lld_found)
        set(_obf_lld_candidate "${_obf_lld_found}")
      endif()
    endif()
  endif()
  if(WIN32 AND NOT _obf_lld_candidate STREQUAL ""
      AND NOT EXISTS "${_obf_lld_candidate}")
    string(APPEND _obf_lld_candidate ".exe")
  endif()
  if(EXISTS "${_obf_lld_candidate}" AND NOT IS_DIRECTORY "${_obf_lld_candidate}")
    execute_process(COMMAND "${OBF_CLANG}" --version
      OUTPUT_VARIABLE _obf_clang_version_stdout ERROR_VARIABLE _obf_clang_version_stderr
      RESULT_VARIABLE _obf_clang_version_result)
    execute_process(COMMAND "${_obf_lld_candidate}" --version
      OUTPUT_VARIABLE _obf_lld_version_stdout ERROR_VARIABLE _obf_lld_version_stderr
      RESULT_VARIABLE _obf_lld_version_result)
    string(REGEX MATCH "clang version ([0-9]+\\.[0-9]+(\\.[0-9]+)?)"
      _obf_clang_version_match "${_obf_clang_version_stdout}${_obf_clang_version_stderr}")
    set(_obf_clang_version "${CMAKE_MATCH_1}")
    string(REGEX MATCH "(^|[^A-Za-z0-9_])LLD ([0-9]+\\.[0-9]+(\\.[0-9]+)?)"
      _obf_lld_version_match "${_obf_lld_version_stdout}${_obf_lld_version_stderr}")
    set(_obf_lld_version "${CMAKE_MATCH_2}")
    if(_obf_clang_version_result EQUAL 0 AND _obf_lld_version_result EQUAL 0
        AND NOT _obf_clang_version STREQUAL "" AND _obf_clang_version STREQUAL _obf_lld_version)
      file(REAL_PATH "${_obf_lld_candidate}" OBF_INSTALL_LLD_SOURCE)
      obf_install_llvm_host("${OBF_INSTALL_LLD_SOURCE}" "${_obf_linker_name}" _obf_installed_lld)
      list(APPEND OBF_INSTALL_HOST_SOURCES "${OBF_INSTALL_LLD_SOURCE}")
    endif()
  endif()
endif()
list(REMOVE_DUPLICATES OBF_INSTALL_HOST_SOURCES)

# The same Python templates have distinct build-tree and installed settings.
set(_obf_build_wrapper_paths "${OBF_WRAPPER_PATHS}")
set(_obf_build_wrapper_shebang "${OBF_WRAPPER_SHEBANG}")
obf_python_string(OBF_WRAPPER_LIB_RELATIVE "${_obf_bin_to_lib}")
obf_python_string(OBF_WRAPPER_INCLUDE_RELATIVE "${_obf_bin_to_include}")
obf_python_string(OBF_WRAPPER_CLANG_RELATIVE "${_obf_installed_clang}")
obf_python_string(OBF_WRAPPER_CLANGXX_RELATIVE "${_obf_installed_clangxx}")
obf_python_string(OBF_WRAPPER_OPT_RELATIVE "${_obf_installed_opt}")
file(RELATIVE_PATH _obf_bin_to_resource
  "${_obf_relative_root}/${CMAKE_INSTALL_BINDIR}" "${_obf_relative_root}/${OBF_INSTALL_CLANG_RESOURCE_DIR}")
obf_python_string(OBF_WRAPPER_RESOURCE_RELATIVE "${_obf_bin_to_resource}")
configure_file("${CMAKE_CURRENT_LIST_DIR}/ObfInstalledWrapperPaths.py.in"
  "${PROJECT_BINARY_DIR}/cmake/ObfInstalledWrapperPaths.py" @ONLY)
file(READ "${PROJECT_BINARY_DIR}/cmake/ObfInstalledWrapperPaths.py" OBF_WRAPPER_PATHS)
set(OBF_WRAPPER_SHEBANG "/usr/bin/env python3")
set(OBF_INSTALL_WRAPPER_DIR "${PROJECT_BINARY_DIR}/install-tools")
foreach(_obf_wrapper IN ITEMS obf-clang obf-clang++ obf-opt)
  if(_obf_wrapper STREQUAL "obf-opt")
    set(_obf_wrapper_template "${PROJECT_SOURCE_DIR}/tools/obf-opt/obf-opt.py.in")
  else()
    set(_obf_wrapper_template "${PROJECT_SOURCE_DIR}/tools/obf-clang/obf-clang.py.in")
  endif()
  configure_file("${_obf_wrapper_template}" "${OBF_INSTALL_WRAPPER_DIR}/${_obf_wrapper}"
    @ONLY FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
  install(PROGRAMS "${OBF_INSTALL_WRAPPER_DIR}/${_obf_wrapper}"
    DESTINATION "${CMAKE_INSTALL_BINDIR}")
  if(WIN32)
    file(GENERATE OUTPUT "${OBF_INSTALL_WRAPPER_DIR}/${_obf_wrapper}.cmd"
      CONTENT "@echo off\r\npython \"%~dp0${_obf_wrapper}\" %*\r\n")
    install(PROGRAMS "${OBF_INSTALL_WRAPPER_DIR}/${_obf_wrapper}.cmd"
      DESTINATION "${CMAKE_INSTALL_BINDIR}")
  endif()
endforeach()
set(OBF_WRAPPER_PATHS "${_obf_build_wrapper_paths}")
set(OBF_WRAPPER_SHEBANG "${_obf_build_wrapper_shebang}")

set(OBF_INSTALL_DEPENDENCY_DIRS ${LLVM_LIBRARY_DIRS} "${LLVM_TOOLS_BINARY_DIR}")
foreach(_obf_host IN LISTS OBF_INSTALL_HOST_SOURCES)
  cmake_path(GET _obf_host PARENT_PATH _obf_host_dir)
  list(APPEND OBF_INSTALL_DEPENDENCY_DIRS "${_obf_host_dir}")
endforeach()
set(OBF_INSTALL_RUNTIME_EXECUTABLES ${OBF_INSTALL_HOST_SOURCES})
foreach(_obf_target IN LISTS _obf_install_helpers)
  list(APPEND OBF_INSTALL_RUNTIME_EXECUTABLES "$<TARGET_FILE:${_obf_target}>")
endforeach()
set(OBF_INSTALL_RUNTIME_MODULES "")
foreach(_obf_target IN LISTS _obf_install_plugins)
  list(APPEND OBF_INSTALL_RUNTIME_MODULES "$<TARGET_FILE:${_obf_target}>")
endforeach()
set(OBF_INSTALL_SYSTEM_RUNTIME_LIBS "")
if(WIN32)
  # Include the redistributable compiler runtime, not the Windows SDK or OS DLLs.
  set(CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS_SKIP TRUE)
  include(InstallRequiredSystemLibraries)
  set(OBF_INSTALL_SYSTEM_RUNTIME_LIBS ${CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS})
  foreach(_obf_runtime IN LISTS OBF_INSTALL_SYSTEM_RUNTIME_LIBS)
    cmake_path(GET _obf_runtime PARENT_PATH _obf_runtime_dir)
    list(APPEND OBF_INSTALL_DEPENDENCY_DIRS "${_obf_runtime_dir}")
  endforeach()
endif()
list(REMOVE_DUPLICATES OBF_INSTALL_DEPENDENCY_DIRS)

configure_file("${CMAKE_CURRENT_LIST_DIR}/ObfInstallRuntimeDeps.cmake.in"
  "${PROJECT_BINARY_DIR}/cmake/ObfInstallRuntimeDeps.cmake.in" @ONLY)
file(GENERATE OUTPUT "${PROJECT_BINARY_DIR}/cmake/ObfInstallRuntimeDeps-$<CONFIG>.cmake"
  INPUT "${PROJECT_BINARY_DIR}/cmake/ObfInstallRuntimeDeps.cmake.in")
install(SCRIPT "${PROJECT_BINARY_DIR}/cmake/ObfInstallRuntimeDeps-$<CONFIG>.cmake")

set(CPACK_PACKAGE_NAME "llvm-obfus")
set(CPACK_PACKAGE_VENDOR "llvm-obfus")
# No independent release version is declared; identify the matching LLVM toolchain.
set(CPACK_PACKAGE_VERSION "${LLVM_PACKAGE_VERSION}")
set(CPACK_PACKAGE_VERSION_MAJOR "${LLVM_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR "${LLVM_VERSION_MINOR}")
set(CPACK_PACKAGE_VERSION_PATCH "${LLVM_VERSION_PATCH}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Relocatable llvm-obfus C/C++ toolchain")
set(CPACK_RESOURCE_FILE_LICENSE "${PROJECT_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGE_RELOCATABLE TRUE)
set(CPACK_PACKAGING_INSTALL_PREFIX "/")
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY TRUE)
set(CPACK_SOURCE_GENERATOR "")
if(WIN32)
  set(CPACK_GENERATOR "ZIP")
else()
  set(CPACK_GENERATOR "TGZ")
endif()
set(CPACK_PACKAGE_FILE_NAME
  "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")
include(CPack)
