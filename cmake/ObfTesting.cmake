enable_testing()

file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/tests")
configure_file(tests/lit.cfg.py.in
  "${CMAKE_CURRENT_BINARY_DIR}/tests/lit.cfg.py"
  @ONLY)

add_test(
  NAME obf-lit
  COMMAND "${OBF_LIT}" -j 3 -sv "${CMAKE_CURRENT_BINARY_DIR}/tests"
)

add_test(
  NAME obf-unit-tests
  COMMAND obf-unit-tests
)

add_test(
  NAME obf-runtime-atomic-tests
  COMMAND obf-runtime-atomic-tests
)

add_test(
  NAME obf-runtime-decode-concurrency-tests
  COMMAND obf-runtime-decode-concurrency-tests
)

foreach(kind IN ITEMS string constant)
  foreach(corruption IN ITEMS decoding-zero phase-corruption pending-tag)
    add_test(
      NAME "obf-runtime-decode-${kind}-${corruption}"
      COMMAND "${Python3_EXECUTABLE}"
              "${PROJECT_SOURCE_DIR}/tests/lit/Inputs/assert_trap_within.py"
              $<TARGET_FILE:obf-runtime-decode-concurrency-tests>
              --reject "${kind}" "${corruption}"
    )
  endforeach()
endforeach()

add_test(
  NAME obf-mba-lifetime-tests
  COMMAND obf-mba-lifetime-tests
)
set_tests_properties(obf-runtime-decode-concurrency-tests obf-mba-lifetime-tests
  PROPERTIES TIMEOUT 120)

if(OBF_PLUGIN_IS_LOADABLE AND (CMAKE_SYSTEM_NAME STREQUAL "Linux" OR WIN32))
  foreach(_obf_package_mode IN ITEMS install package)
    set(_obf_package_arguments "")
    if(_obf_package_mode STREQUAL "package")
      set(_obf_package_arguments --package --cpack "${CMAKE_CPACK_COMMAND}")
    endif()
    add_test(
      NAME obf-${_obf_package_mode}-consumer
      COMMAND "${Python3_EXECUTABLE}"
              "${PROJECT_SOURCE_DIR}/tests/lit/Inputs/install_consumer.py"
              --build "${CMAKE_CURRENT_BINARY_DIR}"
              --cmake "${CMAKE_COMMAND}"
              ${_obf_package_arguments}
              --bindir "${CMAKE_INSTALL_BINDIR}"
              --libdir "${CMAKE_INSTALL_LIBDIR}"
              --includedir "${CMAKE_INSTALL_INCLUDEDIR}"
              --forbid-root "${PROJECT_SOURCE_DIR}"
              --forbid-root "${CMAKE_CURRENT_BINARY_DIR}"
    )
    set_tests_properties(obf-${_obf_package_mode}-consumer
      PROPERTIES RUN_SERIAL TRUE TIMEOUT 600)
  endforeach()
endif()
