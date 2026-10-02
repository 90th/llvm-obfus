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
