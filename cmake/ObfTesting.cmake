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

add_test(
  NAME obf-runtime-decode-concurrency-tests
  COMMAND obf-runtime-decode-concurrency-tests
)

add_test(
  NAME obf-mba-lifetime-tests
  COMMAND obf-mba-lifetime-tests
)
set_tests_properties(obf-runtime-decode-concurrency-tests obf-mba-lifetime-tests
  PROPERTIES TIMEOUT 120)
