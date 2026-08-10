set(OBF_ENTROPY_ANCHOR_LL "${CMAKE_CURRENT_BINARY_DIR}/obf_entropy_anchor.ll")
set(OBF_ENTROPY_ANCHOR_RANDOMIZED_LL "${CMAKE_CURRENT_BINARY_DIR}/obf_entropy_anchor.randomized.ll")
set(OBF_ENTROPY_ANCHOR_OBJ "${CMAKE_CURRENT_BINARY_DIR}/obf_entropy_anchor.o")
set(OBF_STRING_AUTH_RUNTIME_OBJ "${CMAKE_CURRENT_BINARY_DIR}/obf_string_auth_runtime.o")
add_custom_command(
  OUTPUT "${OBF_ENTROPY_ANCHOR_OBJ}"
  COMMAND "${OBF_CLANG}" -std=c17 -O0 -I${CMAKE_CURRENT_BINARY_DIR}/include -I${CMAKE_CURRENT_SOURCE_DIR}/include -S -emit-llvm "${CMAKE_CURRENT_SOURCE_DIR}/runtime/entropy_anchor.c" -o "${OBF_ENTROPY_ANCHOR_LL}"
  COMMAND "${OBF_OPT}" -load-pass-plugin "$<TARGET_FILE:obf_plugin>" "--obf-seed=${OBF_EFFECTIVE_BENCHMARK_SEED}" -passes=obf-entropy-init -S "${OBF_ENTROPY_ANCHOR_LL}" -o "${OBF_ENTROPY_ANCHOR_RANDOMIZED_LL}"
  COMMAND "${OBF_CLANG}" -c -fPIC "${OBF_ENTROPY_ANCHOR_RANDOMIZED_LL}" -o "${OBF_ENTROPY_ANCHOR_OBJ}"
  DEPENDS obf_plugin "${CMAKE_CURRENT_SOURCE_DIR}/runtime/entropy_anchor.c" "${CMAKE_CURRENT_SOURCE_DIR}/include/obf/support/blake2s_internal.h" "${CMAKE_CURRENT_BINARY_DIR}/include/obf/support/runtime_abi_generated.h" "${OBF_BENCHMARK_SEED_STAMP}"
  VERBATIM)
add_custom_command(
  OUTPUT "${OBF_STRING_AUTH_RUNTIME_OBJ}"
  COMMAND "${OBF_CLANG}" -std=c17 -O2 -I${CMAKE_CURRENT_BINARY_DIR}/include -I${CMAKE_CURRENT_SOURCE_DIR}/include -c -fPIC "${CMAKE_CURRENT_SOURCE_DIR}/runtime/string_auth_runtime.c" -o "${OBF_STRING_AUTH_RUNTIME_OBJ}"
  DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/runtime/string_auth_runtime.c" "${CMAKE_CURRENT_SOURCE_DIR}/include/obf/support/blake2s_internal.h" "${CMAKE_CURRENT_BINARY_DIR}/include/obf/support/runtime_abi_generated.h"
  VERBATIM)
add_custom_target(obf-entropy-anchor-runtime ALL DEPENDS "${OBF_ENTROPY_ANCHOR_OBJ}")
add_custom_target(obf-string-auth-runtime ALL DEPENDS "${OBF_STRING_AUTH_RUNTIME_OBJ}")
set(OBF_RUNTIME_ARCHIVE "${CMAKE_CURRENT_BINARY_DIR}/libobf_runtime.a")
add_custom_command(
  OUTPUT "${OBF_RUNTIME_ARCHIVE}"
  COMMAND "${CMAKE_COMMAND}" -E rm -f "${OBF_RUNTIME_ARCHIVE}"
  COMMAND "${CMAKE_AR}" qc "${OBF_RUNTIME_ARCHIVE}" "${OBF_ENTROPY_ANCHOR_OBJ}" "${OBF_STRING_AUTH_RUNTIME_OBJ}"
  COMMAND "${CMAKE_RANLIB}" "${OBF_RUNTIME_ARCHIVE}"
  DEPENDS "${OBF_ENTROPY_ANCHOR_OBJ}" "${OBF_STRING_AUTH_RUNTIME_OBJ}"
  VERBATIM)
add_custom_target(obf-runtime ALL DEPENDS "${OBF_RUNTIME_ARCHIVE}")
configure_file(
  tools/obf-clang/obf-clang.py.in
  "${CMAKE_CURRENT_BINARY_DIR}/obf-clang"
  @ONLY
  FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
configure_file(
  tools/obf-clang/obf-clang.py.in
  "${CMAKE_CURRENT_BINARY_DIR}/obf-clang++"
  @ONLY
  FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
add_custom_target(obf-clang-wrappers ALL
  DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/obf-clang" "${CMAKE_CURRENT_BINARY_DIR}/obf-clang++")
add_dependencies(obf-clang-wrappers obf_plugin obf-runtime)
configure_file(
  tools/obf-bc/obf-bc.py.in
  "${CMAKE_CURRENT_BINARY_DIR}/obf-bc"
  @ONLY
  FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
configure_file(
  tools/obf-rustc/obf-rustc.py.in
  "${CMAKE_CURRENT_BINARY_DIR}/obf-rustc"
  @ONLY
  FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
configure_file(
  tools/obf-tinygo/obf-tinygo.py.in
  "${CMAKE_CURRENT_BINARY_DIR}/obf-tinygo"
  @ONLY
  FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
add_custom_target(obf-language-tools ALL
  DEPENDS
    "${CMAKE_CURRENT_BINARY_DIR}/obf-bc"
    "${CMAKE_CURRENT_BINARY_DIR}/obf-rustc"
    "${CMAKE_CURRENT_BINARY_DIR}/obf-tinygo")
add_dependencies(obf-language-tools obf-driver obf_plugin obf-runtime)
