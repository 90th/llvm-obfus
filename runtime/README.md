# Runtime

The build creates `build/libobf_runtime.a` through the `obf-runtime` CMake target. This archive is the public runtime link artifact for transformed binaries.

`build/libobf_runtime.a` contains:

- `obf_entropy_anchor.o`
- `obf_string_auth_runtime.o`

Users invoking raw `clang` or `clang++` must link `build/libobf_runtime.a` after their transformed input objects.

Users invoking `build/obf-clang` or `build/obf-clang++` get `build/libobf_runtime.a` appended automatically for link actions.
