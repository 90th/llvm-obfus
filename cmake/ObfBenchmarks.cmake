set(OBF_BENCHMARK_GENERATED_CONFIG_DIR
  "${CMAKE_CURRENT_BINARY_DIR}/benchmarks/config")
file(MAKE_DIRECTORY "${OBF_BENCHMARK_GENERATED_CONFIG_DIR}")
configure_file(
  benchmarks/config/rust_demo.yaml.in
  "${OBF_BENCHMARK_GENERATED_CONFIG_DIR}/rust_demo.yaml"
  @ONLY)
configure_file(
  benchmarks/config/zig_demo.yaml.in
  "${OBF_BENCHMARK_GENERATED_CONFIG_DIR}/zig_demo.yaml"
  @ONLY)
configure_file(
  benchmarks/config/tinygo_demo.yaml.in
  "${OBF_BENCHMARK_GENERATED_CONFIG_DIR}/tinygo_demo.yaml"
  @ONLY)

set(OBF_RUST_DEMO_BENCH_CONFIG
  "${OBF_BENCHMARK_GENERATED_CONFIG_DIR}/rust_demo.yaml")
set(OBF_ZIG_DEMO_BENCH_CONFIG
  "${OBF_BENCHMARK_GENERATED_CONFIG_DIR}/zig_demo.yaml")
set(OBF_TINYGO_DEMO_BENCH_CONFIG
  "${OBF_BENCHMARK_GENERATED_CONFIG_DIR}/tinygo_demo.yaml")

function(_obf_add_native_post_ir_commands final_obfuscated_ll_out compiler baseline_ll obfuscated_ll cleaned_ll baseline_bin obfuscated_bin)
  set(final_obfuscated_ll "${obfuscated_ll}")

  if(OBF_BENCHMARK_CLEAN_IR)
    add_custom_command(
      OUTPUT "${cleaned_ll}"
      COMMAND "${CMAKE_COMMAND}" -E rm -f "${cleaned_ll}"
      COMMAND "${OBF_OPT}" "-passes=${OBF_BENCHMARK_CLEANUP_PASSES}" -S "${obfuscated_ll}" -o "${cleaned_ll}"
      DEPENDS "${obfuscated_ll}"
      VERBATIM)
    set(final_obfuscated_ll "${cleaned_ll}")
  endif()

  add_custom_command(
    OUTPUT "${baseline_bin}"
    COMMAND "${compiler}" "${baseline_ll}" -O0 -o "${baseline_bin}"
    COMMAND "${OBF_STRIP}" --strip-all "${baseline_bin}"
    DEPENDS "${baseline_ll}"
    VERBATIM)

  add_custom_command(
    OUTPUT "${obfuscated_bin}"
    COMMAND "${compiler}" "${final_obfuscated_ll}" "${OBF_ENTROPY_ANCHOR_OBJ}" "${OBF_STRING_AUTH_RUNTIME_OBJ}" -O0 -o "${obfuscated_bin}"
    COMMAND "${OBF_STRIP}" --strip-all "${obfuscated_bin}"
    DEPENDS "${final_obfuscated_ll}" "${OBF_ENTROPY_ANCHOR_OBJ}" "${OBF_STRING_AUTH_RUNTIME_OBJ}"
    VERBATIM)

  set(${final_obfuscated_ll_out} "${final_obfuscated_ll}" PARENT_SCOPE)
endfunction()

function(add_obf_benchmark target_name source_file config_file compiler std_flag)
  set(output_dir "${CMAKE_CURRENT_BINARY_DIR}/benchmarks/${target_name}")
  set(baseline_ll "${output_dir}/${target_name}.baseline.ll")
  set(obfuscated_ll "${output_dir}/${target_name}.obfuscated.ll")
  set(cleaned_ll "${output_dir}/${target_name}.obfuscated.cleaned.ll")
  set(baseline_bin "${output_dir}/${target_name}.baseline")
  set(obfuscated_bin "${output_dir}/${target_name}.obfuscated")

  add_custom_command(
    OUTPUT "${baseline_ll}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${output_dir}"
    COMMAND "${compiler}" "${std_flag}" -O1 -fno-inline -fno-inline-functions -S -emit-llvm "${source_file}" -o "${baseline_ll}"
    DEPENDS "${source_file}"
    VERBATIM)

  if(WIN32)
    add_custom_command(
      OUTPUT "${obfuscated_ll}"
      COMMAND "${CMAKE_COMMAND}" -E make_directory "${output_dir}"
      COMMAND "${CMAKE_COMMAND}" -E rm -f "${obfuscated_ll}"
      COMMAND "${CMAKE_COMMAND}" -E env "OBF_CONFIG=${config_file}" "OBF_SEED=${OBF_EFFECTIVE_BENCHMARK_SEED}" "${OBF_OPT}" -load-pass-plugin "$<TARGET_FILE:obf_plugin>" -passes=obf-safe-pipeline -S "${baseline_ll}" -o "${obfuscated_ll}"
      DEPENDS obf_plugin "${baseline_ll}" "${config_file}" "${OBF_BENCHMARK_SEED_STAMP}"
      VERBATIM)
  else()
    add_custom_command(
      OUTPUT "${obfuscated_ll}"
      COMMAND "${CMAKE_COMMAND}" -E make_directory "${output_dir}"
      COMMAND "${CMAKE_COMMAND}" -E rm -f "${obfuscated_ll}"
      COMMAND "${OBF_OPT}" -load-pass-plugin "$<TARGET_FILE:obf_plugin>" "--obf-config=${config_file}" "--obf-seed=${OBF_EFFECTIVE_BENCHMARK_SEED}" -passes=obf-safe-pipeline -S "${baseline_ll}" -o "${obfuscated_ll}"
      DEPENDS obf_plugin "${baseline_ll}" "${config_file}" "${OBF_BENCHMARK_SEED_STAMP}"
      VERBATIM)
  endif()

  _obf_add_native_post_ir_commands(
    final_obfuscated_ll
    "${compiler}"
    "${baseline_ll}"
    "${obfuscated_ll}"
    "${cleaned_ll}"
    "${baseline_bin}"
    "${obfuscated_bin}")

  add_custom_target("${target_name}_bench" DEPENDS "${baseline_bin}" "${obfuscated_bin}")
  list(APPEND OBF_BENCHMARK_TARGETS "${target_name}_bench")
  set(OBF_BENCHMARK_TARGETS "${OBF_BENCHMARK_TARGETS}" PARENT_SCOPE)
endfunction()

function(add_obf_linked_benchmark target_name compiler std_flag config_file)
  set(output_dir "${CMAKE_CURRENT_BINARY_DIR}/benchmarks/${target_name}")
  set(linked_baseline_ll "${output_dir}/${target_name}.baseline.ll")
  set(linked_obfuscated_ll "${output_dir}/${target_name}.obfuscated.ll")
  set(linked_cleaned_ll "${output_dir}/${target_name}.obfuscated.cleaned.ll")
  set(baseline_bin "${output_dir}/${target_name}.baseline")
  set(obfuscated_bin "${output_dir}/${target_name}.obfuscated")

  set(source_lls)
  foreach(source_file IN LISTS ARGN)
    get_filename_component(source_name "${source_file}" NAME_WE)
    set(source_ll "${output_dir}/${source_name}.ll")
    add_custom_command(
      OUTPUT "${source_ll}"
      COMMAND "${CMAKE_COMMAND}" -E make_directory "${output_dir}"
      COMMAND "${compiler}" "${std_flag}" -O1 -fno-inline -fno-inline-functions -S -emit-llvm "${source_file}" -o "${source_ll}"
      DEPENDS "${source_file}"
      VERBATIM)
    list(APPEND source_lls "${source_ll}")
  endforeach()

  add_custom_command(
    OUTPUT "${linked_baseline_ll}"
    COMMAND "${OBF_LLVM_LINK}" ${source_lls} -S -o "${linked_baseline_ll}"
    DEPENDS ${source_lls}
    VERBATIM)

  if(WIN32)
    add_custom_command(
      OUTPUT "${linked_obfuscated_ll}"
      COMMAND "${CMAKE_COMMAND}" -E rm -f "${linked_obfuscated_ll}"
      COMMAND "${CMAKE_COMMAND}" -E env "OBF_CONFIG=${config_file}" "OBF_SEED=${OBF_EFFECTIVE_BENCHMARK_SEED}" "${OBF_OPT}" -load-pass-plugin "$<TARGET_FILE:obf_plugin>" -passes=obf-safe-pipeline -S "${linked_baseline_ll}" -o "${linked_obfuscated_ll}"
      DEPENDS obf_plugin "${linked_baseline_ll}" "${config_file}" "${OBF_BENCHMARK_SEED_STAMP}"
      VERBATIM)
  else()
    add_custom_command(
      OUTPUT "${linked_obfuscated_ll}"
      COMMAND "${CMAKE_COMMAND}" -E rm -f "${linked_obfuscated_ll}"
      COMMAND "${OBF_OPT}" -load-pass-plugin "$<TARGET_FILE:obf_plugin>" "--obf-config=${config_file}" "--obf-seed=${OBF_EFFECTIVE_BENCHMARK_SEED}" -passes=obf-safe-pipeline -S "${linked_baseline_ll}" -o "${linked_obfuscated_ll}"
      DEPENDS obf_plugin "${linked_baseline_ll}" "${config_file}" "${OBF_BENCHMARK_SEED_STAMP}"
      VERBATIM)
  endif()

  _obf_add_native_post_ir_commands(
    linked_final_obfuscated_ll
    "${compiler}"
    "${linked_baseline_ll}"
    "${linked_obfuscated_ll}"
    "${linked_cleaned_ll}"
    "${baseline_bin}"
    "${obfuscated_bin}")

  add_custom_target("${target_name}_bench" DEPENDS "${baseline_bin}" "${obfuscated_bin}")
  list(APPEND OBF_BENCHMARK_TARGETS "${target_name}_bench")
  set(OBF_BENCHMARK_TARGETS "${OBF_BENCHMARK_TARGETS}" PARENT_SCOPE)

  set(mir_baseline "${output_dir}/${target_name}.baseline.mir")
  set(mir_obfuscated "${output_dir}/${target_name}.obfuscated.mir")
  add_custom_command(
    OUTPUT "${mir_baseline}"
    COMMAND "${OBF_LLC}" -stop-after=finalize-isel "${linked_baseline_ll}" -o "${mir_baseline}"
    DEPENDS "${linked_baseline_ll}"
    VERBATIM)
  add_custom_command(
    OUTPUT "${mir_obfuscated}"
    COMMAND "${OBF_LLC}" -stop-after=finalize-isel "${linked_final_obfuscated_ll}" -o "${mir_obfuscated}"
    DEPENDS "${linked_final_obfuscated_ll}"
    VERBATIM)
  add_custom_target("${target_name}_mir" DEPENDS "${mir_baseline}" "${mir_obfuscated}")
  list(APPEND OBF_MIR_TARGETS "${target_name}_mir")
  set(OBF_MIR_TARGETS "${OBF_MIR_TARGETS}" PARENT_SCOPE)
endfunction()

if(WIN32)
  set(OBF_BENCHMARK_OBF_BC_COMMAND
    "${CMAKE_CURRENT_BINARY_DIR}/obf-bc.cmd")
  set(OBF_BENCHMARK_OBF_RUSTC_COMMAND
    "${CMAKE_CURRENT_BINARY_DIR}/obf-rustc.cmd")
else()
  set(OBF_BENCHMARK_OBF_BC_COMMAND
    "${CMAKE_CURRENT_BINARY_DIR}/obf-bc")
  set(OBF_BENCHMARK_OBF_RUSTC_COMMAND
    "${CMAKE_CURRENT_BINARY_DIR}/obf-rustc")
endif()

function(add_obf_rust_benchmark target_name source_file config_file)
  set(output_dir "${CMAKE_CURRENT_BINARY_DIR}/benchmarks/${target_name}")
  set(baseline_ll "${output_dir}/${target_name}.baseline.ll")
  set(obfuscated_ll "${output_dir}/${target_name}.obfuscated.ll")
  set(cleaned_ll "${output_dir}/${target_name}.obfuscated.cleaned.ll")
  set(extra_ir_outputs)
  set(baseline_bin
    "${output_dir}/${target_name}.baseline${CMAKE_EXECUTABLE_SUFFIX}")
  set(obfuscated_bin
    "${output_dir}/${target_name}.obfuscated${CMAKE_EXECUTABLE_SUFFIX}")

  add_custom_command(
    OUTPUT "${baseline_ll}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${output_dir}"
    COMMAND "${OBF_RUSTC_COMMAND}"
            --crate-name=${target_name}
            --crate-type=bin
            --edition=2021
            --emit=llvm-ir
            -Copt-level=1
            -Ccodegen-units=1
            "${source_file}"
            -o "${baseline_ll}"
    DEPENDS "${source_file}"
    VERBATIM)

  add_custom_command(
    OUTPUT "${obfuscated_ll}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${output_dir}"
    COMMAND "${CMAKE_COMMAND}" -E rm -f "${obfuscated_ll}"
    COMMAND "${OBF_BENCHMARK_OBF_RUSTC_COMMAND}"
            --obf-config=${config_file}
            --crate-name=${target_name}
            --crate-type=bin
            --edition=2021
            --emit=llvm-ir
            -Copt-level=1
            "${source_file}"
            -o "${obfuscated_ll}"
    DEPENDS obf-language-tools "${source_file}" "${config_file}"
    VERBATIM)

  if(OBF_BENCHMARK_CLEAN_IR)
    add_custom_command(
      OUTPUT "${cleaned_ll}"
      COMMAND "${CMAKE_COMMAND}" -E rm -f "${cleaned_ll}"
      COMMAND "${OBF_OPT}" "-passes=${OBF_BENCHMARK_CLEANUP_PASSES}" -S "${obfuscated_ll}" -o "${cleaned_ll}"
      DEPENDS "${obfuscated_ll}"
      VERBATIM)
    list(APPEND extra_ir_outputs "${cleaned_ll}")
  endif()

  add_custom_command(
    OUTPUT "${baseline_bin}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${output_dir}"
    COMMAND "${OBF_RUSTC_COMMAND}"
            --crate-name=${target_name}
            --crate-type=bin
            --edition=2021
            -Copt-level=1
            -Ccodegen-units=1
            "${source_file}"
            -o "${baseline_bin}"
    COMMAND "${OBF_STRIP}" --strip-all "${baseline_bin}"
    DEPENDS "${source_file}"
    VERBATIM)

  add_custom_command(
    OUTPUT "${obfuscated_bin}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${output_dir}"
    COMMAND "${OBF_BENCHMARK_OBF_RUSTC_COMMAND}"
            --obf-config=${config_file}
            --crate-name=${target_name}
            --crate-type=bin
            --edition=2021
            --emit=link
            -Copt-level=1
            "${source_file}"
            -o "${obfuscated_bin}"
    COMMAND "${OBF_STRIP}" --strip-all "${obfuscated_bin}"
    DEPENDS obf-language-tools "${source_file}" "${config_file}"
    VERBATIM)

  add_custom_target("${target_name}_bench"
    DEPENDS "${baseline_ll}" "${obfuscated_ll}" ${extra_ir_outputs} "${baseline_bin}" "${obfuscated_bin}")
  list(APPEND OBF_BENCHMARK_TARGETS "${target_name}_bench")
  set(OBF_BENCHMARK_TARGETS "${OBF_BENCHMARK_TARGETS}" PARENT_SCOPE)
endfunction()

function(add_obf_zig_benchmark target_name component_source main_source config_file)
  set(output_dir "${CMAKE_CURRENT_BINARY_DIR}/benchmarks/${target_name}")
  set(cache_dir "${output_dir}/zig-cache")
  set(global_cache_dir "${output_dir}/zig-global-cache")
  set(component_bc "${output_dir}/${target_name}.component.bc")
  set(protected_bc "${output_dir}/${target_name}.component.protected.bc")
  set(baseline_ll "${output_dir}/${target_name}.baseline.ll")
  set(obfuscated_ll "${output_dir}/${target_name}.obfuscated.ll")
  set(cleaned_ll "${output_dir}/${target_name}.obfuscated.cleaned.ll")
  set(extra_ir_outputs)
  set(baseline_bin
    "${output_dir}/${target_name}.baseline${CMAKE_EXECUTABLE_SUFFIX}")
  set(obfuscated_bin
    "${output_dir}/${target_name}.obfuscated${CMAKE_EXECUTABLE_SUFFIX}")

  set(zig_target_args)
  if(WIN32)
    set(zig_target_args -target x86_64-windows-msvc)
  endif()

  add_custom_command(
    OUTPUT "${component_bc}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${output_dir}"
    COMMAND "${OBF_ZIG_COMMAND}" build-obj "${component_source}"
            -O ReleaseFast
            ${zig_target_args}
            --cache-dir "${cache_dir}"
            --global-cache-dir "${global_cache_dir}"
            "-femit-llvm-bc=${component_bc}"
            -fno-emit-bin
    DEPENDS "${component_source}"
    VERBATIM)

  add_custom_command(
    OUTPUT "${protected_bc}"
    COMMAND "${CMAKE_COMMAND}" -E rm -f "${protected_bc}"
    COMMAND "${OBF_BENCHMARK_OBF_BC_COMMAND}"
            --obf-config=${config_file}
            --obf-seed=${OBF_EFFECTIVE_BENCHMARK_SEED}
            "${component_bc}"
            -o "${protected_bc}"
    DEPENDS obf-language-tools "${component_bc}" "${config_file}"
    VERBATIM)

  add_custom_command(
    OUTPUT "${baseline_ll}"
    COMMAND "${OBF_OPT}" -S "${component_bc}" -o "${baseline_ll}"
    DEPENDS "${component_bc}"
    VERBATIM)

  add_custom_command(
    OUTPUT "${obfuscated_ll}"
    COMMAND "${OBF_OPT}" -S "${protected_bc}" -o "${obfuscated_ll}"
    DEPENDS "${protected_bc}"
    VERBATIM)

  if(OBF_BENCHMARK_CLEAN_IR)
    add_custom_command(
      OUTPUT "${cleaned_ll}"
      COMMAND "${CMAKE_COMMAND}" -E rm -f "${cleaned_ll}"
      COMMAND "${OBF_OPT}" "-passes=${OBF_BENCHMARK_CLEANUP_PASSES}" -S "${obfuscated_ll}" -o "${cleaned_ll}"
      DEPENDS "${obfuscated_ll}"
      VERBATIM)
    list(APPEND extra_ir_outputs "${cleaned_ll}")
  endif()

  add_custom_command(
    OUTPUT "${baseline_bin}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${output_dir}"
    COMMAND "${OBF_ZIG_COMMAND}" build-exe "${main_source}" "${component_bc}"
            -O ReleaseFast
            ${zig_target_args}
            --cache-dir "${cache_dir}"
            --global-cache-dir "${global_cache_dir}"
            "-femit-bin=${baseline_bin}"
    COMMAND "${OBF_STRIP}" --strip-all "${baseline_bin}"
    DEPENDS "${main_source}" "${component_bc}"
    VERBATIM)

  add_custom_command(
    OUTPUT "${obfuscated_bin}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${output_dir}"
    COMMAND "${OBF_ZIG_COMMAND}" build-exe "${main_source}" "${protected_bc}" "${OBF_RUNTIME_ARCHIVE}"
            -O ReleaseFast
            ${zig_target_args}
            --cache-dir "${cache_dir}"
            --global-cache-dir "${global_cache_dir}"
            "-femit-bin=${obfuscated_bin}"
    COMMAND "${OBF_STRIP}" --strip-all "${obfuscated_bin}"
    DEPENDS "${main_source}" "${protected_bc}" "${OBF_RUNTIME_ARCHIVE}"
    VERBATIM)

  add_custom_target("${target_name}_bench"
    DEPENDS "${baseline_ll}" "${obfuscated_ll}" ${extra_ir_outputs} "${baseline_bin}" "${obfuscated_bin}")
  list(APPEND OBF_BENCHMARK_TARGETS "${target_name}_bench")
  set(OBF_BENCHMARK_TARGETS "${OBF_BENCHMARK_TARGETS}" PARENT_SCOPE)
endfunction()

function(add_obf_tinygo_benchmark target_name source_file config_file)
  set(output_dir "${CMAKE_CURRENT_BINARY_DIR}/benchmarks/${target_name}")
  set(baseline_ll "${output_dir}/${target_name}.baseline.ll")
  set(obfuscated_ll "${output_dir}/${target_name}.obfuscated.ll")
  set(cleaned_ll "${output_dir}/${target_name}.obfuscated.cleaned.ll")
  set(extra_ir_outputs)
  set(baseline_bin "${output_dir}/${target_name}.baseline")
  set(obfuscated_bin "${output_dir}/${target_name}.obfuscated")

  add_custom_command(
    OUTPUT "${baseline_ll}" "${obfuscated_ll}" "${baseline_bin}" "${obfuscated_bin}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${output_dir}"
    COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/tools/obf-bench/build_tinygo_benchmark.py"
            --tinygo "${OBF_TINYGO_COMMAND}"
            --wrapper "${CMAKE_CURRENT_BINARY_DIR}/obf-tinygo"
            --opt "${OBF_OPT}"
            --strip "${OBF_STRIP}"
            --config "${config_file}"
            --source "${source_file}"
            --output-dir "${output_dir}"
            --name "${target_name}"
    DEPENDS obf-language-tools
            "${CMAKE_CURRENT_SOURCE_DIR}/tools/obf-bench/build_tinygo_benchmark.py"
            "${source_file}"
            "${config_file}"
    VERBATIM)

  if(OBF_BENCHMARK_CLEAN_IR)
    add_custom_command(
      OUTPUT "${cleaned_ll}"
      COMMAND "${CMAKE_COMMAND}" -E rm -f "${cleaned_ll}"
      COMMAND "${OBF_OPT}" "-passes=${OBF_BENCHMARK_CLEANUP_PASSES}" -S "${obfuscated_ll}" -o "${cleaned_ll}"
      DEPENDS "${obfuscated_ll}"
      VERBATIM)
    list(APPEND extra_ir_outputs "${cleaned_ll}")
  endif()

  add_custom_target("${target_name}_bench"
    DEPENDS "${baseline_ll}" "${obfuscated_ll}" ${extra_ir_outputs} "${baseline_bin}" "${obfuscated_bin}")
  list(APPEND OBF_BENCHMARK_TARGETS "${target_name}_bench")
  set(OBF_BENCHMARK_TARGETS "${OBF_BENCHMARK_TARGETS}" PARENT_SCOPE)
endfunction()

set(OBF_CORPUS_E2E_BENCHMARKS
  license_demo
  config_demo
  vm_workflow_demo
  wpo_demo)

if(OBF_PLUGIN_IS_LOADABLE)
add_obf_benchmark(
  license_demo
  "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/corpus/license_demo.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/config/license_demo.yaml"
  "${OBF_CLANGXX}"
  "-std=c++23")

add_obf_benchmark(
  config_demo
  "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/corpus/config_demo.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/config/config_demo.yaml"
  "${OBF_CLANG}"
  "-std=c17")

add_obf_benchmark(
  vm_workflow_demo
  "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/corpus/vm_workflow_demo.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/config/vm_workflow_demo.yaml"
  "${OBF_CLANG}"
  "-std=c17")

add_obf_linked_benchmark(
  wpo_demo
  "${OBF_CLANG}"
  "-std=c17"
  "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/config/wpo_demo.yaml"
  "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/corpus/wpo_demo_main.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/corpus/wpo_demo_core.c")

if(OBF_HAS_RUST_BENCHMARK_TOOLCHAIN)
  add_obf_rust_benchmark(
    rust_demo
    "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/corpus/rust_demo.rs"
    "${OBF_RUST_DEMO_BENCH_CONFIG}")
  list(APPEND OBF_CORPUS_E2E_BENCHMARKS rust_demo)
endif()

if(OBF_HAS_ZIG_BENCHMARK_TOOLCHAIN)
  add_obf_zig_benchmark(
    zig_demo
    "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/corpus/zig_demo_component.zig"
    "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/corpus/zig_demo_main.zig"
    "${OBF_ZIG_DEMO_BENCH_CONFIG}")
  list(APPEND OBF_CORPUS_E2E_BENCHMARKS zig_demo)
endif()

if(OBF_HAS_TINYGO_BENCHMARK_TOOLCHAIN)
  add_obf_tinygo_benchmark(
    tinygo_demo
    "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/corpus/tinygo_demo.go"
    "${OBF_TINYGO_DEMO_BENCH_CONFIG}")
  list(APPEND OBF_CORPUS_E2E_BENCHMARKS tinygo_demo)
endif()

string(JOIN "," OBF_CORPUS_E2E_BENCHMARKS_CSV ${OBF_CORPUS_E2E_BENCHMARKS})

add_custom_target(obf-benchmarks DEPENDS ${OBF_BENCHMARK_TARGETS})
add_custom_target(obf-benchmarks-e2e
  COMMAND "${Python3_EXECUTABLE}"
          "${CMAKE_CURRENT_SOURCE_DIR}/tools/obf-bench/run_corpus_e2e.py"
          "--benchmarks-dir" "${CMAKE_CURRENT_BINARY_DIR}/benchmarks"
          "--runtime-prefix" "${OBF_RUNTIME_ABI_PREFIX}"
          "--benchmarks" "${OBF_CORPUS_E2E_BENCHMARKS_CSV}"
  DEPENDS obf-benchmarks
  VERBATIM)
add_custom_target(obf-benchmarks-mir DEPENDS ${OBF_MIR_TARGETS})
endif()
