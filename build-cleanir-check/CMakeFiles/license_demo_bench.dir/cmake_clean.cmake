file(REMOVE_RECURSE
  "CMakeFiles/license_demo_bench"
  "benchmarks/license_demo/license_demo.baseline"
  "benchmarks/license_demo/license_demo.baseline.ll"
  "benchmarks/license_demo/license_demo.obfuscated"
  "benchmarks/license_demo/license_demo.obfuscated.cleaned.ll"
  "benchmarks/license_demo/license_demo.obfuscated.ll"
  "obf_entropy_anchor.o"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/license_demo_bench.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
