file(REMOVE_RECURSE
  "CMakeFiles/config_demo_bench"
  "benchmarks/config_demo/config_demo.baseline"
  "benchmarks/config_demo/config_demo.baseline.ll"
  "benchmarks/config_demo/config_demo.obfuscated"
  "benchmarks/config_demo/config_demo.obfuscated.cleaned.ll"
  "benchmarks/config_demo/config_demo.obfuscated.ll"
  "obf_entropy_anchor.o"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/config_demo_bench.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
