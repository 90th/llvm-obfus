file(REMOVE_RECURSE
  "CMakeFiles/wpo_demo_bench"
  "benchmarks/wpo_demo/wpo_demo.baseline"
  "benchmarks/wpo_demo/wpo_demo.baseline.ll"
  "benchmarks/wpo_demo/wpo_demo.obfuscated"
  "benchmarks/wpo_demo/wpo_demo.obfuscated.cleaned.ll"
  "benchmarks/wpo_demo/wpo_demo.obfuscated.ll"
  "benchmarks/wpo_demo/wpo_demo_core.ll"
  "benchmarks/wpo_demo/wpo_demo_main.ll"
  "obf_entropy_anchor.o"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/wpo_demo_bench.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
