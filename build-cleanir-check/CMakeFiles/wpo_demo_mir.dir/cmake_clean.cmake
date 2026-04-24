file(REMOVE_RECURSE
  "CMakeFiles/wpo_demo_mir"
  "benchmarks/wpo_demo/wpo_demo.baseline.ll"
  "benchmarks/wpo_demo/wpo_demo.baseline.mir"
  "benchmarks/wpo_demo/wpo_demo.obfuscated.cleaned.ll"
  "benchmarks/wpo_demo/wpo_demo.obfuscated.ll"
  "benchmarks/wpo_demo/wpo_demo.obfuscated.mir"
  "benchmarks/wpo_demo/wpo_demo_core.ll"
  "benchmarks/wpo_demo/wpo_demo_main.ll"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/wpo_demo_mir.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
