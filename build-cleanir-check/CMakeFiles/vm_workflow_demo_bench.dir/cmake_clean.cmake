file(REMOVE_RECURSE
  "CMakeFiles/vm_workflow_demo_bench"
  "benchmarks/vm_workflow_demo/vm_workflow_demo.baseline"
  "benchmarks/vm_workflow_demo/vm_workflow_demo.baseline.ll"
  "benchmarks/vm_workflow_demo/vm_workflow_demo.obfuscated"
  "benchmarks/vm_workflow_demo/vm_workflow_demo.obfuscated.cleaned.ll"
  "benchmarks/vm_workflow_demo/vm_workflow_demo.obfuscated.ll"
  "obf_entropy_anchor.o"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/vm_workflow_demo_bench.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
