import lit.formats

config.name = "llvm-obfus"
config.test_format = lit.formats.ShTest(True)
config.suffixes = [".ll"]
config.test_source_root = "/home/nt0/Dev/projects/llvm-obfus/tests/lit"
config.test_exec_root = "/home/nt0/Dev/projects/llvm-obfus/build-cleanir-check/tests"

config.substitutions.append(("%opt", "/usr/bin/opt"))
config.substitutions.append(("%FileCheck", "/usr/bin/FileCheck"))
config.substitutions.append(
    ("%lli", "/usr/bin/lli --extra-object=/home/nt0/Dev/projects/llvm-obfus/build-cleanir-check/obf_entropy_anchor.o")
)
config.substitutions.append(
    ("%obf_plugin", "/home/nt0/Dev/projects/llvm-obfus/build-cleanir-check/obf_plugin.so")
)
