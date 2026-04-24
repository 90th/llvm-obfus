# CMake generated Testfile for 
# Source directory: /home/nt0/Dev/projects/llvm-obfus
# Build directory: /home/nt0/Dev/projects/llvm-obfus/build-cleanir-check
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test([=[obf-lit]=] "/home/nt0/.local/bin/lit" "-sv" "/home/nt0/Dev/projects/llvm-obfus/build-cleanir-check/tests")
set_tests_properties([=[obf-lit]=] PROPERTIES  _BACKTRACE_TRIPLES "/home/nt0/Dev/projects/llvm-obfus/CMakeLists.txt;124;add_test;/home/nt0/Dev/projects/llvm-obfus/CMakeLists.txt;0;")
