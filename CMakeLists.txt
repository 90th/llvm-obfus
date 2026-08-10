cmake_minimum_required(VERSION 3.24)

project(llvm-obfus LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(cmake/ObfToolchain.cmake)
include(cmake/ObfTargets.cmake)
include(cmake/ObfRuntime.cmake)
include(cmake/ObfTesting.cmake)
include(cmake/ObfBenchmarks.cmake)
include(cmake/ObfAnalysis.cmake)
