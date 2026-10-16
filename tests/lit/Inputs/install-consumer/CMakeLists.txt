cmake_minimum_required(VERSION 3.24)
project(installed_consumer LANGUAGES C CXX)
find_package(Python3 3.10 REQUIRED COMPONENTS Interpreter)
set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
foreach(language IN ITEMS c cpp)
  if(language STREQUAL "c")
    set(compiler_language C)
  else()
    set(compiler_language CXX)
  endif()
  add_library(producer_${language} OBJECT producer.${language})
  target_compile_options(producer_${language} PRIVATE
    "--obf-config=${CMAKE_CURRENT_SOURCE_DIR}/policy.yaml" -O2)
  set_property(TARGET producer_${language} PROPERTY
    ${compiler_language}_COMPILER_LAUNCHER
    "${Python3_EXECUTABLE};${CMAKE_CURRENT_SOURCE_DIR}/capture.py;${CMAKE_CURRENT_BINARY_DIR}/${language}-coverage.json")
  add_executable(consumer_${language} consumer.${language}
    $<TARGET_OBJECTS:producer_${language}>)
endforeach()
