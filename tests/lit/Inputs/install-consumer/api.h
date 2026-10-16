#pragma once
#include <obf/string_copy.h>
#include <obf/support/runtime_abi_generated.h>

OBF_STRING_COPY_DECLARE_V1(package_copy_v1);
#ifdef __cplusplus
extern "C"
#endif
uint64_t package_mix(uint64_t value);
