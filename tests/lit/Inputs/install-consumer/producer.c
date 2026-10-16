#include "api.h"

OBF_STRING_COPY_SOURCE_V1(package_copy_v1, 1)
static const char package_payload[] = "installed authenticated payload";

#ifdef __cplusplus
extern "C"
#endif
__attribute__((noinline)) uint64_t package_mix(uint64_t value) {
  return (value ^ UINT64_C(0x9e37)) * UINT64_C(17) + UINT64_C(3);
}
