#include "cross-dso-string-copy-api.h"

__attribute__((noinline))
uint64_t exchange_read_bytes(const unsigned char *bytes, uint64_t count,
                             uint64_t salt, uint64_t *effect) {
  uint64_t value = UINT64_C(0x13579bdf) ^ salt;
  for (uint64_t index = 0; index < count; ++index)
    value += ((uint64_t)bytes[index] + salt) * (index + 1);
  *effect = value ^ (salt << 1);
  return value;
}
