#include "api.h"
#include <stdio.h>
#include <string.h>

int main(void) {
  char buffer[64];
  size_t required = 0;
  memset(buffer, 0x5a, sizeof(buffer));
  if (package_copy_v1(1, NULL, 0, &required) != OBF_STRING_COPY_NEED_CAPACITY ||
      required != 32 || buffer[0] != 0x5a)
    return 1;
  if (package_copy_v1(1, buffer, required - 1, &required) !=
          OBF_STRING_COPY_NEED_CAPACITY || required != 32 || buffer[0] != 0x5a)
    return 2;
  if (package_copy_v1(1, buffer, sizeof(buffer), &required) != OBF_STRING_COPY_OK ||
      required != 32 || memcmp(buffer, "installed authenticated payload", 32) ||
      buffer[32] != 0x5a || package_mix(37) != UINT64_C(687925))
    return 3;
  printf("C: %s mix=687925\n", buffer);
  return 0;
}
