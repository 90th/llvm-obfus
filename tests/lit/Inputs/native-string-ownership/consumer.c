#include "ownership.h"
#include <stdio.h>
int main(void) {
  unsigned values[6], effects[6];
  for (uint64_t slot = 0; slot != 2; ++slot) {
    for (uint64_t index = 0; index != 3; ++index) {
      unsigned position = (unsigned)(slot * 3 + index);
      effects[position] = 0xDEADBEEFu;
      values[position] = audit_read(slot, index, &effects[position]);
    }
  }
  unsigned char bytes[2] = {110, 78};
  unsigned first_effect = 0xDEADBEEFu, second_effect = 0xDEADBEEFu;
  unsigned third_effect = 0xDEADBEEFu;
  unsigned first = audit_runtime(bytes, 0, &first_effect);
  bytes[0] = 78;
  unsigned second = audit_runtime(bytes, 0, &second_effect);
  unsigned third = audit_runtime(bytes, 1, &third_effect);
  printf("{\"values\":[%u,%u,%u,%u,%u,%u],\"effects\":[%u,%u,%u,%u,%u,%u],"
         "\"runtime\":[%u,%u,%u],\"runtime_effects\":[%u,%u,%u]}\n",
         values[0], values[1], values[2], values[3], values[4], values[5],
         effects[0], effects[1], effects[2], effects[3], effects[4], effects[5],
         first, second, third, first_effect, second_effect, third_effect);
  return 0;
}
