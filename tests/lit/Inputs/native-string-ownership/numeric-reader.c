#include "numeric.h"
unsigned audit_read(uint64_t slot, uint64_t index, unsigned *effect) {
#if AUDIT_KIND == 7
  unsigned value = audit_matrix[slot][index % 2];
#elif AUDIT_KIND == 8
  unsigned value = slot == 0 ? audit_counters.first : audit_counters.second;
#endif
  *effect = value;
  return value;
}
unsigned audit_runtime(const unsigned char *bytes, uint64_t index, unsigned *effect) {
  unsigned value = bytes[index];
  *effect = value;
  return value;
}
