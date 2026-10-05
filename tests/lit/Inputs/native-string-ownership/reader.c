#include "ownership.h"
#ifdef AUDIT_SAME_TU
#include "provider.c"
#endif
unsigned audit_read(uint64_t slot, uint64_t index, unsigned *effect) {
#if AUDIT_KIND == 0
  unsigned value = audit_direct[0];
#elif AUDIT_KIND == 1
  unsigned value = (unsigned char)audit_cell[index];
#elif AUDIT_KIND == 2
  unsigned value = (unsigned char)audit_table[slot][index];
#elif AUDIT_KIND == 3
  unsigned value = audit_integers[slot];
#elif AUDIT_KIND == 5
  unsigned value = audit_integer_cell[slot];
#elif AUDIT_KIND == 6
  unsigned value = (*audit_integer_chain)[slot];
#endif
#ifdef AUDIT_CALL_FORCE
  value += audit_force();
#endif
  *effect = value;
  return value;
}
unsigned audit_runtime(const unsigned char *bytes, uint64_t index, unsigned *effect) {
  unsigned value = bytes[index];
  *effect = value;
  return value;
}
