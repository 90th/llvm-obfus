#ifdef AUDIT_OTHER_DIRECT
#define audit_direct audit_other_direct
#endif
#include "ownership.h"
#ifdef AUDIT_SAME_TU
#include "provider.c"
#endif
#ifdef AUDIT_LOCAL_READER
static __attribute__((noinline)) unsigned audit_owned(
    uint64_t slot, uint64_t index, unsigned *effect) __asm__("audit_owned");
#define audit_read audit_owned
#endif
unsigned audit_read(uint64_t slot, uint64_t index, unsigned *effect) {
#if AUDIT_KIND == 0
  unsigned value = audit_direct[0];
#elif AUDIT_KIND == 9
  unsigned value = audit_direct[index];
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
#ifdef AUDIT_LOCAL_READER
#undef audit_read
#ifdef __cplusplus
extern "C" {
#endif
#ifdef AUDIT_SECOND_READER
unsigned audit_aux_read(uint64_t slot, uint64_t index, unsigned *effect) {
  return audit_owned(slot, index, effect);
}
#else
#ifdef AUDIT_PAIRED_READER
unsigned audit_aux_read(uint64_t slot, uint64_t index, unsigned *effect);
#endif
unsigned audit_read(uint64_t slot, uint64_t index, unsigned *effect) {
#ifdef AUDIT_PAIRED_READER
  if (slot)
    return audit_aux_read(slot, index, effect);
#endif
  return audit_owned(slot, index, effect);
}
#endif
#ifdef __cplusplus
}
#endif
#endif
#ifndef AUDIT_SECOND_READER
unsigned audit_runtime(const unsigned char *bytes, uint64_t index, unsigned *effect) {
  unsigned value = bytes[index];
  *effect = value;
  return value;
}
#endif
