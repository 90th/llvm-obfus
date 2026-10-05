#include "ownership.h"
static __attribute__((noinline, annotate("obf:strong_vm")))
unsigned audit_dead_read(uint64_t index, unsigned *effect) {
  unsigned value = audit_direct[index];
  *effect = value;
  return value;
}
#ifdef __cplusplus
extern "C"
#endif
__attribute__((noinline, annotate("obf:none")))
unsigned audit_dead_anchor(uint64_t index, unsigned *effect) {
  return audit_dead_read(index, effect);
}
#include "reader.c"
