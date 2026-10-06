#ifndef NATIVE_STRING_OWNERSHIP_H
#define NATIVE_STRING_OWNERSHIP_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#ifndef AUDIT_LOCAL_DIRECT
extern const unsigned char audit_direct[4];
#endif
extern const char * const audit_cell;
extern const char * const audit_table[2];
extern const uint32_t audit_integers[2];
#if AUDIT_KIND == 5
extern const uint32_t * const audit_integer_cell;
#elif AUDIT_KIND == 6
extern const uint32_t * const * const audit_integer_chain;
#endif
unsigned audit_force(void);
__attribute__((noinline)) unsigned audit_read(uint64_t slot, uint64_t index, unsigned *effect);
__attribute__((noinline)) unsigned audit_runtime(const unsigned char *bytes, uint64_t index, unsigned *effect);
#ifdef __cplusplus
}
#endif
#endif
