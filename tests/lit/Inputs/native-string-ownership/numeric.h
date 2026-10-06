#ifndef NATIVE_STRING_OWNERSHIP_NUMERIC_H
#define NATIVE_STRING_OWNERSHIP_NUMERIC_H
#include "ownership.h"
#ifdef __cplusplus
extern "C" {
#endif
extern const uint32_t audit_matrix[2][2];
struct AuditCounters { uint32_t first, second; };
extern const struct AuditCounters audit_counters;
#ifdef __cplusplus
}
#endif
#endif
