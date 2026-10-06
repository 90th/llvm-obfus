#include "numeric.h"
#if AUDIT_KIND == 7
extern const uint32_t audit_matrix[2][2] = {{110, 78}, {31, 47}};
#elif AUDIT_KIND == 8
extern const struct AuditCounters audit_counters = {110, 78};
#endif
