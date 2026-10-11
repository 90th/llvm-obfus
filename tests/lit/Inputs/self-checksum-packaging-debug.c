#include <stdint.h>

/* Raw debug-bearing TU; protected-module debug cleanup remains unchanged. */
__attribute__((used, noinline, visibility("hidden")))
uint64_t packaging_debug_identity(uint64_t value) {
    return value ^ UINT64_C(0x0123456789abcdef);
}
