#include <stdint.h>

/* Eligible retained code is sampled but never called by protected_target. */
static volatile uint64_t sampled_anchor = UINT64_C(0xe15bd312caf09763);
__attribute__((noinline, used)) static uint64_t sampled_sibling(uint64_t x) {
    uint64_t a = sampled_anchor;
    uint64_t b = sampled_anchor;
    return ((x ^ a) * UINT64_C(0x9e3779b97f4a7c15)) + (b >> 3);
}

__attribute__((noinline, visibility("default")))
uint64_t protected_target(uint64_t x, uint64_t *effect) {
    uint64_t a = x ^ UINT64_C(0xd6e8feb86659fd93);
    a = (a << 13) | (a >> 51);
    uint64_t b = a + x * UINT64_C(0xa0761d6478bd642f);
    if (x & UINT64_C(1)) {
        b ^= UINT64_C(0xe7037ed1a0b428db);
    } else {
        b += UINT64_C(0x8ebc6af09c88c6e3);
    }
    *effect = ((*effect + b) ^ (x >> 7)) * UINT64_C(0x589965cc75374cc3);
    return b ^ (*effect >> 11) ^ (x << 9);
}
