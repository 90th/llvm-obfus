#include <stdint.h>

/* Compiled as a separate raw TU, with no shared implementation or target calls. */
uint64_t oracle_target(uint64_t input, uint64_t *cumulative) {
    const uint64_t mixed = input ^ UINT64_C(0xd6e8feb86659fd93);
    const uint64_t rotated = (mixed >> 51) + (mixed << 13);
    uint64_t value = input * UINT64_C(0xa0761d6478bd642f) + rotated;
    if ((input % UINT64_C(2)) == 0) {
        value = UINT64_C(0x8ebc6af09c88c6e3) + value;
    } else {
        value = UINT64_C(0xe7037ed1a0b428db) ^ value;
    }
    const uint64_t next = (value + *cumulative) ^ (input / UINT64_C(128));
    *cumulative = UINT64_C(0x589965cc75374cc3) * next;
    const uint64_t result = (input << 9) ^ value;
    return (*cumulative >> 11) ^ result;
}
