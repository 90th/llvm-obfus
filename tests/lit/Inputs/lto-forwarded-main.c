#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#ifndef FORWARDED_BYTES
#define FORWARDED_BYTES 33
#endif

#ifdef FORWARDED_TABLE
extern uint32_t protected_table_read(uint64_t slot, uint64_t index);
#ifdef FORWARDED_SHARED
extern uint32_t unprotected_read(uint64_t slot, uint64_t index);
#endif
#ifdef FORWARDED_ESCAPE
/* A native consumer keeps the forwarding table externally visible to LTO. */
extern const unsigned char *const forwarded_table[2];
#endif
#else
extern uint32_t protected_cell_read(uint64_t index);
#endif

int main(void) {
#ifdef FORWARDED_TABLE
  for (uint64_t slot = 0; slot != 2; ++slot) {
    printf("table[%" PRIu64 "]=", slot);
    for (uint64_t index = 0; index != FORWARDED_BYTES - slot; ++index) {
      printf("%s%" PRIu32, index ? "," : "", protected_table_read(slot, index));
    }
    putchar('\n');
#ifdef FORWARDED_SHARED
    printf("shared[%" PRIu64 "]=", slot);
    for (uint64_t index = 0; index != FORWARDED_BYTES - slot; ++index) {
      printf("%s%" PRIu32, index ? "," : "", unprotected_read(slot, index));
    }
    putchar('\n');
#endif
#ifdef FORWARDED_ESCAPE
    const unsigned char *escaped = forwarded_table[slot];
    printf("escaped[%" PRIu64 "]=", slot);
    for (uint64_t index = 0; index != FORWARDED_BYTES - slot; ++index) {
      printf("%s%u", index ? "," : "", (unsigned)escaped[index]);
    }
    putchar('\n');
#endif
  }
#else
  fputs("cell=", stdout);
  for (uint64_t index = 0; index != FORWARDED_BYTES; ++index) {
    printf("%s%" PRIu32, index ? "," : "", protected_cell_read(index));
  }
  putchar('\n');
#endif
  return 0;
}
