#include <stdio.h>

extern unsigned protected_calc(unsigned);
extern unsigned excluded_calc(unsigned);

int main(int argc, char **argv) {
  (void)argv;
  unsigned result = 0;
  for (unsigned i = 0; i < 16; ++i) {
    unsigned value = i * 113U + (unsigned)argc;
    unsigned expected = ((value ^ 0x5a5aU) + 17U) * 3U;
    unsigned actual = protected_calc(value);
    if (actual != expected) return 1;
    if (excluded_calc(value) != value + 1234U) return 2;
    result ^= actual;
  }
  printf("lto-protection result=%u\n", result);
  return 0;
}
