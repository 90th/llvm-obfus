#include <stdio.h>

__attribute__((noinline, annotate("obf:strong_vm")))
unsigned secret_vm(unsigned value) {
  unsigned mixed = (value ^ 0x5a5aU) + 17U;
  return mixed * 3U;
}

__attribute__((noinline, annotate("obf:none")))
unsigned relay_none(unsigned value) {
  return secret_vm(value);
}

__attribute__((noinline, annotate("obf:none")))
unsigned branch_none(unsigned value) {
  unsigned relay = relay_none(value);
  if ((relay & 0x40U) == 0U) { return relay + 0x1234U; }
  return relay ^ 0x2468U;
}

__attribute__((noinline, annotate("obf:none")))
unsigned untouched_none(unsigned value) {
  return (value + 0x120U) ^ 0x33U;
}

int main(void) {
  unsigned result = 0;
  for (unsigned i = 0; i < 12; ++i) {
    unsigned value = i * 97U + 5U;
    result ^= relay_none(value);
    result ^= branch_none(value);
    result ^= untouched_none(value);
  }
  printf("retained-promotion result=%u\n", result);
  return 0;
}
