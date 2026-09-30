#ifdef OBF_LTO_ANNOTATED
#define PROTECT __attribute__((annotate("obf:strong_vm")))
#else
#define PROTECT
#endif

PROTECT unsigned protected_calc(unsigned value) {
  unsigned mixed = (value ^ 0x5a5aU) + 17U;
  return mixed * 3U;
}

__attribute__((noinline, annotate("obf:none")))
unsigned excluded_calc(unsigned value) {
  return value + 1234U;
}
