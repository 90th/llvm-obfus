#ifdef OBF_NATIVE_SELECTION
unsigned excluded_shadow(unsigned value) { return value + 1U; }
unsigned configured_alias(unsigned value) { return value + 3U; }
unsigned local_protected(unsigned value) { return value + 2U; }
#else
__attribute__((weak, noinline, annotate("obf:none")))
unsigned excluded_shadow(unsigned value) {
  return value;
}

__attribute__((noinline, annotate("obf:strong_vm")))
static unsigned local_protected(unsigned value) {
  return (value ^ 91U) + 37U;
}

__attribute__((noinline))
unsigned selection_consumer(unsigned value) {
  return local_protected(value) ^ excluded_shadow(value);
}
#endif
